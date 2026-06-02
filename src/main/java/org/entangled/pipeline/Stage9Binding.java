package org.entangled.pipeline;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.Verdict;
import org.entangled.crypto.Base64Url;
import org.entangled.crypto.Ed25519;
import org.entangled.crypto.Sha;
import org.entangled.crypto.TorV3Address;
import org.entangled.json.Jcs;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.Rfc3339;

/**
 * Stage 9: path and origin binding (section 10), plus the manifest origin
 * lifecycle and migration checks (section 06, section 10).
 *
 * <p>Manifest: Tor v3 origin binding ({@code E_BIND_ORIGIN}); {@code origin.not_after}
 * expiry with the symmetric 300s past-bound tolerance ({@code E_ORIGIN_EXPIRED});
 * and, when a {@code migration_pointer} is present, the fetched-successor
 * verification ({@code E_MIGRATION_MISMATCH}) and the per-flow {@code chain_cycle}
 * determination ({@code E_MIGRATION_INVALID}). The announcement-internal
 * {@code migration_pointer} semantic checks ({@code E_MIGRATION_INVALID} reasons
 * {@code self_pointer}, {@code carrier_mismatch}, {@code announced_at_after_updated},
 * and {@code successor_key_mismatch}) moved to Stage 5 and now run in
 * {@link org.entangled.schema.DocumentSchema} (AMB-19, rc.38).
 *
 * <p>Content: byte-exact {@code path} binding ({@code E_BIND_PATH}). Transaction:
 * {@code in_response_to} ({@code E_BIND_RESPONSE_PATH}), {@code request_id}
 * ({@code E_BIND_REQUEST_ID}), and {@code request_hash} ({@code E_BIND_REQUEST_HASH}).
 */
public final class Stage9Binding {

    /** Section 10 past-bound tolerance for origin.not_after. */
    private static final long SKEW = 300;

    private Stage9Binding() {
    }

    // --- manifest ---

    static void manifest(JsonValue.Obj doc, Context ctx) {
        JsonValue.Obj origin = (JsonValue.Obj) doc.get("origin");
        bindOrigin(origin, ctx.fetchedOriginAddress);
        notAfterExpiry(origin, ctx.nowEpoch);

        if (doc.has("migration_pointer")) {
            migration(doc, ctx);
        }
    }

    /** Tor v3 origin binding: fetched address decodes to a key equal to origin.origin_pubkey. */
    private static void bindOrigin(JsonValue.Obj origin, String fetchedAddress) {
        String declaredPubkeyB64u = ((JsonValue.Str) origin.get("origin_pubkey")).value();
        byte[] declaredPubkey = Base64Url.decode(declaredPubkeyB64u, 32);
        // Section 05:157,159 strict profile for origin.origin_pubkey (AMB-17,
        // rc.33): a non-canonical or small-order origin key is rejected at Stage 9
        // origin binding with E_BIND_ORIGIN, since K_origin verifies no document
        // and so never reaches signature verification.
        if (!Ed25519.isStrictProfilePubkey(declaredPubkey)) {
            throw new RejectException(DiagnosticCode.E_BIND_ORIGIN);
        }
        if (fetchedAddress == null) {
            return; // no fetched origin supplied; address binding not evaluated
        }
        String declaredAddress = ((JsonValue.Str) origin.get("address")).value();
        // Fetched address must equal the declared address (canonical form).
        if (!declaredAddress.equals(fetchedAddress)) {
            throw new RejectException(DiagnosticCode.E_BIND_ORIGIN);
        }
        byte[] derived;
        try {
            derived = TorV3Address.decodePublicKey(fetchedAddress);
        } catch (TorV3Address.InvalidOnionAddress e) {
            throw new RejectException(DiagnosticCode.E_BIND_ORIGIN);
        }
        if (!Arrays.equals(declaredPubkey, derived)) {
            throw new RejectException(DiagnosticCode.E_BIND_ORIGIN);
        }
    }

    private static void notAfterExpiry(JsonValue.Obj origin, long nowEpoch) {
        if (!origin.members().containsKey("not_after")) {
            return;
        }
        long notAfter = Rfc3339.epochSeconds(((JsonValue.Str) origin.get("not_after")).value());
        // Section 10 past-bound rejection: current_time > not_after + 300 (strict).
        if (nowEpoch > notAfter + SKEW) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("not_after", ((JsonValue.Str) origin.get("not_after")).value());
            details.put("now", isoMinute(nowEpoch));
            throw new RejectException(DiagnosticCode.E_ORIGIN_EXPIRED, details);
        }
    }

    // --- migration ---

    private static void migration(JsonValue.Obj doc, Context ctx) {
        // The announcement-internal migration_pointer semantic checks
        // (self_pointer, announced_at_after_updated, carrier_mismatch,
        // successor_key_mismatch) are Stage 5 closed-schema checks on the
        // announcing manifest and run in DocumentSchema (AMB-19, rc.38). Stage 9
        // owns only the fetch-time successor verification and the per-flow
        // chain_cycle determination, both of which need the fetched successor
        // manifest and the navigation flow.
        if (ctx.successorManifest == null) {
            return;
        }
        JsonValue.Obj origin = (JsonValue.Obj) doc.get("origin");
        String announcingAddress = ((JsonValue.Str) origin.get("address")).value();
        JsonValue.Obj mp = (JsonValue.Obj) doc.get("migration_pointer");
        JsonValue.Obj successorOrigin = (JsonValue.Obj) mp.get("successor_origin");
        String successorAddress = ((JsonValue.Str) successorOrigin.get("address")).value();
        verifySuccessor(doc, successorOrigin, successorAddress, announcingAddress, ctx);
    }

    private static void verifySuccessor(JsonValue.Obj announcing, JsonValue.Obj successorOrigin,
                                        String successorAddress, String announcingAddress, Context ctx) {
        // Per-flow visited-origins begins with the announcing origin; a successor
        // address already visited is a chain cycle.
        if (successorAddress.equals(announcingAddress)) {
            throw migrationInvalid("chain_cycle", announcingAddress, successorAddress);
        }

        // Run the successor manifest through the full pipeline in isolation.
        Context successorCtx = new Context(ctx.nowEpoch);
        successorCtx.fetchedOriginAddress = successorAddress;
        // The successor manifest is attacker-controlled (fetched from the
        // announced successor onion address). It is parsed here so the
        // post-verification checks (publisher continuity, binding equality, and
        // the second-hop chain cycle) can read its fields; invalid JSON throws
        // E_PARSE_* (a clean reject), but a valid-JSON value that is not the
        // manifest shape this code expects must not crash with an unchecked
        // cast. A non-object body, or a body whose migration_pointer /
        // successor_origin / fields are the wrong type, is left for the
        // successor's own pipeline run below to reject as E_MIGRATION_MISMATCH;
        // only a well-formed successor reaches the typed comparisons.
        JsonValue parsedSuccessor = JsonParser.parse(new String(ctx.successorManifest, StandardCharsets.UTF_8));
        JsonValue.Obj successorDoc = parsedSuccessor instanceof JsonValue.Obj obj ? obj : null;

        Verdict successorVerdict = new Pipeline(successorCtx).run(ctx.successorManifest);
        if (!successorVerdict.isAccepted()) {
            // The successor fails its own pipeline; surface as E_MIGRATION_MISMATCH
            // with the underlying code.
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("mismatch_field", "successor_stage9_failure");
            details.put("underlying_diagnostic_code", successorVerdict.diagnostic().code().name());
            throw new RejectException(DiagnosticCode.E_MIGRATION_MISMATCH, details);
        }

        // The successor passed its own pipeline, so it is a schema-valid manifest
        // object with a well-typed origin, publisher_pubkey, address, and
        // origin_pubkey; the accessors below are therefore safe. (A non-object
        // body would have been rejected at the successor's Stage 4, so
        // successorDoc is non-null here; assert it defensively rather than rely
        // on the invariant implicitly.)
        if (successorDoc == null) {
            throw mismatch("successor_shape");
        }
        // Publisher continuity and binding-field equality (checks 3 and 4).
        String announcingPub = ((JsonValue.Str) announcing.get("publisher_pubkey")).value();
        String successorPub = ((JsonValue.Str) successorDoc.get("publisher_pubkey")).value();
        if (!announcingPub.equals(successorPub)) {
            throw mismatch("publisher_pubkey");
        }
        JsonValue.Obj successorDocOrigin = (JsonValue.Obj) successorDoc.get("origin");
        String successorDocAddress = ((JsonValue.Str) successorDocOrigin.get("address")).value();
        if (!successorDocAddress.equals(((JsonValue.Str) successorOrigin.get("address")).value())) {
            throw mismatch("address");
        }
        String successorDocPubkey = ((JsonValue.Str) successorDocOrigin.get("origin_pubkey")).value();
        if (!successorDocPubkey.equals(((JsonValue.Str) successorOrigin.get("origin_pubkey")).value())) {
            throw mismatch("origin_pubkey");
        }

        // Second-hop chain cycle (AMB-26): only after the successor has passed its
        // own full pipeline and the publisher/binding continuity checks does it
        // become a verified pending successor (section 10:398-411); only then is
        // its own announcement processed. A successor that announces a return to
        // the announcing origin (already in visited_origins) is a chain cycle. A
        // broken successor surfaces E_MIGRATION_MISMATCH above, before this point,
        // so the cycle check never preempts the successor-verification failure.
        String secondHop = nestedString(successorDoc, "migration_pointer", "successor_origin", "address");
        if (secondHop != null && secondHop.equals(announcingAddress)) {
            throw migrationInvalid("chain_cycle", successorAddress, announcingAddress);
        }
    }

    /**
     * Walk a chain of object members and return the final value as a string, or
     * {@code null} if any step is absent or not of the expected type. Used to
     * read attacker-controlled successor-manifest fields without unchecked casts.
     */
    private static String nestedString(JsonValue.Obj root, String... path) {
        JsonValue current = root;
        for (int i = 0; i < path.length; i++) {
            if (!(current instanceof JsonValue.Obj obj)) {
                return null;
            }
            current = obj.get(path[i]);
        }
        return current instanceof JsonValue.Str s ? s.value() : null;
    }

    // --- content / transaction ---

    static void contentPath(JsonValue.Obj doc, Context ctx) {
        if (ctx.fetchedPath == null) {
            return;
        }
        String declared = ((JsonValue.Str) doc.get("path")).value();
        if (!declared.equals(ctx.fetchedPath)) {
            throw new RejectException(DiagnosticCode.E_BIND_PATH);
        }
    }

    static void transaction(JsonValue.Obj doc, Context ctx) {
        if (ctx.submitPath != null) {
            String inResponseTo = ((JsonValue.Str) doc.get("in_response_to")).value();
            if (!inResponseTo.equals(ctx.submitPath)) {
                throw new RejectException(DiagnosticCode.E_BIND_RESPONSE_PATH);
            }
        }
        if (ctx.submitBody != null) {
            JsonValue.Obj submitParsed =
                    (JsonValue.Obj) JsonParser.parse(new String(ctx.submitBody, StandardCharsets.UTF_8));

            // request_id: the transaction's request_id MUST equal the request_id
            // the client placed in the submit body (section 02:298, section
            // 09:139). The transaction's request_id is an independent copied
            // field, so this is checked separately from request_hash.
            String declaredRequestId = ((JsonValue.Str) doc.get("request_id")).value();
            String submitRequestId = ((JsonValue.Str) submitParsed.get("request_id")).value();
            if (!declaredRequestId.equals(submitRequestId)) {
                throw new RejectException(DiagnosticCode.E_BIND_REQUEST_ID);
            }

            // request_hash = "sha-256:" || base64url(SHA-256(JCS(submit_body))).
            byte[] canonical = Jcs.canonicalize(submitParsed);
            String expectedHash = "sha-256:" + base64urlNoPad(Sha.sha256(canonical));
            String declaredHash = ((JsonValue.Str) doc.get("request_hash")).value();
            if (!declaredHash.equals(expectedHash)) {
                throw new RejectException(DiagnosticCode.E_BIND_REQUEST_HASH);
            }
        }
    }

    // --- helpers ---

    private static RejectException migrationInvalid(String reason, String announcing, String successor) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("reason", reason);
        details.put("announcing_origin_address", announcing);
        details.put("successor_origin_address", successor);
        return new RejectException(DiagnosticCode.E_MIGRATION_INVALID, details);
    }

    private static RejectException mismatch(String field) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("mismatch_field", field);
        return new RejectException(DiagnosticCode.E_MIGRATION_MISMATCH, details);
    }

    private static String isoMinute(long epochSeconds) {
        long minute = (epochSeconds / 60) * 60;
        return java.time.Instant.ofEpochSecond(minute)
                .atOffset(java.time.ZoneOffset.UTC)
                .format(java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:'00Z'"));
    }

    private static String base64urlNoPad(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
