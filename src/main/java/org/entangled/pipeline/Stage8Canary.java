package org.entangled.pipeline;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.crypto.Base64Url;
import org.entangled.crypto.Ed25519;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.Rfc3339;

/**
 * Stage 8: canary and anti-downgrade resolution (section 08, section 10).
 *
 * <p>Stage 5 enforces only the canary field shapes (closed schema,
 * {@code runtime_pubkey}, and the {@code statement} / {@code freshness_proof}
 * string-content rules). The canary timestamp validity, {@code next_expected}
 * ordering, and 7..30 day interval bounds are checked here at Stage 8 (AMB-16,
 * section 11:209): a malformed canary timestamp or out-of-bounds interval is
 * E_CANARY_INVALID reported after Stage 6, not a Stage 5 schema code. This stage
 * then adds the time- and history-dependent checks:
 * <ul>
 *   <li>{@code issued_at} future-skew beyond the 300s tolerance ->
 *       {@code E_CANARY_INVALID} (section 08, vector 183);</li>
 *   <li>anti-downgrade: {@code issued_at} strictly older than the newest verified
 *       {@code issued_at} for the same publisher -> {@code E_CANARY_DOWNGRADE}
 *       (vector 181);</li>
 *   <li>equal-{@code issued_at} conflict: same {@code issued_at} as a previously
 *       verified manifest but a different signed payload ->
 *       {@code E_CANARY_CONFLICT} (vector 180);</li>
 *   <li>runtime-key reuse: {@code runtime_pubkey} equal to the immediately
 *       preceding verified manifest (MUST) or any earlier history entry (SHOULD)
 *       for the same publisher -> {@code E_CANARY_RUNTIME_REUSE} (vectors 184,
 *       185), with {@code window_position} details.</li>
 * </ul>
 */
public final class Stage8Canary {

    private Stage8Canary() {
    }

    /** A minimal projection of a verified manifest needed for Stage 8 history checks. */
    private record HistoryEntry(String publisherPubkey, String runtimePubkey,
                                long issuedAt, String jcsPayload) {
    }

    static void evaluate(JsonValue.Obj doc, Context ctx) {
        JsonValue.Obj canary = (JsonValue.Obj) doc.get("canary");
        String issuedAtStr = ((JsonValue.Str) canary.get("issued_at")).value();
        String nextExpectedStr = ((JsonValue.Str) canary.get("next_expected")).value();

        // Canary timestamp validity, ordering, and interval bounds are Stage 8
        // canary-integrity checks (AMB-16, section 11:209): a malformed
        // issued_at / next_expected timestamp, next_expected not strictly after
        // issued_at, or an interval outside [7, 30] days is E_CANARY_INVALID,
        // reported here after the Stage 6 signature check, not as a Stage 5
        // schema code. Stage 5 validated only that the two fields are strings, so
        // the timestamp-as-instant judgment happens here, before epochSeconds.
        if (!Rfc3339.isValid(issuedAtStr) || !Rfc3339.isValid(nextExpectedStr)) {
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID);
        }
        long issuedAt = Rfc3339.epochSeconds(issuedAtStr);
        long nextExpected = Rfc3339.epochSeconds(nextExpectedStr);
        long interval = nextExpected - issuedAt;
        if (interval < CANARY_INTERVAL_MIN_SECS || interval > CANARY_INTERVAL_MAX_SECS) {
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID);
        }

        // issued_at future-skew beyond the 300s tolerance is a canary Invalid
        // condition (section 08), distinct from the section 05 signature checks.
        if (issuedAt > ctx.nowEpoch + DocumentSchema_SKEW) {
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID);
        }

        String publisherPubkey = ((JsonValue.Str) doc.get("publisher_pubkey")).value();
        String runtimePubkey = ((JsonValue.Str) canary.get("runtime_pubkey")).value();

        // section 05 strict profile on canary.runtime_pubkey (AMB-23): a
        // non-canonical or small-order runtime key is rejected here at Stage 8 as
        // E_CANARY_INVALID, rather than surfacing only when a content or
        // transaction document is later verified under it (E_SIG_VERIFICATION).
        // The manifest itself is signed under K_publisher, so the bad runtime key
        // does not otherwise affect manifest verification; failing at canary
        // structure time aligns the rejection point with manifest acceptance.
        // Stage 5 already validated the base64url/32-byte form, so the decode here
        // does not throw. Matches the Rust reference.
        if (!Ed25519.isStrictProfilePubkey(Base64Url.decode(runtimePubkey, 32))) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("field_path", "canary.runtime_pubkey");
            details.put("reason", "public_key_rejected");
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID, details);
        }

        String currentPayload = new String(Pipeline.canonicalPayloadMinusSig(doc), StandardCharsets.UTF_8);

        List<HistoryEntry> history = parseHistory(ctx);
        if (history.isEmpty()) {
            return;
        }

        // Anti-downgrade and equal-issued_at conflict are evaluated against the
        // newest verified issued_at for the same publisher.
        HistoryEntry newest = null;
        for (HistoryEntry h : history) {
            if (!h.publisherPubkey.equals(publisherPubkey)) {
                continue;
            }
            if (newest == null || h.issuedAt > newest.issuedAt) {
                newest = h;
            }
        }
        if (newest != null) {
            if (issuedAt < newest.issuedAt) {
                throw new RejectException(DiagnosticCode.E_CANARY_DOWNGRADE);
            }
            if (issuedAt == newest.issuedAt && !currentPayload.equals(newest.jcsPayload)) {
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("issued_at", issuedAtStr);
                details.put("retained_runtime_pubkey", newest.runtimePubkey);
                details.put("presented_runtime_pubkey", runtimePubkey);
                throw new RejectException(DiagnosticCode.E_CANARY_CONFLICT, details);
            }
        }

        // Runtime-key reuse. The immediately preceding entry (last in history,
        // for the same publisher) is the MUST check (window_position 1); any
        // earlier match is the SHOULD check (window_position >= 2). History is
        // ordered oldest-first, so index from the end.
        checkRuntimeReuse(history, publisherPubkey, runtimePubkey, issuedAtStr);
    }

    private static void checkRuntimeReuse(List<HistoryEntry> history, String publisherPubkey,
                                          String runtimePubkey, String currentIssuedAt) {
        // Build the per-publisher list in chronological order.
        List<HistoryEntry> own = new ArrayList<>();
        for (HistoryEntry h : history) {
            if (h.publisherPubkey.equals(publisherPubkey)) {
                own.add(h);
            }
        }
        // window_position: 1 = immediately preceding (last), 2 = the one before, ...
        for (int i = own.size() - 1; i >= 0; i--) {
            HistoryEntry h = own.get(i);
            if (h.runtimePubkey.equals(runtimePubkey)) {
                int windowPosition = own.size() - i;
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("runtime_pubkey", runtimePubkey);
                details.put("previous_issued_at", isoOf(h.issuedAt));
                details.put("current_issued_at", currentIssuedAt);
                details.put("window_position", (long) windowPosition);
                throw new RejectException(DiagnosticCode.E_CANARY_RUNTIME_REUSE, details);
            }
        }
    }

    private static List<HistoryEntry> parseHistory(Context ctx) {
        List<HistoryEntry> entries = new ArrayList<>();
        for (byte[] manifestBytes : ctx.publisherHistory) {
            String text = new String(manifestBytes, StandardCharsets.UTF_8);
            JsonValue.Obj m = (JsonValue.Obj) JsonParser.parse(text);
            JsonValue.Obj canary = (JsonValue.Obj) m.get("canary");
            String pub = ((JsonValue.Str) m.get("publisher_pubkey")).value();
            String rt = ((JsonValue.Str) canary.get("runtime_pubkey")).value();
            long issuedAt = Rfc3339.epochSeconds(((JsonValue.Str) canary.get("issued_at")).value());
            String payload = new String(Pipeline.canonicalPayloadMinusSig(m), StandardCharsets.UTF_8);
            entries.add(new HistoryEntry(pub, rt, issuedAt, payload));
        }
        return entries;
    }

    private static String isoOf(long epochSeconds) {
        return java.time.Instant.ofEpochSecond(epochSeconds)
                .atOffset(java.time.ZoneOffset.UTC)
                .format(java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'"));
    }

    // Section 10 clock-skew tolerance, mirrored here to avoid a cross-package
    // constant dependency cycle; both reference the same normative 300 seconds.
    private static final long DocumentSchema_SKEW = 300;

    // Canary interval bounds (section 08:86): [7, 30] days, in seconds.
    private static final long CANARY_INTERVAL_MIN_SECS = 604800;   // 7 days
    private static final long CANARY_INTERVAL_MAX_SECS = 2592000;  // 30 days
}
