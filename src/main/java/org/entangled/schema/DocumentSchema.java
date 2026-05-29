package org.entangled.schema;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.json.JsonValue;

/**
 * Stage 5 closed-schema validation for the three document kinds (section 02,
 * section 06, section 07, section 08), including the cross-field semantic checks
 * the Stage 5 definition in section 10 assigns to this stage:
 * <ul>
 *   <li>{@code origin.not_after} vs {@code canary.issued_at} bounds
 *       ({@code E_ORIGIN_INVALID}, section 06);</li>
 *   <li>the {@code state_policy} submit-budget satisfiability aggregate
 *       ({@code E_SUBMIT_BUDGET}, section 07/section 09);</li>
 *   <li>{@code manifest.updated} future-skew beyond the 300s tolerance
 *       ({@code E_SCHEMA_FIELD_SYNTAX} with {@code reason=future_beyond_skew_tolerance},
 *       section 10).</li>
 * </ul>
 *
 * <p>The signature ({@code sig}) is validated here only for base64url syntax and
 * length (section 04 wire-side), so a malformed {@code sig} surfaces as
 * {@code E_SCHEMA_FIELD_SYNTAX} at Stage 5 (vector 151), not as Stage 6
 * {@code E_SIG_MALFORMED}.
 */
public final class DocumentSchema {

    /** Section 10 clock-skew tolerance, seconds. */
    public static final long SKEW_TOLERANCE_SECONDS = 300;

    /** Section 09 submit-body budget partition: state_budget = 53248 bytes. */
    public static final int STATE_BUDGET_BYTES = 53248;

    /** Section 06 origin.not_after ceiling: 5 years in seconds. */
    public static final long NOT_AFTER_MAX_HORIZON_SECONDS = 157680000L;

    private static final Set<String> STATE_MODES = Set.of("client_only", "request");

    private DocumentSchema() {
    }

    /**
     * Document-wide numeric-grammar pre-scan (section 04).
     *
     * <p>Section 04 requires every numeric token to be validated against the
     * integer grammar "at the lexical or parse level, before any conversion to a
     * numeric type", independently of which fields a particular path reads. A
     * non-conforming number anywhere in the document is therefore detected before
     * closed-schema field-presence checks. Corpus vector 140 fixes this ordering:
     * a manifest that both omits required fields and carries a float-shape token
     * is rejected as E_SCHEMA_NON_INTEGER, not E_SCHEMA_REQUIRED_FIELD. We model
     * the numeric grammar as a whole-document Stage 5 pre-pass to honor that.
     *
     * <p>(Ambiguity note: section 10's Stage 5 listing does not state the relative
     * order of the numeric-grammar check and the required-field check when both
     * fire. The chosen reading follows section 04's "before any conversion"
     * mandate, treating the numeric grammar as a parse-adjacent whole-document
     * check; vector 140 is the falsification condition. Filed as an ambiguity.)
     */
    public static void scanNumericGrammar(JsonValue v) {
        if (v instanceof JsonValue.Num n) {
            if (!n.conformingInteger()) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_NON_INTEGER);
            }
        } else if (v instanceof JsonValue.Obj o) {
            for (JsonValue child : o.members().values()) {
                scanNumericGrammar(child);
            }
        } else if (v instanceof JsonValue.Arr a) {
            for (JsonValue child : a.elements()) {
                scanNumericGrammar(child);
            }
        }
    }

    /** Validate a manifest payload (Stage 5). {@code nowEpoch} is the injected clock in epoch seconds. */
    public static void validateManifest(JsonValue.Obj doc, long nowEpoch) {
        scanNumericGrammar(doc);
        Closed.check(doc,
                Set.of("spec_version", "kind", "publisher_pubkey", "origin", "canary",
                        "state_policy", "navigation", "min_refresh_interval", "updated",
                        "sig", "migration_pointer", "content_root"),
                Set.of("spec_version", "kind", "publisher_pubkey", "origin", "canary",
                        "state_policy", "navigation", "min_refresh_interval", "updated", "sig"));

        Fields.base64url(Fields.str(doc.get("publisher_pubkey")), 32);

        long issuedAt = validateCanary(Fields.obj(doc.get("canary")));
        validateOrigin(Fields.obj(doc.get("origin")), issuedAt);
        validateStatePolicy(Fields.arr(doc.get("state_policy")));
        validateNavigation(Fields.arr(doc.get("navigation")));
        Fields.integerInRange(doc.get("min_refresh_interval"), 300, 604800);
        validateUpdated(Fields.str(doc.get("updated")), nowEpoch);

        if (doc.has("migration_pointer")) {
            validateMigrationPointer(Fields.obj(doc.get("migration_pointer")), doc, issuedAt);
        }
        if (doc.has("content_root")) {
            sha256Field(Fields.str(doc.get("content_root")));
        }
        sig(Fields.str(doc.get("sig")));
    }

    /** Validate a content document payload (Stage 5). */
    public static void validateContent(JsonValue.Obj doc) {
        scanNumericGrammar(doc);
        Closed.check(doc,
                Set.of("spec_version", "kind", "path", "meta", "blocks", "sig", "seq"),
                Set.of("spec_version", "kind", "path", "meta", "blocks", "sig"));
        Fields.path(Fields.str(doc.get("path")));
        validateMeta(Fields.obj(doc.get("meta")));
        validateBlocks(Fields.arr(doc.get("blocks")), false, 1024);
        if (doc.has("seq")) {
            // seq is a positive integer (>= 1).
            Fields.integerInRange(doc.get("seq"), 1, Long.MAX_VALUE);
        }
        sig(Fields.str(doc.get("sig")));
    }

    /** Validate a transaction document payload (Stage 5). */
    public static void validateTransaction(JsonValue.Obj doc) {
        scanNumericGrammar(doc);
        Closed.check(doc,
                Set.of("spec_version", "kind", "in_response_to", "request_id",
                        "request_hash", "state_updates", "blocks", "sig"),
                Set.of("spec_version", "kind", "in_response_to", "request_id",
                        "request_hash", "state_updates", "blocks", "sig"));
        Fields.path(Fields.str(doc.get("in_response_to")));
        // request_id: 22 base64url chars = 16 bytes.
        Fields.base64url(Fields.str(doc.get("request_id")), 16);
        sha256Field(Fields.str(doc.get("request_hash")));
        validateStateUpdates(Fields.arr(doc.get("state_updates")));
        validateBlocks(Fields.arr(doc.get("blocks")), true, 256);
        sig(Fields.str(doc.get("sig")));
    }

    // --- manifest sub-objects ---

    /** Validate the canary object; returns canary.issued_at in epoch seconds. */
    private static long validateCanary(JsonValue.Obj canary) {
        Closed.check(canary,
                Set.of("runtime_pubkey", "issued_at", "next_expected", "statement", "freshness_proof"),
                Set.of("runtime_pubkey", "issued_at", "next_expected", "statement"));
        Fields.base64url(Fields.str(canary.get("runtime_pubkey")), 32);

        String issuedAtStr = Fields.str(canary.get("issued_at"));
        String nextExpectedStr = Fields.str(canary.get("next_expected"));
        // Timestamp syntax is a canary-structural concern; an invalid timestamp
        // is reported as E_CANARY_INVALID at Stage 8, not E_SCHEMA_FIELD_SYNTAX.
        if (!Rfc3339.isValid(issuedAtStr) || !Rfc3339.isValid(nextExpectedStr)) {
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID);
        }
        long issuedAt = Rfc3339.epochSeconds(issuedAtStr);
        long nextExpected = Rfc3339.epochSeconds(nextExpectedStr);
        // next_expected strictly later than issued_at; interval 7..30 days.
        long interval = nextExpected - issuedAt;
        if (interval < 604800 || interval > 2592000) {
            throw new RejectException(DiagnosticCode.E_CANARY_INVALID);
        }

        String statement = Fields.str(canary.get("statement"));
        Fields.maxBytes(statement, 2048);
        Fields.noControlChars(statement, true); // line feed allowed
        Fields.requireNfc(statement);

        if (canary.has("freshness_proof")) {
            String fp = Fields.str(canary.get("freshness_proof"));
            Fields.maxBytes(fp, 200);
            Fields.noControlChars(fp, false);
            Fields.requireNfc(fp);
        }
        return issuedAt;
    }

    private static void validateOrigin(JsonValue.Obj origin, long issuedAt) {
        Closed.check(origin,
                Set.of("carrier", "address", "origin_pubkey", "not_after"),
                Set.of("carrier", "address", "origin_pubkey"));
        // A non-tor-v3 carrier is a v1.0 rejection; treated as enum violation.
        if (!Fields.str(origin.get("carrier")).equals("tor-v3")) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
        onionAddress(Fields.str(origin.get("address")));
        Fields.base64url(Fields.str(origin.get("origin_pubkey")), 32);
        if (origin.has("not_after")) {
            String notAfterStr = Fields.str(origin.get("not_after"));
            Fields.rfc3339(notAfterStr);
            long notAfter = Rfc3339.epochSeconds(notAfterStr);
            // Cross-field semantic checks (E_ORIGIN_INVALID, section 06).
            if (notAfter <= issuedAt) {
                throw originInvalid("not_after_not_later_than_issued_at");
            }
            if (notAfter - issuedAt > NOT_AFTER_MAX_HORIZON_SECONDS) {
                throw originInvalid("not_after_beyond_5y");
            }
        }
    }

    private static void validateStatePolicy(JsonValue.Arr statePolicy) {
        List<JsonValue> entries = statePolicy.elements();
        if (entries.size() > 32) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        Set<String> seen = new java.util.HashSet<>();
        long stateAggregate = 0;
        int requestEntries = 0;
        for (JsonValue e : entries) {
            JsonValue.Obj entry = Fields.obj(e);
            Closed.check(entry,
                    Set.of("namespace", "key", "mode", "max_size", "max_lifetime", "purpose"),
                    Set.of("namespace", "key", "mode", "max_size", "max_lifetime", "purpose"));
            String namespace = Fields.str(entry.get("namespace"));
            String key = Fields.str(entry.get("key"));
            Fields.slug(namespace, 64);
            Fields.slug(key, 64);
            String composite = namespace + " " + key;
            if (!seen.add(composite)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_DUPLICATE_ENTRY);
            }
            String mode = Fields.str(entry.get("mode"));
            Fields.inEnum(mode, STATE_MODES);
            long maxSize = Fields.integerInRange(entry.get("max_size"), 1, 4096);
            Fields.integerInRange(entry.get("max_lifetime"), 300, 7776000);
            String purpose = Fields.str(entry.get("purpose"));
            Fields.maxBytes(purpose, 200);
            Fields.noControlChars(purpose, false);
            Fields.requireNfc(purpose);

            if (mode.equals("request")) {
                // Section 09 per-entry wire contribution: a {"namespace":"","key":"",
                // "value":""} skeleton is 36 bytes; add namespace, key, and the
                // value counted at its raw max_size (section 07).
                stateAggregate += 36L + namespace.length() + key.length() + maxSize;
                requestEntries++;
            }
        }
        if (requestEntries > 1) {
            stateAggregate += (requestEntries - 1L); // inter-entry commas
        }
        if (stateAggregate > STATE_BUDGET_BYTES) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("component", "state");
            details.put("declared_bytes", stateAggregate);
            details.put("budget_bytes", (long) STATE_BUDGET_BYTES);
            throw new RejectException(DiagnosticCode.E_SUBMIT_BUDGET, details);
        }
    }

    private static void validateNavigation(JsonValue.Arr navigation) {
        List<JsonValue> entries = navigation.elements();
        if (entries.size() > 32) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        for (JsonValue e : entries) {
            JsonValue.Obj entry = Fields.obj(e);
            Closed.check(entry, Set.of("label", "path"), Set.of("label", "path"));
            String label = Fields.str(entry.get("label"));
            Fields.maxBytes(label, 100);
            Fields.noControlChars(label, false);
            Fields.requireNfc(label);
            // navigation path uses content path syntax (reserved manifest path forbidden).
            Fields.path(Fields.str(entry.get("path")));
        }
    }

    private static void validateUpdated(String updated, long nowEpoch) {
        Fields.rfc3339(updated);
        long updatedEpoch = Rfc3339.epochSeconds(updated);
        // Future-skew beyond 300s tolerance is a Stage 5 temporal-domain syntax
        // failure (section 10): E_SCHEMA_FIELD_SYNTAX, reason future_beyond_skew_tolerance.
        if (updatedEpoch > nowEpoch + SKEW_TOLERANCE_SECONDS) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("reason", "future_beyond_skew_tolerance");
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX, details);
        }
    }

    private static void validateMigrationPointer(JsonValue.Obj mp, JsonValue.Obj manifest, long issuedAt) {
        Closed.check(mp, Set.of("successor_origin", "announced_at"),
                Set.of("successor_origin", "announced_at"));
        JsonValue.Obj successor = Fields.obj(mp.get("successor_origin"));
        Closed.check(successor, Set.of("carrier", "address", "origin_pubkey"),
                Set.of("carrier", "address", "origin_pubkey"));
        if (!Fields.str(successor.get("carrier")).equals("tor-v3")) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
        onionAddress(Fields.str(successor.get("address")));
        Fields.base64url(Fields.str(successor.get("origin_pubkey")), 32);
        String announcedAt = Fields.str(mp.get("announced_at"));
        Fields.rfc3339(announcedAt);
        // Note: the semantic checks (self-pointer, announced_at vs updated,
        // carrier match, successor address-to-key binding, chain cycle) are
        // Stage 9 migration checks (E_MIGRATION_INVALID / E_MIGRATION_MISMATCH),
        // handled by the pipeline, not here.
    }

    // --- content sub-objects ---

    private static void validateMeta(JsonValue.Obj meta) {
        Closed.check(meta, Set.of("title", "published_at"), Set.of("title", "published_at"));
        String title = Fields.str(meta.get("title"));
        Fields.maxBytes(title, 200);
        Fields.noControlChars(title, false);
        Fields.requireNfc(title);
        Fields.rfc3339(Fields.str(meta.get("published_at")));
    }

    private static void validateBlocks(JsonValue.Arr blocks, boolean transaction, int maxBlocks) {
        List<JsonValue> list = blocks.elements();
        if (list.isEmpty()) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        if (list.size() > maxBlocks) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        for (JsonValue b : list) {
            Blocks.validate(b, transaction);
        }
    }

    private static void validateStateUpdates(JsonValue.Arr updates) {
        List<JsonValue> list = updates.elements();
        if (list.size() > 32) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        for (JsonValue u : list) {
            JsonValue.Obj op = Fields.obj(u);
            String opName = Fields.str(Inline.require(op, "op"));
            switch (opName) {
                case "set" -> {
                    Closed.check(op, Set.of("op", "namespace", "key", "value", "ttl"),
                            Set.of("op", "namespace", "key", "value", "ttl"));
                    Fields.slug(Fields.str(op.get("namespace")), 64);
                    Fields.slug(Fields.str(op.get("key")), 64);
                    String value = Fields.str(op.get("value"));
                    // section 11:286 / section 07:170: a state set value over the
                    // 4096-byte hard ceiling is E_STATE_VALUE_SIZE, not the generic
                    // field-length code.
                    if (Fields.utf8Len(value) > 4096) {
                        throw new RejectException(DiagnosticCode.E_STATE_VALUE_SIZE);
                    }
                    // section 11:287 / section 07:279: a state set ttl outside the
                    // 300..7776000 hard range is E_STATE_TTL. The integer-grammar and
                    // type checks stay generic (E_SCHEMA_NON_INTEGER / E_SCHEMA_FIELD_TYPE).
                    BigInteger ttl = Fields.integer(op.get("ttl"));
                    if (ttl.compareTo(BigInteger.valueOf(300)) < 0
                            || ttl.compareTo(BigInteger.valueOf(7776000)) > 0) {
                        throw new RejectException(DiagnosticCode.E_STATE_TTL);
                    }
                }
                case "delete" -> {
                    Closed.check(op, Set.of("op", "namespace", "key"),
                            Set.of("op", "namespace", "key"));
                    Fields.slug(Fields.str(op.get("namespace")), 64);
                    Fields.slug(Fields.str(op.get("key")), 64);
                }
                default -> throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
            }
        }
    }

    // --- shared ---

    private static void onionAddress(String address) {
        if (!address.endsWith(".onion")) {
            throw Fields.syntax();
        }
        String body = address.substring(0, address.length() - ".onion".length());
        if (body.length() != 56) {
            throw Fields.syntax();
        }
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
            if (!ok) {
                throw Fields.syntax();
            }
        }
    }

    private static void sha256Field(String s) {
        if (s.length() != 51 || !s.startsWith("sha-256:")) {
            throw Fields.syntax();
        }
        Fields.base64url(s.substring("sha-256:".length()), 32);
    }

    private static void sig(String s) {
        // sig is 86 base64url chars = 64 bytes; wire-side length/alphabet
        // violations are E_SCHEMA_FIELD_SYNTAX at Stage 5 (vector 151, section 11).
        Fields.base64url(s, 64);
    }

    private static RejectException originInvalid(String reason) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("reason", reason);
        return new RejectException(DiagnosticCode.E_ORIGIN_INVALID, details);
    }
}
