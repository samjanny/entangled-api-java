package org.entangled;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.DocumentSchema;
import org.junit.jupiter.api.Test;

/**
 * Stage 5 standalone validation of a transaction's {@code state_updates}
 * (section 07, section 11): a {@code set} operation whose {@code value} exceeds
 * the 4096-byte hard ceiling is {@code E_STATE_VALUE_SIZE} (section 11:286), and
 * a {@code ttl} outside the 300..7776000 hard range is {@code E_STATE_TTL}
 * (section 11:287) -- the dedicated state codes, not the generic
 * {@code E_SCHEMA_FIELD_LENGTH} / {@code E_SCHEMA_FIELD_RANGE}.
 *
 * <p>Runs Stage 5 ({@link DocumentSchema#validateTransaction}) directly on
 * hand-built transactions, so no signature is needed; a syntactically valid
 * placeholder {@code sig} satisfies the wire-side base64url check. The all-valid
 * controls double as a guard that the hand-built JSON is otherwise schema-valid.
 * Normative cross-impl coverage is spec corpus vectors 148-state-value-size and
 * 149-state-ttl (rc.36).
 */
class Stage5StateUpdateTest {

    private static final String SIG = "A".repeat(86);
    // A valid request_hash shape ("sha-256:" + 43 base64url chars); Stage 5 only
    // checks its syntax, not that it matches any submit body.
    private static final String RHASH = "sha-256:-EvECkoil9nNYYBfRQE85W5pWojAP0K9UG830mtQn0M";

    private static String txWithUpdates(String updates) {
        return "{\"spec_version\":\"1.0\",\"kind\":\"transaction\",\"in_response_to\":\"/c\","
                + "\"request_id\":\"AAECAwQFBgcICQoLDA0ODw\","
                + "\"request_hash\":\"" + RHASH + "\","
                + "\"state_updates\":" + updates + ","
                + "\"blocks\":[{\"kind\":\"feedback\",\"variant\":\"success\","
                + "\"content\":[{\"kind\":\"text\",\"value\":\"ok\",\"marks\":[]}]}],"
                + "\"sig\":\"" + SIG + "\"}";
    }

    private static String txWithSet(String value, long ttl) {
        return txWithUpdates("[{\"op\":\"set\",\"namespace\":\"session\",\"key\":\"data\","
                + "\"value\":\"" + value + "\",\"ttl\":" + ttl + "}]");
    }

    private static DiagnosticCode rejectCode(String json) {
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(json);
        RejectException ex = assertThrows(RejectException.class,
                () -> DocumentSchema.validateTransaction(doc));
        return ex.diagnostic().code();
    }

    private static void acceptsSchema(String json) {
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(json);
        assertDoesNotThrow(() -> DocumentSchema.validateTransaction(doc));
    }

    @Test
    void valueOverCeilingIsStateValueSize() {
        // 4097 raw bytes, one over the 4096 hard ceiling.
        assertEquals(DiagnosticCode.E_STATE_VALUE_SIZE,
                rejectCode(txWithSet("X".repeat(4097), 86400)));
    }

    @Test
    void ttlOverMaxIsStateTtl() {
        assertEquals(DiagnosticCode.E_STATE_TTL,
                rejectCode(txWithSet("x", 7776001)));
    }

    @Test
    void ttlUnderMinIsStateTtl() {
        assertEquals(DiagnosticCode.E_STATE_TTL,
                rejectCode(txWithSet("x", 299)));
    }

    @Test
    void validSetAndBoundariesAccepted() {
        // Positive controls (also guard that the hand-built JSON is schema-valid):
        // a typical set, the exact value ceiling, and both ttl bounds.
        acceptsSchema(txWithSet("hello", 86400));
        acceptsSchema(txWithSet("X".repeat(4096), 86400));
        acceptsSchema(txWithSet("x", 300));
        acceptsSchema(txWithSet("x", 7776000));
    }

    @Test
    void duplicateNamespaceKeyRejectedRegardlessOfOperationForm() {
        String updates = "[{\"op\":\"set\",\"namespace\":\"session\",\"key\":\"data\","
                + "\"value\":\"ok\",\"ttl\":86400},"
                + "{\"op\":\"delete\",\"namespace\":\"session\",\"key\":\"data\"}]";
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(txWithUpdates(updates));
        RejectException ex = assertThrows(RejectException.class,
                () -> DocumentSchema.validateTransaction(doc));
        assertEquals(DiagnosticCode.E_STATE_DUPLICATE, ex.diagnostic().code());
        assertEquals("session", ex.diagnostic().details().get("duplicate_namespace"));
        assertEquals("data", ex.diagnostic().details().get("duplicate_key"));
    }
}
