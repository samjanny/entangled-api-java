package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.pipeline.Stage2Input;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.DocumentSchema;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.Test;

/**
 * Stage 4 (kind) and Stage 5 (closed schema, including cross-field semantic
 * checks) driven by the corpus vectors whose first failing stage is one of
 * those, plus the positive vectors which must pass Stage 5 cleanly.
 *
 * <p>This does not run signature, canary, or binding stages; it isolates the
 * schema layer ahead of the full pipeline.
 */
class SchemaStageTest {

    private static final long CLOCK_NOW = Rfc3339.epochSeconds("2026-05-07T00:01:00Z");

    private DiagnosticCode rejectCode(String vectorId, int cap) {
        RejectException ex = assertThrows(RejectException.class, () -> runStage5(vectorId, cap));
        return ex.diagnostic().code();
    }

    private void runStage5(String vectorId, int cap) {
        byte[] body = CorpusFiles.vectorInput(vectorId);
        String text = Stage2Input.validateAndDecode(body, cap);
        JsonValue root = JsonParser.parse(text);
        Stage4Kind.Kind kind = Stage4Kind.discriminate(root);
        JsonValue.Obj doc = (JsonValue.Obj) root;
        switch (kind) {
            case MANIFEST -> DocumentSchema.validateManifest(doc, CLOCK_NOW);
            case CONTENT -> DocumentSchema.validateContent(doc);
            case TRANSACTION -> DocumentSchema.validateTransaction(doc);
        }
    }

    // --- Stage 4 ---

    @Test
    void specVersionWrong120() {
        assertEquals(DiagnosticCode.E_KIND_SPEC_VERSION,
                rejectCode("120-spec-version-wrong", Stage2Input.MANIFEST_BYTE_CAP));
    }

    @Test
    void kindUnknown121() {
        assertEquals(DiagnosticCode.E_KIND_UNKNOWN,
                rejectCode("121-kind-unknown", Stage2Input.MANIFEST_BYTE_CAP));
    }

    @Test
    void kindMissingFields122() {
        assertEquals(DiagnosticCode.E_KIND_MISSING_FIELDS,
                rejectCode("122-kind-missing-fields", Stage2Input.MANIFEST_BYTE_CAP));
    }

    // --- Stage 5 schema ---

    @Test
    void schemaVectors() {
        record Case(String id, int cap, DiagnosticCode code) {
        }
        Case[] cases = {
            new Case("123-link-citation-url-userinfo", Stage2Input.CONTENT_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("124-link-carrier-url-userinfo", Stage2Input.CONTENT_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("130-schema-unknown-field", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_UNKNOWN_FIELD),
            new Case("131-schema-missing-required", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_REQUIRED_FIELD),
            new Case("132-schema-null-value", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_NULL_VALUE),
            new Case("133-schema-block-kind-unknown", Stage2Input.CONTENT_BYTE_CAP, DiagnosticCode.E_SCHEMA_ENUM_VIOLATION),
            new Case("134-schema-field-type", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_TYPE),
            new Case("135-schema-field-range", Stage2Input.CONTENT_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_RANGE),
            new Case("137-schema-duplicate-entry", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_DUPLICATE_ENTRY),
            new Case("138-schema-malformed-unicode", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_MALFORMED_UNICODE),
            new Case("139-schema-field-length", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_LENGTH),
            new Case("140-numeric-float", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_NON_INTEGER),
            new Case("141-numeric-exponent", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_NON_INTEGER),
            new Case("142-numeric-overflow", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_NON_INTEGER),
            new Case("143-submit-budget-state-overflow", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SUBMIT_BUDGET),
            new Case("151-sig-syntax-length", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("160-base64url-padded", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("161-base64url-standard-alphabet", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("162-base64url-whitespace", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("171-bind-reserved-manifest-path", Stage2Input.CONTENT_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("176-origin-invalid", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_ORIGIN_INVALID),
            new Case("177-origin-invalid-beyond-5y", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_ORIGIN_INVALID),
            new Case("178-manifest-updated-future-skew", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("190-unicode-nfd-statement", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
            new Case("191-unicode-nfd-freshness-proof", Stage2Input.MANIFEST_BYTE_CAP, DiagnosticCode.E_SCHEMA_FIELD_SYNTAX),
        };
        for (Case c : cases) {
            assertEquals(c.code(), rejectCode(c.id(), c.cap()), "vector " + c.id());
        }
    }

    @Test
    void positiveVectorsPassSchema() {
        // The accept vectors must pass Stage 5 without throwing.
        assertDoesNotThrow(() -> runStage5("001-manifest-valid-minimal", Stage2Input.MANIFEST_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("002-manifest-valid-state-policy", Stage2Input.MANIFEST_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("003-content-valid-minimal", Stage2Input.CONTENT_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("004-content-valid-blocks-showcase", Stage2Input.CONTENT_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("005-transaction-valid-minimal", Stage2Input.TRANSACTION_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("006-manifest-valid-not-after", Stage2Input.MANIFEST_BYTE_CAP));
        assertDoesNotThrow(() -> runStage5("007-content-valid-large-seq", Stage2Input.CONTENT_BYTE_CAP));
    }

    @Test
    void malformedCanaryTimestampPassesStage5() {
        // AMB-16 (section 11:209): a malformed canary timestamp is a Stage 8
        // canary-integrity failure (E_CANARY_INVALID), not a Stage 5 schema code.
        // Vector 186 carries a malformed canary.next_expected ("garbage"); Stage 5
        // checks only that the canary timestamp fields are strings, so it must
        // pass Stage 5 here. The full pipeline still rejects it at Stage 8 (the
        // conformance suite pins the E_CANARY_INVALID verdict).
        assertDoesNotThrow(() -> runStage5("186-canary-malformed-timestamp", Stage2Input.MANIFEST_BYTE_CAP));
    }
}
