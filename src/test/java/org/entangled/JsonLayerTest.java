package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.pipeline.Stage2Input;
import org.junit.jupiter.api.Test;

/**
 * Stage 2 (input) and Stage 3 (parse) behavior, driven by the corpus vectors
 * whose first failing stage is one of those stages. These do not exercise the
 * full pipeline; they verify that the byte/parse layer raises the right
 * diagnostic before any later stage runs.
 */
class JsonLayerTest {

    private static int capForManifest() {
        return Stage2Input.MANIFEST_BYTE_CAP;
    }

    private static int capForContent() {
        return Stage2Input.CONTENT_BYTE_CAP;
    }

    private RejectException rejectOf(String vectorId, int cap) {
        byte[] body = CorpusFiles.vectorInput(vectorId);
        return assertThrows(RejectException.class, () -> {
            String text = Stage2Input.validateAndDecode(body, cap);
            JsonParser.parse(text);
        });
    }

    @Test
    void inputBomVector100() {
        assertEquals(DiagnosticCode.E_INPUT_BOM,
                rejectOf("100-input-bom", capForManifest()).diagnostic().code());
    }

    @Test
    void inputBadUtf8Vector101() {
        assertEquals(DiagnosticCode.E_INPUT_UTF8,
                rejectOf("101-input-bad-utf8", capForManifest()).diagnostic().code());
    }

    @Test
    void inputByteCapVector102() {
        assertEquals(DiagnosticCode.E_INPUT_BYTE_CAP,
                rejectOf("102-input-byte-cap", capForManifest()).diagnostic().code());
    }

    @Test
    void duplicateKeysVector110() {
        assertEquals(DiagnosticCode.E_PARSE_DUPLICATE_KEY,
                rejectOf("110-parse-duplicate-keys", capForContent()).diagnostic().code());
    }

    @Test
    void nestingDepthVector111() {
        assertEquals(DiagnosticCode.E_PARSE_NESTING_DEPTH,
                rejectOf("111-parse-nesting-depth", capForManifest()).diagnostic().code());
    }

    @Test
    void stringLengthVector112() {
        assertEquals(DiagnosticCode.E_PARSE_STRING_LENGTH,
                rejectOf("112-parse-string-length", capForContent()).diagnostic().code());
    }

    @Test
    void arrayLengthVector113() {
        assertEquals(DiagnosticCode.E_PARSE_ARRAY_LENGTH,
                rejectOf("113-parse-array-length", capForContent()).diagnostic().code());
    }

    @Test
    void objectKeysVector114() {
        assertEquals(DiagnosticCode.E_PARSE_OBJECT_KEYS,
                rejectOf("114-parse-object-keys", capForContent()).diagnostic().code());
    }

    @Test
    void malformedJsonVector115() {
        assertEquals(DiagnosticCode.E_PARSE_JSON,
                rejectOf("115-parse-json-malformed", capForManifest()).diagnostic().code());
    }

    @Test
    void integerGrammarClassification() {
        // Conforming integers (well-formed JSON and matching the section 04 grammar).
        assertTrue(((JsonValue.Num) JsonParser.parse("0")).conformingInteger());
        assertTrue(((JsonValue.Num) JsonParser.parse("42")).conformingInteger());
        assertTrue(((JsonValue.Num) JsonParser.parse("9223372036854775807")).conformingInteger());
        // Non-conforming but well-formed JSON: float, exponent, overflow. These
        // parse (so a later stage can read them) but are flagged non-integer for
        // Stage 5 (E_SCHEMA_NON_INTEGER): vectors 140, 141, 142.
        assertFalse(((JsonValue.Num) JsonParser.parse("42.0")).conformingInteger());
        assertFalse(((JsonValue.Num) JsonParser.parse("4.2e1")).conformingInteger());
        assertFalse(((JsonValue.Num) JsonParser.parse("9223372036854775808")).conformingInteger());
        // A leading zero followed by a digit (01) and a bare sign with nothing
        // are not valid JSON at all, so they are E_PARSE_JSON, not a Stage 5
        // integer-grammar failure. No corpus vector exercises leading-zero,
        // consistent with this being a JSON-level malformation.
        assertThrows(RejectException.class, () -> JsonParser.parse("01"));
    }

    @Test
    void wellFormedNumbersParseEvenWhenNonInteger() {
        // A float is valid JSON and must parse; the E_SCHEMA_NON_INTEGER judgment
        // happens at Stage 5, not at parse time.
        JsonValue v = JsonParser.parse("{\"x\":1.5}");
        assertTrue(v instanceof JsonValue.Obj);
    }
}
