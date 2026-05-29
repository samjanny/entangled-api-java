package org.entangled;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.DocumentSchema;
import org.junit.jupiter.api.Test;

/**
 * Stage 5 NFC enforcement on the three {@code submit_form} scalar labels
 * (section 04:159): the form-level {@code submit_label}, each form field's
 * {@code label}, and each select option's {@code label}. A non-NFC value in any
 * of these is {@code E_SCHEMA_FIELD_SYNTAX} (section 04:167), the same rule
 * already applied to {@code canary.statement}, {@code meta.title},
 * {@code image.alt}, {@code code_block.content}, and {@code note.title}.
 *
 * <p>These run Stage 5 ({@link DocumentSchema#validateContent}) directly on
 * hand-built documents, so no signature is needed; a syntactically valid
 * placeholder {@code sig} satisfies the wire-side base64url check. The combining
 * acute {@code U+0301} turns {@code "Cafe" + U+0301} into a decomposed (NFD)
 * string that is not NFC. The all-NFC positive controls double as a guard that
 * the hand-built JSON is otherwise schema-valid. The normative cross-impl
 * coverage is spec corpus vector 192-unicode-nfd-submit-label (rc.35).
 */
class Stage5NfcLabelTest {

    // 64-byte all-zero key encodes to 86 canonical base64url chars; Stage 5
    // only checks sig syntax/length, not the signature itself.
    private static final String SIG = "A".repeat(86);

    // U+0301 combining acute: "Cafe" + this is NFD (not the precomposed NFC form).
    private static final String NFD_LABEL = "Cafe\u0301";

    private static String textFieldForm(String submitLabel, String fieldLabel) {
        return "{\"spec_version\":\"1.0\",\"kind\":\"content\",\"path\":\"/contact-form\","
                + "\"meta\":{\"title\":\"Contact\",\"published_at\":\"2026-05-07T00:00:00Z\"},"
                + "\"blocks\":[{\"kind\":\"submit_form\","
                + "\"label\":[{\"kind\":\"text\",\"value\":\"Contact us\",\"marks\":[]}],"
                + "\"submit_to\":\"/contact\","
                + "\"fields\":[{\"kind\":\"text\",\"name\":\"message\",\"label\":\"" + fieldLabel
                + "\",\"required\":true,\"max_length\":100}],"
                + "\"submit_label\":\"" + submitLabel + "\"}],"
                + "\"sig\":\"" + SIG + "\"}";
    }

    private static String selectFieldForm(String optionLabel) {
        return "{\"spec_version\":\"1.0\",\"kind\":\"content\",\"path\":\"/contact-form\","
                + "\"meta\":{\"title\":\"Contact\",\"published_at\":\"2026-05-07T00:00:00Z\"},"
                + "\"blocks\":[{\"kind\":\"submit_form\","
                + "\"label\":[{\"kind\":\"text\",\"value\":\"Contact us\",\"marks\":[]}],"
                + "\"submit_to\":\"/contact\","
                + "\"fields\":[{\"kind\":\"select\",\"name\":\"choice\",\"label\":\"Pick\",\"required\":true,"
                + "\"options\":[{\"value\":\"a\",\"label\":\"" + optionLabel + "\"}]}],"
                + "\"submit_label\":\"Send\"}],"
                + "\"sig\":\"" + SIG + "\"}";
    }

    private static DiagnosticCode rejectCode(String json) {
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(json);
        RejectException ex = assertThrows(RejectException.class,
                () -> DocumentSchema.validateContent(doc));
        return ex.diagnostic().code();
    }

    private static void acceptsSchema(String json) {
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(json);
        assertDoesNotThrow(() -> DocumentSchema.validateContent(doc));
    }

    @Test
    void submitLabelNfdRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(textFieldForm(NFD_LABEL, "Message")));
    }

    @Test
    void fieldLabelNfdRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(textFieldForm("Send", NFD_LABEL)));
    }

    @Test
    void optionLabelNfdRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(selectFieldForm(NFD_LABEL)));
    }

    @Test
    void allNfcLabelsAccepted() {
        // Positive controls: identical forms with NFC labels must pass Stage 5.
        // These also guard that the hand-built JSON is otherwise schema-valid.
        acceptsSchema(textFieldForm("Send", "Message"));
        acceptsSchema(selectFieldForm("Option A"));
    }
}
