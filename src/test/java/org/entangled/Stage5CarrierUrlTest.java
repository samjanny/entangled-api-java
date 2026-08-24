package org.entangled;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.DocumentSchema;
import org.junit.jupiter.api.Test;

/**
 * Stage 5 validation of a {@code carrier} link target URL (section 03:584): the
 * URL host MUST be a valid carrier address for the declared carrier -- for
 * {@code tor-v3}, a 56-character onion address followed by {@code .onion}. A URL
 * whose host is not a valid onion v3 address is {@code E_SCHEMA_FIELD_SYNTAX}.
 *
 * <p>Previously the carrier URL was only checked for the {@code http://} scheme,
 * a 1 KiB length cap, and absence of control/space characters; the onion host
 * was not validated, so a clearnet-style host was accepted.
 *
 * <p>Runs Stage 5 ({@link DocumentSchema#validateContent}) directly on hand-built
 * documents; a syntactically valid placeholder {@code sig} satisfies the
 * wire-side base64url check. Normative cross-impl coverage is spec corpus vector
 * 158-link-carrier-url-non-onion-host (rc.37).
 */
class Stage5CarrierUrlTest {

    private static final String SIG = "A".repeat(86);
    // A valid 56-char tor v3 onion address (corpus keys.json "origin").
    private static final String ONION =
            "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";

    private static String contentWithCarrierLink(String url) {
        return "{\"spec_version\":\"1.0\",\"kind\":\"content\",\"path\":\"/p\","
                + "\"meta\":{\"title\":\"T\",\"published_at\":\"2026-05-07T00:00:00Z\"},"
                + "\"blocks\":[{\"kind\":\"link\","
                + "\"label\":[{\"kind\":\"text\",\"value\":\"Link\",\"marks\":[]}],"
                + "\"target\":{\"kind\":\"carrier\",\"carrier\":\"tor-v3\",\"url\":\"" + url + "\"}}],"
                + "\"sig\":\"" + SIG + "\"}";
    }

    private static String contentWithCitationLink(String url) {
        return "{\"spec_version\":\"1.0\",\"kind\":\"content\",\"path\":\"/p\","
                + "\"meta\":{\"title\":\"T\",\"published_at\":\"2026-05-07T00:00:00Z\"},"
                + "\"blocks\":[{\"kind\":\"link\","
                + "\"label\":[{\"kind\":\"text\",\"value\":\"Link\",\"marks\":[]}],"
                + "\"target\":{\"kind\":\"citation\",\"url\":\"" + url + "\"}}],"
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
    void clearnetHostRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(contentWithCarrierLink("http://example.com/path")));
    }

    @Test
    void emptyHostRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(contentWithCarrierLink("http:///path")));
    }

    @Test
    void shortOnionHostRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(contentWithCarrierLink("http://abc.onion/path")));
    }

    @Test
    void validOnionHostAccepted() {
        // Positive control (also guards the hand-built JSON is schema-valid).
        acceptsSchema(contentWithCarrierLink("http://" + ONION + "/path"));
        // A port after the onion host is stripped before host validation.
        acceptsSchema(contentWithCarrierLink("http://" + ONION + ":8080/path"));
    }

    @Test
    void carrierUserinfoRejectedBeforeOnionHostValidation() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(contentWithCarrierLink("http://trusted.example@" + ONION + "/path")));
    }

    @Test
    void citationUserinfoRejected() {
        assertEquals(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX,
                rejectCode(contentWithCitationLink(
                        "https://trusted.example@evil.example/reference")));
    }

    @Test
    void citationExplicitProfileFeaturesAccepted() {
        acceptsSchema(contentWithCitationLink(
                "https://example.org:8443/a%2Fb?x=%7e#part%2Fone"));
    }
}
