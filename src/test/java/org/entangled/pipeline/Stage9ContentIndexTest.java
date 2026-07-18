package org.entangled.pipeline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.crypto.Sha;
import org.entangled.json.JsonValue;
import org.junit.jupiter.api.Test;

class Stage9ContentIndexTest {

    @Test
    void malformedUtf8IsRejectedAfterHashVerification() {
        byte[] index = {(byte) 0xc3, 0x28};
        assertInvalid(index, contentRoot(index));
    }

    @Test
    void leadingBomIsRejectedAfterHashVerification() {
        byte[] json = "{\"entries\":{}}".getBytes(StandardCharsets.UTF_8);
        byte[] index = new byte[json.length + 3];
        index[0] = (byte) 0xef;
        index[1] = (byte) 0xbb;
        index[2] = (byte) 0xbf;
        System.arraycopy(json, 0, index, 3, json.length);
        assertInvalid(index, contentRoot(index));
    }

    @Test
    void invalidAndReservedEntryPathsAreRejected() {
        String zeroHash = "sha-256:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        for (String path : new String[] {"relative", "/a//b", "/../escape", "/content_index.json"}) {
            byte[] index = ("{\"entries\":{\"" + path
                    + "\":{\"seq\":1,\"hash\":\"" + zeroHash + "\"}}}")
                    .getBytes(StandardCharsets.UTF_8);
            assertInvalid(index, contentRoot(index));
        }
    }

    @Test
    void sizeCapPrecedesHashing() {
        byte[] index = new byte[1024 * 1024 + 1];
        assertInvalid(index, "sha-256:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
    }

    private static void assertInvalid(byte[] index, String root) {
        JsonValue.Obj manifest = new JsonValue.Obj(
                Map.of("content_root", new JsonValue.Str(root)));
        RejectException error = assertThrows(
                RejectException.class,
                () -> Stage9ContentIndex.verifyManifestIndex(manifest, index));
        assertEquals(DiagnosticCode.E_CONTENT_INDEX_INVALID, error.diagnostic().code());
    }

    private static String contentRoot(byte[] bytes) {
        return "sha-256:"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(Sha.sha256(bytes));
    }
}
