package org.entangled.pipeline;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;

/**
 * Stage 2 byte-level checks (section 10, section 04):
 * <ul>
 *   <li>byte size within the document-kind cap (enforced before parsing);</li>
 *   <li>strict UTF-8 validation (no overlong, no surrogate code points, no
 *       malformed sequences);</li>
 *   <li>no leading UTF-8 BOM.</li>
 * </ul>
 *
 * <p>The cap is checked first: a response that exceeds its cap is rejected
 * without further inspection. BOM is checked before UTF-8 decoding because a
 * BOM is well-formed UTF-8 but is its own rejection condition (section 04 "No
 * BOM"); ordering it first yields {@code E_INPUT_BOM} rather than letting it
 * pass UTF-8 validation.
 */
public final class Stage2Input {

    /** Document-kind byte caps (section 02, section 06, section 09). */
    public static final int MANIFEST_BYTE_CAP = 64 * 1024;
    public static final int CONTENT_BYTE_CAP = 1024 * 1024;
    public static final int TRANSACTION_BYTE_CAP = 1024 * 1024;
    public static final int SUBMIT_BYTE_CAP = 64 * 1024;

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private Stage2Input() {
    }

    /**
     * Validate raw body bytes and decode to a String for parsing.
     *
     * @param body    the exact response body bytes
     * @param byteCap the document-kind cap to enforce before any decoding
     * @return the decoded UTF-8 String, guaranteed BOM-free and strict UTF-8
     */
    public static String validateAndDecode(byte[] body, int byteCap) {
        if (body.length > byteCap) {
            throw new RejectException(DiagnosticCode.E_INPUT_BYTE_CAP);
        }
        if (startsWithBom(body)) {
            throw new RejectException(DiagnosticCode.E_INPUT_BOM);
        }
        return decodeStrictUtf8(body);
    }

    private static boolean startsWithBom(byte[] body) {
        if (body.length < UTF8_BOM.length) {
            return false;
        }
        for (int i = 0; i < UTF8_BOM.length; i++) {
            if (body[i] != UTF8_BOM[i]) {
                return false;
            }
        }
        return true;
    }

    private static String decodeStrictUtf8(byte[] body) {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(java.nio.ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            throw new RejectException(DiagnosticCode.E_INPUT_UTF8);
        }
    }
}
