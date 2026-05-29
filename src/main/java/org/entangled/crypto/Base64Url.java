package org.entangled.crypto;

/**
 * Strict base64url decoding per RFC 4648 Section 5 ("Base 64 Encoding with URL
 * and Filename Safe Alphabet"), with the additional strictness Entangled
 * requires (section 04 "Strict base64url decoding").
 *
 * <p>The decoder:
 * <ul>
 *   <li>accepts only the URL-safe alphabet {@code A-Z a-z 0-9 - _};</li>
 *   <li>rejects every other character, including {@code +}, {@code /},
 *       whitespace, line breaks, control characters, and any character above
 *       U+007F;</li>
 *   <li>rejects the padding character {@code =} (Entangled fields are unpadded);</li>
 *   <li>rejects inputs whose length is not the field-declared exact ASCII
 *       length;</li>
 *   <li>rejects non-canonical encodings: the unused bits of the final encoded
 *       character must be zero, so each input maps to a unique byte string.</li>
 * </ul>
 *
 * <p>A violation of any rule is signalled by {@link InvalidBase64Url}; callers
 * map it to {@code E_SCHEMA_FIELD_SYNTAX} at Stage 5.
 */
public final class Base64Url {

    /** Thrown when a base64url field violates the strict decoding rules. */
    public static final class InvalidBase64Url extends RuntimeException {
        public InvalidBase64Url(String message) {
            super(message);
        }
    }

    private static final int[] DECODE = new int[128];

    static {
        for (int i = 0; i < DECODE.length; i++) {
            DECODE[i] = -1;
        }
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < alphabet.length(); i++) {
            DECODE[alphabet.charAt(i)] = i;
        }
    }

    private Base64Url() {
    }

    /**
     * Decode an unpadded base64url string into exactly {@code expectedBytes}
     * bytes. The encoded length must equal {@code ceil(expectedBytes * 8 / 6)}
     * and the input must satisfy every strictness rule above.
     *
     * @param s             the encoded string
     * @param expectedBytes the exact number of decoded bytes the field declares
     * @return the decoded bytes (length {@code expectedBytes})
     */
    public static byte[] decode(String s, int expectedBytes) {
        int expectedChars = (expectedBytes * 8 + 5) / 6;
        if (s.length() != expectedChars) {
            throw new InvalidBase64Url("length " + s.length() + " != expected " + expectedChars);
        }
        byte[] out = new byte[expectedBytes];
        int outPos = 0;
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 128) {
                throw new InvalidBase64Url("non-ASCII character at " + i);
            }
            int v = DECODE[c];
            if (v < 0) {
                throw new InvalidBase64Url("character outside base64url alphabet at " + i + ": " + c);
            }
            buffer = (buffer << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[outPos++] = (byte) ((buffer >> bits) & 0xFF);
            }
        }
        // Canonical-encoding check: any leftover bits in the final group must be zero.
        if (bits > 0) {
            int mask = (1 << bits) - 1;
            if ((buffer & mask) != 0) {
                throw new InvalidBase64Url("non-canonical trailing bits");
            }
        }
        if (outPos != expectedBytes) {
            // Should not happen given the length check, but guard anyway.
            throw new InvalidBase64Url("decoded " + outPos + " bytes, expected " + expectedBytes);
        }
        return out;
    }
}
