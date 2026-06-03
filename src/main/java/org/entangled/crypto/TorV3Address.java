package org.entangled.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Tor v3 onion address decoding, following the rend-spec-v3 "Encoding onion
 * addresses" procedure referenced by section 05.
 *
 * <p>A v3 address is {@code base32(PUBKEY || CHECKSUM || VERSION) + ".onion"},
 * where {@code PUBKEY} is the 32-byte Ed25519 service public key,
 * {@code CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]}, and
 * {@code VERSION = 0x03}. The base32 alphabet is lowercase RFC 4648 ({@code a-z2-7}),
 * yielding a 56-character address body before the {@code .onion} suffix.
 *
 * <p>Decoding validates the structure, the version byte, and the checksum, and
 * returns the embedded public key so the caller can compare it to
 * {@code origin.origin_pubkey} (origin binding, section 06; failure maps to
 * {@code E_BIND_ORIGIN}). The inverse direction, {@link #encodePublicKey},
 * derives the canonical address from an origin public key, which a publisher
 * needs when building a manifest origin.
 */
public final class TorV3Address {

    /** Thrown when an address is not a structurally valid Tor v3 onion address. */
    public static final class InvalidOnionAddress extends RuntimeException {
        public InvalidOnionAddress(String message) {
            super(message);
        }
    }

    private static final String SUFFIX = ".onion";
    private static final int ADDRESS_BODY_LEN = 56;
    private static final byte VERSION = 0x03;
    private static final byte[] CHECKSUM_PREFIX = ".onion checksum".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final String BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

    private TorV3Address() {
    }

    /**
     * Decode and validate a canonical Tor v3 address; return the 32-byte service
     * public key. The address must be lowercase, exactly 56 base32 characters
     * before the {@code .onion} suffix, with no scheme, port, path, query, or
     * fragment.
     */
    public static byte[] decodePublicKey(String address) {
        if (!address.endsWith(SUFFIX)) {
            throw new InvalidOnionAddress("missing .onion suffix");
        }
        String body = address.substring(0, address.length() - SUFFIX.length());
        if (body.length() != ADDRESS_BODY_LEN) {
            throw new InvalidOnionAddress("address body must be 56 characters, got " + body.length());
        }
        byte[] decoded = base32Decode(body); // 35 bytes
        if (decoded.length != 35) {
            throw new InvalidOnionAddress("decoded length must be 35 bytes");
        }
        byte[] pubkey = Arrays.copyOfRange(decoded, 0, 32);
        byte[] checksum = Arrays.copyOfRange(decoded, 32, 34);
        byte version = decoded[34];
        if (version != VERSION) {
            throw new InvalidOnionAddress("version byte must be 0x03");
        }
        byte[] expectedChecksum = computeChecksum(pubkey, version);
        if (!(checksum[0] == expectedChecksum[0] && checksum[1] == expectedChecksum[1])) {
            throw new InvalidOnionAddress("checksum mismatch");
        }
        return pubkey;
    }

    /**
     * Derive the canonical Tor v3 onion address from a 32-byte Ed25519 origin
     * public key. The exact inverse of {@link #decodePublicKey}: compute
     * {@code CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || 0x03)[:2]},
     * base32-encode {@code PUBKEY || CHECKSUM || VERSION} in the lowercase RFC
     * 4648 alphabet, and append {@code .onion}. A publisher building a manifest
     * origin derives the address this way from its origin key.
     */
    public static String encodePublicKey(byte[] pubkey) {
        if (pubkey.length != 32) {
            throw new InvalidOnionAddress("origin public key must be 32 bytes, got " + pubkey.length);
        }
        byte[] checksum = computeChecksum(pubkey, VERSION);
        byte[] body = new byte[35];
        System.arraycopy(pubkey, 0, body, 0, 32);
        body[32] = checksum[0];
        body[33] = checksum[1];
        body[34] = VERSION;
        return base32Encode(body) + SUFFIX;
    }

    private static byte[] computeChecksum(byte[] pubkey, byte version) {
        byte[] input = new byte[CHECKSUM_PREFIX.length + pubkey.length + 1];
        int pos = 0;
        System.arraycopy(CHECKSUM_PREFIX, 0, input, pos, CHECKSUM_PREFIX.length);
        pos += CHECKSUM_PREFIX.length;
        System.arraycopy(pubkey, 0, input, pos, pubkey.length);
        pos += pubkey.length;
        input[pos] = version;
        byte[] hash = sha3_256(input);
        return new byte[] {hash[0], hash[1]};
    }

    private static byte[] sha3_256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA3-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 unavailable", e);
        }
    }

    /** Lowercase RFC 4648 base32 decode (no padding); 56 chars -> 35 bytes. */
    private static byte[] base32Decode(String s) {
        int outLen = s.length() * 5 / 8;
        byte[] out = new byte[outLen];
        int buffer = 0;
        int bits = 0;
        int outPos = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int v = BASE32_ALPHABET.indexOf(c);
            if (v < 0) {
                throw new InvalidOnionAddress("character outside lowercase base32 alphabet: " + c);
            }
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[outPos++] = (byte) ((buffer >> bits) & 0xFF);
            }
        }
        return out;
    }

    /** Lowercase RFC 4648 base32 encode (no padding); 35 bytes -> 56 chars. */
    private static String base32Encode(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 8 / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(BASE32_ALPHABET.charAt((buffer >> bits) & 0x1F));
            }
        }
        if (bits > 0) {
            out.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
        }
        return out.toString();
    }
}
