package org.entangled.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Thin wrappers over the JDK {@link MessageDigest} for SHA-256 and SHA-512.
 *
 * <p>SHA-256 is used for the PIP checksum (section 05), image and content hash
 * binding, and {@code request_hash} (section 02, section 03). SHA-512 is used
 * inside the Ed25519 verification equation (RFC 8032). These are standard,
 * unambiguous primitives, so the JDK implementations are used directly.
 */
public final class Sha {

    private Sha() {
    }

    public static byte[] sha256(byte[] data) {
        return digest("SHA-256", data);
    }

    public static byte[] sha512(byte[] data) {
        return digest("SHA-512", data);
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " unavailable", e);
        }
    }
}
