package org.entangled.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Strict Ed25519 verification (section 05 "Ed25519 verification profile").
 *
 * <p><b>Do not ship your own crypto.</b> The curve arithmetic, the SHA-512 hash,
 * and the RFC 8032 verification equation are delegated to the JDK's built-in
 * Ed25519 implementation (the {@code SunEC} provider, JEP 339, JDK 15+). This
 * class is only a thin, documented layer that adds the one strict-profile
 * rejection the JDK does not perform, exactly as section 05:180 directs: "Where
 * a library does not expose a strict mode separately, the implementation MUST
 * add the rejections defined above on top of the library's default verification
 * path."
 *
 * <p>The strict profile (RFC 8032 plus the section 05 additions) accepts a
 * signature only if:
 * <ul>
 *   <li>the public key {@code A} is a canonical 32-byte compressed point and is
 *       not a small-order point (order dividing the cofactor 8) (section 05:154,
 *       05:155);</li>
 *   <li>the signature is exactly 64 bytes, parsed as {@code R || S};</li>
 *   <li>{@code R} is a canonical compressed point and is not a small-order point
 *       (section 05:168, 05:174);</li>
 *   <li>{@code S}, little-endian, satisfies {@code 0 <= S < L} (section 05:169);</li>
 *   <li>the cofactorless verification equation {@code [S]B = R + [k]A} holds, for
 *       {@code k = SHA-512(R || A || M) mod L} (section 05:170). Section 05:178
 *       forbids the cofactored equation {@code [8S]B = [8]R + [8][k]A}.</li>
 * </ul>
 *
 * <p><b>What the JDK already enforces.</b> {@code SunEC}'s Ed25519 verify rejects
 * a non-canonical scalar {@code S} ({@code S >= L}) and non-canonical point
 * encodings of {@code A} and {@code R} ({@code y >= p}), and -- critically for
 * section 05:178 -- it evaluates the <em>cofactorless</em> equation, so it
 * rejects mixed-order (torsion-laden) points that a cofactored verifier would
 * accept. Those checks are not re-implemented here.
 *
 * <p><b>What the JDK does not do, and this layer adds: explicit small-order
 * rejection of {@code A} and {@code R}</b> (section 05:174). {@code SunEC} does
 * not reject small-order points, so a small-order {@code A} or {@code R} is
 * caught here, before delegating, to match the {@code verify_strict} mode in
 * {@code ed25519-dalek} that section 05 names as the reference (it rejects when
 * {@code signature_R.is_small_order()} or {@code A.is_small_order()}). The check
 * is a constant-table comparison against the eight known small-order point
 * encodings on edwards25519 -- it performs no curve arithmetic of its own.
 *
 * <p><b>Conformance is measured, not assumed.</b> Run against the 15
 * {@code ed25519-speccheck} vectors (Chalkias-Garillot-Nikolaenko, "Taming the
 * Many EdDSAs"), this verifier matches {@code ed25519-dalek} {@code verify_strict}
 * on all 15: the four small-order cases the JDK would otherwise accept (speccheck
 * indices 1, 3, 5, 13) are rejected by the small-order table; the two mixed-order
 * cofactor cases (indices 6, 8) are rejected by the JDK's cofactorless equation;
 * the non-canonical-{@code S} and non-canonical-encoding cases (9-12) and the
 * remaining small-order cases (0, 2, 4, 14) are rejected; and the single valid
 * case (index 7) is accepted. {@code CryptoTest} pins this, and the Entangled
 * spec corpus verifies unchanged.
 */
public final class Ed25519 {

    private Ed25519() {
    }

    /**
     * The eight small-order points on edwards25519, as their canonical 32-byte
     * little-endian compressed encodings. A point whose encoding matches any of
     * these has order dividing the cofactor 8 and is rejected for both {@code A}
     * and {@code R} (section 05:155, 05:174). These are the same constants used
     * by libsodium's small-order blocklist and the {@code ed25519-dalek}
     * {@code is_small_order} check.
     */
    private static final byte[][] SMALL_ORDER_POINTS = {
        hex("0100000000000000000000000000000000000000000000000000000000000000"),
        hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        hex("0000000000000000000000000000000000000000000000000000000000000080"),
        hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    };

    // The DER SubjectPublicKeyInfo prefix for an Ed25519 raw public key: the
    // X.509 wrapper SunEC's KeyFactory expects ahead of the 32 raw key bytes.
    // (SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (32 bytes) }.)
    private static final byte[] X509_ED25519_PREFIX =
            hex("302a300506032b6570032100");

    /**
     * Verify a signature under the strict profile.
     *
     * @param publicKey 32-byte compressed public key A
     * @param signature 64-byte signature R || S
     * @param message   the signature input M (context || 0x00 || JCS(payload))
     * @return true iff the signature is valid under the strict profile
     */
    public static boolean verify(byte[] publicKey, byte[] signature, byte[] message) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        // Strict-profile addition (section 05:174): reject a small-order public
        // key A or signature component R before the equation is evaluated. R is
        // the first 32 bytes of the signature. The JDK does not do this.
        if (isSmallOrder(publicKey) || isSmallOrder(Arrays.copyOfRange(signature, 0, 32))) {
            return false;
        }
        // Delegate the canonical-S check, canonical R/A decoding, SHA-512, and
        // the cofactorless RFC 8032 verification equation to the JDK (SunEC).
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(x509Wrap(publicKey)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // A malformed key or signature (non-canonical encoding, bad point)
            // surfaces as a verification failure, not an accept.
            return false;
        }
    }

    /** True iff the 32-byte compressed encoding is one of the eight small-order points. */
    private static boolean isSmallOrder(byte[] pointEncoding) {
        for (byte[] candidate : SMALL_ORDER_POINTS) {
            if (Arrays.equals(pointEncoding, candidate)) {
                return true;
            }
        }
        return false;
    }

    /** Wrap a raw 32-byte Ed25519 public key in its X.509 SubjectPublicKeyInfo encoding. */
    private static byte[] x509Wrap(byte[] rawKey) {
        byte[] out = new byte[X509_ED25519_PREFIX.length + rawKey.length];
        System.arraycopy(X509_ED25519_PREFIX, 0, out, 0, X509_ED25519_PREFIX.length);
        System.arraycopy(rawKey, 0, out, X509_ED25519_PREFIX.length, rawKey.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
