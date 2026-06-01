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
 * class is only a thin, documented layer that adds the strict-profile
 * rejections the JDK does not perform, exactly as section 05:180 directs: "Where
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
 * <p><b>What is delegated to the JDK.</b> Only the irreducible curve operations
 * are left to {@code SunEC}: the on-curve decoding of {@code A} and {@code R},
 * SHA-512, and -- critically for section 05:178 -- the evaluation of the
 * <em>cofactorless</em> equation, so mixed-order (torsion-laden) points that a
 * cofactored verifier would accept are rejected. These are not re-implemented
 * here; reimplementing curve arithmetic would be hand-rolled crypto.
 *
 * <p><b>What this layer decides itself, before delegating.</b> Every
 * strict-profile accept/reject <em>policy</em> is made here, so acceptance does
 * not depend on the provider's internal point/scalar policy:
 * <ul>
 *   <li><b>non-canonical point encodings</b> of {@code A} and {@code R}
 *       ({@code y >= p}, sign bit masked off) (section 05:154, 05:168).
 *       {@code SunEC} does NOT reject these: it reduces {@code y} modulo
 *       {@code p} (ZIP-215 style) and verifies against the reduced point, so a
 *       non-canonical encoding of the genuine key, presented with a signature
 *       valid under the reduced point, would otherwise be accepted. The check
 *       compares the little-endian {@code y} against {@code p = 2^255 - 19}.</li>
 *   <li><b>small-order points</b> {@code A} and {@code R} (order dividing the
 *       cofactor 8) (section 05:155, 05:174). {@code SunEC} does not reject
 *       these either. The check is a constant-table comparison against the eight
 *       known small-order point encodings on edwards25519.</li>
 *   <li><b>non-canonical scalar</b> {@code S} ({@code S >= L}) (section 05:169).
 *       {@code SunEC} does reject this today, but the rejection is made here too,
 *       as a little-endian compare of {@code S} against the group order
 *       {@code L}, so the policy is not delegated to the provider.</li>
 * </ul>
 * None of these checks perform curve arithmetic; they are constant-table or
 * integer-bound comparisons. All three match the {@code verify_strict} mode in
 * {@code ed25519-dalek} that section 05 names as the reference (it rejects when
 * {@code signature_R.is_small_order()} or {@code A.is_small_order()}, rejects
 * non-canonical compressed points, and checks {@code S < L}).
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
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        // Strict-profile additions the JDK does not perform, applied before the
        // equation is evaluated. R is the first 32 bytes of the signature.
        //
        //   1. Reject a non-canonical encoding of A or R (section 05:154,
        //      05:168): y >= p with the sign bit masked off. SunEC does NOT
        //      reject these; it reduces y mod p (ZIP-215 style) and verifies
        //      against the reduced point, so a non-canonical encoding of the
        //      genuine key with a signature valid under the reduced point would
        //      otherwise be accepted.
        //   2. Reject a small-order A or R (section 05:155, 05:174): a point of
        //      order dividing the cofactor 8.
        //
        // Both match the verify_strict mode in ed25519-dalek that section 05
        // names as the reference.
        if (!isCanonicalEncoding(publicKey) || !isCanonicalEncoding(r)) {
            return false;
        }
        if (isSmallOrder(publicKey) || isSmallOrder(r)) {
            return false;
        }
        // 3. Reject a non-canonical scalar S (section 05:169): S, little-endian,
        //    MUST satisfy 0 <= S < L. SunEC does enforce this today, but the
        //    strict-profile accept/reject policy is decided here, in-layer, so
        //    that acceptance does not depend on the provider's internal scalar
        //    policy. This is an integer bound check, not curve arithmetic.
        if (!isCanonicalScalarS(signature)) {
            return false;
        }
        // Only the irreducible curve operations are delegated to the JDK
        // (SunEC): the on-curve decoding of A and R, SHA-512, and the
        // cofactorless RFC 8032 verification equation [S]B = R + [k]A. Every
        // strict-profile accept/reject decision above this point is made by this
        // layer, not by the provider. The provider is pinned to the platform
        // Ed25519 service; any failure, or its absence, rejects (fail closed).
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

    // Edwards25519 field prime p = 2^255 - 19, as 32 little-endian bytes. A
    // canonical public-key encoding has y < p once the high (x-sign) bit of
    // byte 31 is masked off (RFC 8032 section 5.1.2).
    private static final byte[] ED25519_FIELD_PRIME_LE =
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    /** Little-endian unsigned 32-byte comparison: true iff a &lt; b. */
    private static boolean ltLe32(byte[] a, byte[] b) {
        for (int i = 31; i >= 0; i--) {
            int ai = a[i] & 0xFF;
            int bi = b[i] & 0xFF;
            if (ai < bi) {
                return true;
            }
            if (ai > bi) {
                return false;
            }
        }
        return false;
    }

    /** True iff the 32-byte encoding is canonical: y &lt; p with the sign bit masked off. */
    private static boolean isCanonicalEncoding(byte[] publicKey) {
        byte[] y = publicKey.clone();
        y[31] &= 0x7F;
        return ltLe32(y, ED25519_FIELD_PRIME_LE);
    }

    // The order of the Ed25519 base point, L = 2^252 +
    // 27742317777372353535851937790883648493, as 32 little-endian bytes. A
    // canonical signature scalar satisfies 0 <= S < L (RFC 8032 section 5.1.7,
    // section 05:169).
    private static final byte[] ED25519_GROUP_ORDER_LE =
            hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

    /** True iff S (the trailing 32 bytes of the signature) is canonical: S &lt; L. */
    private static boolean isCanonicalScalarS(byte[] signature) {
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        return ltLe32(s, ED25519_GROUP_ORDER_LE);
    }

    /**
     * The section 05 strict profile for a public key that verifies no document
     * in the current context (e.g. {@code origin.origin_pubkey}, section 05:157,
     * 05:159): the 32-byte encoding MUST be canonical ({@code y < p}) and MUST
     * NOT be a small-order point. Mirrors the Rust reference
     * {@code validate_pubkey_strict}.
     */
    public static boolean isStrictProfilePubkey(byte[] publicKey) {
        return publicKey.length == 32
                && isCanonicalEncoding(publicKey)
                && !isSmallOrder(publicKey);
    }

    /** Wrap a raw 32-byte Ed25519 public key in its X.509 SubjectPublicKeyInfo encoding. */
    private static byte[] x509Wrap(byte[] rawKey) {
        byte[] out = new byte[X509_ED25519_PREFIX.length + rawKey.length];
        System.arraycopy(X509_ED25519_PREFIX, 0, out, 0, X509_ED25519_PREFIX.length);
        System.arraycopy(rawKey, 0, out, X509_ED25519_PREFIX.length, rawKey.length);
        return out;
    }

    /**
     * Package-private view of {@link #x509Wrap} for the boundary-invariant tests:
     * the wrapping is an X.509 envelope around the raw key, never a modification
     * of the 32 verified key bytes. The test pins it byte-exact against the JDK's
     * own {@code getEncoded()} so SunEC never decodes a key other than the one
     * this layer validated.
     */
    static byte[] x509WrapForTest(byte[] rawKey) {
        return x509Wrap(rawKey);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
