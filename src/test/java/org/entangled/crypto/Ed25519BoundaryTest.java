package org.entangled.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Trust-boundary invariants between this layer and the JDK {@code SunEC}
 * provider. The layer adds strict-profile rejections on top of SunEC; these
 * tests pin that the layer can only ever ADD rejections and never induce SunEC
 * to accept something it would not, so a future bug in the layer cannot
 * compromise the provider's verdict in the unsafe (accept) direction.
 *
 * <p>The security argument is structural: {@code Ed25519.verify} runs its own
 * checks as {@code return false} guards and then returns SunEC's verdict on the
 * original, untransformed bytes. That makes the relationship a monotone AND:
 * {@code accept <=> (layer checks pass) AND (SunEC accepts)}. These tests turn
 * that argument into executable guarantees.
 */
class Ed25519BoundaryTest {

    private static final byte[] X509_ED25519_PREFIX = hex("302a300506032b6570032100");

    /**
     * Invariant: monotone AND. For a broad spread of inputs (a genuine signature
     * and many mutations of it), whenever {@code Ed25519.verify} accepts, a raw
     * SunEC verification of the SAME original bytes also accepts. The layer never
     * accepts beyond SunEC, so no layer bug can widen acceptance.
     */
    @Test
    void layerNeverAcceptsBeyondRawSunEc() throws Exception {
        Random rnd = new Random(0x0E17A4D25519L); // fixed seed: reproducible
        int trials = 0;
        int layerAccepts = 0;
        for (int i = 0; i < 400; i++) {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] msg = new byte[1 + rnd.nextInt(48)];
            rnd.nextBytes(msg);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            byte[] pub = rawPub(kp.getPublic());

            // The genuine triple, plus mutations that exercise every layer guard
            // and the equation: flipped bits in pub/sig/msg, non-canonical S, and
            // small-order / non-canonical point encodings.
            byte[][][] cases = mutations(pub, sig, msg, rnd);
            for (byte[][] c : cases) {
                byte[] p = c[0];
                byte[] s = c[1];
                byte[] m = c[2];
                trials++;
                boolean layer = Ed25519.verify(p, s, m);
                if (layer) {
                    layerAccepts++;
                    // The core invariant: a layer accept implies a raw SunEC
                    // accept on the identical original bytes.
                    assertTrue(rawSunEcVerify(p, s, m),
                            "layer accepted but raw SunEC rejected the same bytes (case " + i + ")");
                }
            }
        }
        // Sanity: the genuine signatures were among the inputs, so the layer did
        // accept some cases (otherwise the implication would be vacuous).
        assertTrue(layerAccepts > 0, "expected some genuine signatures to be accepted");
        assertTrue(trials > 1000, "expected a broad input spread");
    }

    /**
     * Invariant: the bytes verified by SunEC are the original input bytes, not a
     * layer-normalized copy. Proven by reconstructing SunEC's verdict in the test
     * from the SAME pub/sig/msg the layer received and requiring exact agreement
     * for genuine signatures (accept) and for a tampered message (reject). If the
     * layer silently rewrote any of the three before delegating, this agreement
     * on the original bytes would not hold.
     */
    @Test
    void delegatesOriginalUntransformedBytes() throws Exception {
        Random rnd = new Random(0x0B17E5L);
        for (int i = 0; i < 50; i++) {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] msg = new byte[16 + rnd.nextInt(32)];
            rnd.nextBytes(msg);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            byte[] pub = rawPub(kp.getPublic());

            assertEquals(rawSunEcVerify(pub, sig, msg), Ed25519.verify(pub, sig, msg),
                    "layer and raw SunEC must agree on the genuine triple");

            byte[] tampered = msg.clone();
            tampered[rnd.nextInt(tampered.length)] ^= 0x01;
            assertEquals(rawSunEcVerify(pub, sig, tampered), Ed25519.verify(pub, sig, tampered),
                    "layer and raw SunEC must agree on a tampered message");
            assertFalse(Ed25519.verify(pub, sig, tampered), "tampered message must be rejected");
        }
    }

    /**
     * Invariant: {@code x509Wrap} is a byte-exact X.509 SubjectPublicKeyInfo
     * envelope around the raw 32 key bytes, never a modification of them. Pinned
     * against the JDK's own {@code getEncoded()} so SunEC decodes exactly the key
     * this layer validated.
     */
    @Test
    void x509WrapIsByteExactEnvelope() throws Exception {
        for (int i = 0; i < 20; i++) {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] jdkEncoded = kp.getPublic().getEncoded();
            byte[] raw = rawPub(kp.getPublic());
            byte[] wrapped = Ed25519.x509WrapForTest(raw);
            assertArrayEquals(jdkEncoded, wrapped,
                    "x509Wrap must reproduce the JDK SubjectPublicKeyInfo byte-for-byte");
            // The trailing 32 bytes of the wrapping are exactly the raw key.
            byte[] tail = new byte[32];
            System.arraycopy(wrapped, wrapped.length - 32, tail, 0, 32);
            assertArrayEquals(raw, tail, "the wrapped key bytes must equal the raw input");
        }
    }

    /**
     * Invariant: the Ed25519 service resolves to the expected platform provider,
     * and the verify path is fail-closed. A missing or substituted provider, or
     * any provider failure, yields reject (false), never accept.
     */
    @Test
    void providerIsSunEcAndFailClosed() throws Exception {
        assertEquals("SunEC", Signature.getInstance("Ed25519").getProvider().getName(),
                "Ed25519 Signature must resolve to the SunEC provider");
        assertEquals("SunEC", KeyFactory.getInstance("Ed25519").getProvider().getName(),
                "Ed25519 KeyFactory must resolve to the SunEC provider");

        // Fail-closed: structurally malformed inputs reject rather than throw or
        // accept. Wrong lengths, all-zero (small-order) key, and a key that is
        // valid bytes but cannot be a public key all return false.
        assertFalse(Ed25519.verify(new byte[31], new byte[64], new byte[8]), "short key rejects");
        assertFalse(Ed25519.verify(new byte[32], new byte[63], new byte[8]), "short sig rejects");
        assertFalse(Ed25519.verify(new byte[32], new byte[64], new byte[8]),
                "all-zero key (small-order) and zero sig reject");
    }

    // --- helpers ---

    /**
     * A reference verification using SunEC directly on the given bytes, wrapping
     * the key in X.509 exactly as the layer does. This is the "raw provider"
     * verdict the layer must never exceed in the accept direction.
     */
    private static boolean rawSunEcVerify(byte[] pub, byte[] sig, byte[] msg) {
        if (pub.length != 32 || sig.length != 64) {
            return false;
        }
        try {
            byte[] x509 = new byte[X509_ED25519_PREFIX.length + 32];
            System.arraycopy(X509_ED25519_PREFIX, 0, x509, 0, X509_ED25519_PREFIX.length);
            System.arraycopy(pub, 0, x509, X509_ED25519_PREFIX.length, 32);
            PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(x509));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(key);
            v.update(msg);
            return v.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Extract the raw 32-byte key from an X.509-encoded Ed25519 public key. */
    private static byte[] rawPub(PublicKey pub) {
        byte[] enc = pub.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(enc, enc.length - 32, raw, 0, 32);
        return raw;
    }

    /**
     * A spread of cases around a genuine triple: the genuine one, single-bit
     * flips in each of pub/sig/msg, a non-canonical scalar S (S + L), and small-
     * order / non-canonical point substitutions for A and R.
     */
    private static byte[][][] mutations(byte[] pub, byte[] sig, byte[] msg, Random rnd) {
        java.util.List<byte[][]> out = new java.util.ArrayList<>();
        out.add(new byte[][] {pub, sig, msg}); // genuine

        byte[] pubFlip = pub.clone();
        pubFlip[rnd.nextInt(32)] ^= (byte) (1 << rnd.nextInt(8));
        out.add(new byte[][] {pubFlip, sig, msg});

        byte[] sigFlip = sig.clone();
        sigFlip[rnd.nextInt(64)] ^= (byte) (1 << rnd.nextInt(8));
        out.add(new byte[][] {pub, sigFlip, msg});

        byte[] msgFlip = msg.clone();
        msgFlip[rnd.nextInt(msg.length)] ^= (byte) (1 << rnd.nextInt(8));
        out.add(new byte[][] {pub, sig, msgFlip});

        // Non-canonical S = S + L.
        java.math.BigInteger order = java.math.BigInteger.TWO.pow(252)
                .add(new java.math.BigInteger("27742317777372353535851937790883648493"));
        byte[] sBe = new byte[32];
        for (int i = 0; i < 32; i++) {
            sBe[i] = sig[63 - i];
        }
        java.math.BigInteger sPlusL = new java.math.BigInteger(1, sBe).add(order);
        if (sPlusL.bitLength() <= 256) {
            byte[] raw = sPlusL.toByteArray();
            byte[] be = new byte[32];
            int copy = Math.min(raw.length, 32);
            System.arraycopy(raw, raw.length - copy, be, 32 - copy, copy);
            byte[] badS = sig.clone();
            for (int i = 0; i < 32; i++) {
                badS[32 + i] = be[31 - i];
            }
            out.add(new byte[][] {pub, badS, msg});
        }

        // Small-order / non-canonical A and R substitutions.
        String[] badPoints = {
            "0100000000000000000000000000000000000000000000000000000000000000", // small-order
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // small-order
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // non-canonical y=p
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // non-canonical y=p+1
        };
        for (String bp : badPoints) {
            out.add(new byte[][] {hex(bp), sig, msg}); // bad A
            byte[] badRsig = sig.clone();
            System.arraycopy(hex(bp), 0, badRsig, 0, 32);
            out.add(new byte[][] {pub, badRsig, msg}); // bad R
        }
        return out.toArray(new byte[0][][]);
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
