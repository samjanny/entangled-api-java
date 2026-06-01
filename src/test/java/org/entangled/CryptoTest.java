package org.entangled;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.entangled.crypto.Base64Url;
import org.entangled.crypto.Bip39Pip;
import org.entangled.crypto.Ed25519;
import org.entangled.crypto.TorV3Address;
import org.entangled.json.Jcs;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.junit.jupiter.api.Test;

/**
 * Crypto primitives, anchored on the fixture material in corpus/keys.json and on
 * a real corpus signature (vector 001), so the whole base64url + JCS + Ed25519
 * stack is exercised against known-good bytes derived from the spec corpus.
 */
class CryptoTest {

    private static final String PUBLISHER_PUB_B64U = "moyzpl3i5hUIcMNRLPMxir4sdmSO3gO79gLUtvYDWxc";
    private static final String PUBLISHER_PIP =
            "once grain trumpet rookie common appear canyon blur eye guide small betray "
            + "tissue depth mutual swift admit text level practice hunt accuse hobby unusual";
    private static final String ORIGIN_PUB_B64U = "Gp8y4JM7Qlkn8JXkJAOW8s3MSkkQNGHGC1c7-AK6Wpo";
    private static final String ORIGIN_ONION =
            "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";
    private static final String ORIGIN2_PUB_B64U = "Ko4-lXCoSgOUc_2Dt2Bi9NcyVyUN3GYgEKMJkgPQtb8";
    private static final String ORIGIN2_ONION =
            "fkhd5flqvbfahfdt7wb3oydc6tltevzfbxogmiaqumezea6qww7rjhid.onion";

    @Test
    void base64urlStrictDecode() {
        // A 43-char base64url decodes to 32 bytes.
        byte[] pub = Base64Url.decode(PUBLISHER_PUB_B64U, 32);
        assertEquals(32, pub.length);
        // Wrong declared length is rejected.
        assertThrows(Base64Url.InvalidBase64Url.class, () -> Base64Url.decode(PUBLISHER_PUB_B64U, 64));
        // Padding, standard alphabet, and whitespace are rejected.
        assertThrows(Base64Url.InvalidBase64Url.class, () -> Base64Url.decode("AAAA====", 4));
        assertThrows(Base64Url.InvalidBase64Url.class, () -> Base64Url.decode("ab+/" + "AAAA", 6));
        assertThrows(Base64Url.InvalidBase64Url.class, () -> Base64Url.decode("AA AA", 3));
    }

    @Test
    void pipMatchesKeysJson() {
        byte[] pub = Base64Url.decode(PUBLISHER_PUB_B64U, 32);
        assertEquals(PUBLISHER_PIP, Bip39Pip.derive(pub));
    }

    @Test
    void onionAddressesDecodeToTheirPubkeys() {
        assertArrayEquals(Base64Url.decode(ORIGIN_PUB_B64U, 32), TorV3Address.decodePublicKey(ORIGIN_ONION));
        assertArrayEquals(Base64Url.decode(ORIGIN2_PUB_B64U, 32), TorV3Address.decodePublicKey(ORIGIN2_ONION));
    }

    @Test
    void onionAddressChecksumIsChecked() {
        // Flip one character: checksum (or structure) must fail.
        String tampered = "e" + ORIGIN_ONION.substring(1);
        assertThrows(TorV3Address.InvalidOnionAddress.class, () -> TorV3Address.decodePublicKey(tampered));
    }

    @Test
    void verifiesRealManifestSignatureVector001() {
        byte[] body = CorpusFiles.vectorInput("001-manifest-valid-minimal");
        String text = new String(body, StandardCharsets.UTF_8);
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(text);

        String sigB64u = ((JsonValue.Str) doc.get("sig")).value();
        byte[] sig = Base64Url.decode(sigB64u, 64);
        byte[] pub = Base64Url.decode(((JsonValue.Str) doc.get("publisher_pubkey")).value(), 32);

        // signature_input = "ENTANGLED-v1 manifest" || 0x00 || JCS(payload minus sig)
        Map<String, JsonValue> members = new LinkedHashMap<>(doc.members());
        members.remove("sig");
        byte[] jcs = Jcs.canonicalize(new JsonValue.Obj(members));
        byte[] input = signatureInput("ENTANGLED-v1 manifest", jcs);

        assertTrue(Ed25519.verify(pub, sig, input), "vector 001 manifest signature must verify");

        // A one-bit flip in the message must fail.
        byte[] tampered = input.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(Ed25519.verify(pub, sig, tampered));
    }

    private static byte[] signatureInput(String context, byte[] jcs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] ctx = context.getBytes(StandardCharsets.US_ASCII);
        out.writeBytes(ctx);
        out.write(0x00);
        out.writeBytes(jcs);
        return out.toByteArray();
    }

    /**
     * Pin the strict verification profile (section 05) against the 15
     * ed25519-speccheck vectors (Chalkias-Garillot-Nikolaenko, "Taming the Many
     * EdDSAs"). The expected column is ed25519-dalek verify_strict, which section
     * 05 names as the reference: reject all except index 7. This is the guard
     * that the JDK-plus-small-order-table verifier stays equivalent to
     * verify_strict, in particular the small-order rejections (indices 1, 3, 5,
     * 13) the JDK alone would accept and the cofactorless rejections (indices 6,
     * 8) that distinguish the required cofactorless equation from a cofactored one.
     */
    @Test
    void strictProfileMatchesSpeccheckVectors() {
        Vec[] vectors = {
            v(false, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
              "2a66241a42a9ee12994d8068dcf1bb7dfc6637b45450acd43711f637fa5080fc"),
            v(false, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
              "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6"),
            v(false, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
              "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
              "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            v(false, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
              "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
              "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            v(false, "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa182ef1a5b928da07fec769cc8a12db6bcf70dab3f3227fa315e9d5e3e01a3405",
              "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41"),
            v(false, "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
              "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab"),
            v(false, "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
              "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
              "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            v(true, "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
              "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
              "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"),
            v(false, "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
              "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
              "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c"),
            v(false, "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
              "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
              "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            v(false, "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
              "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
              "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40"),
            v(false, "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
              "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f454d370c8d9fc323a41450f8d513eafeb5b0697390c1e505a0d4ddc71f566607",
              "fdaebc429f4a735932a160da1301080c13280eea8bc280d1b392c6b9e6ba3a5a"),
            v(false, "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
              "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f084d5b99c2a9463d9c8bd5026916996984eeec87ddf1d3be329006ace1b37b09",
              "84b698d39be126ff55fe45079e6c8bf64a0d7db6994560b4e96b7021eb39c1a1"),
            v(false, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
              "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b"),
            v(false, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
              "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
              "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f"),
        };
        for (int i = 0; i < vectors.length; i++) {
            Vec vec = vectors[i];
            boolean got = Ed25519.verify(hex(vec.pub()), hex(vec.sig()), hex(vec.msg()));
            assertEquals(vec.expected(), got, "speccheck vector " + i);
        }
    }

    /**
     * Section 05:154 / 05:168: a non-canonical compressed encoding of the public
     * key {@code A} or the signature component {@code R} ({@code y >= p} once the
     * sign bit is masked off) MUST be rejected. The JDK's {@code SunEC} provider
     * does NOT reject these; it reduces {@code y} modulo {@code p} (ZIP-215 style)
     * and verifies against the reduced point. {@code Ed25519.verify} therefore has
     * to reject the non-canonical encoding itself, before delegating, or a
     * non-canonical encoding of the genuine signing key, presented with a
     * signature valid under the reduced point, would be wrongly accepted.
     *
     * <p>The test isolates the canonical-encoding guard from the other strict
     * checks. It uses {@code y = p} ({@code ed..7f}) and {@code y = p + 1}
     * ({@code ee..7f}) -- 32-byte encodings the field accepts but that lie at and
     * just above the field prime. Around each non-canonical value it places the
     * genuine, canonical, non-small-order counterpart from corpus vector 001 (a
     * real signature when probing a non-canonical {@code A}, a real public key
     * when probing a non-canonical {@code R}), so the small-order table and the
     * {@code S < L} / equation checks cannot be what rejects -- only the new
     * canonical-encoding guard can. SunEC's acceptance of the non-canonical key
     * encodings is asserted first, so the test documents the exact gap the guard
     * closes (and fails loudly if a future JDK changes that behaviour).
     */
    @Test
    void rejectsNonCanonicalPublicKeyAndREncodings() {
        byte[] yEqualsP = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        byte[] yEqualsPplus1 = hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

        // Precondition: SunEC accepts these non-canonical key encodings, so the
        // section 05:154 rejection genuinely depends on this layer's own guard.
        assertTrue(sunEcAcceptsPublicKey(yEqualsP),
                "precondition: SunEC accepts y = p (this is the gap section 05:154 closes)");
        assertTrue(sunEcAcceptsPublicKey(yEqualsPplus1),
                "precondition: SunEC accepts y = p+1");

        // The canonical-encoding check itself rejects them (regression guard on
        // the logic: a canonical, non-small-order key passes, y >= p does not).
        assertTrue(Ed25519.isStrictProfilePubkey(Base64Url.decode(PUBLISHER_PUB_B64U, 32)),
                "genuine canonical non-small-order key must pass the strict profile");
        assertFalse(Ed25519.isStrictProfilePubkey(yEqualsP), "y = p is non-canonical");
        assertFalse(Ed25519.isStrictProfilePubkey(yEqualsPplus1), "y = p+1 is non-canonical");

        // Genuine, canonical, non-small-order signature and key from vector 001.
        byte[] body = CorpusFiles.vectorInput("001-manifest-valid-minimal");
        JsonValue.Obj doc = (JsonValue.Obj) JsonParser.parse(new String(body, StandardCharsets.UTF_8));
        byte[] genuineSig = Base64Url.decode(((JsonValue.Str) doc.get("sig")).value(), 64);
        byte[] genuinePub = Base64Url.decode(((JsonValue.Str) doc.get("publisher_pubkey")).value(), 32);
        byte[] msg = "entangled non-canonical encoding test".getBytes(StandardCharsets.UTF_8);

        // Non-canonical A, with the genuine canonical R from vector 001: only the
        // canonical(A) guard can reject. (Pre-fix, SunEC would reduce A mod p.)
        assertFalse(Ed25519.verify(yEqualsP, genuineSig, msg), "non-canonical A (y = p) must be rejected");
        assertFalse(Ed25519.verify(yEqualsPplus1, genuineSig, msg), "non-canonical A (y = p+1) must be rejected");

        // Non-canonical R (first 32 bytes of the signature), with the genuine
        // canonical S from vector 001 and a canonical A: only canonical(R) rejects.
        byte[] sigNonCanonR = genuineSig.clone();
        System.arraycopy(yEqualsP, 0, sigNonCanonR, 0, 32);
        assertFalse(Ed25519.verify(genuinePub, sigNonCanonR, msg), "non-canonical R (y = p) must be rejected");
        byte[] sigNonCanonR2 = genuineSig.clone();
        System.arraycopy(yEqualsPplus1, 0, sigNonCanonR2, 0, 32);
        assertFalse(Ed25519.verify(genuinePub, sigNonCanonR2, msg), "non-canonical R (y = p+1) must be rejected");
    }

    /** True iff SunEC's KeyFactory accepts the 32-byte raw encoding as an Ed25519 public key. */
    private static boolean sunEcAcceptsPublicKey(byte[] rawKey) {
        byte[] prefix = hex("302a300506032b6570032100");
        byte[] x509 = new byte[prefix.length + rawKey.length];
        System.arraycopy(prefix, 0, x509, 0, prefix.length);
        System.arraycopy(rawKey, 0, x509, prefix.length, rawKey.length);
        try {
            java.security.KeyFactory.getInstance("Ed25519")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(x509));
            return true;
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    private static Vec v(boolean expected, String pub, String sig, String msg) {
        return new Vec(expected, pub, sig, msg);
    }

    private record Vec(boolean expected, String pub, String sig, String msg) {
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
