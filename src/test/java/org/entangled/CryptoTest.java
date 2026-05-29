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
}
