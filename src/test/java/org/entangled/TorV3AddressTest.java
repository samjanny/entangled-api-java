package org.entangled;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entangled.crypto.Base64Url;
import org.entangled.crypto.TorV3Address;
import org.junit.jupiter.api.Test;

/** Tor v3 onion address encode/decode exercises. */
class TorV3AddressTest {

    @Test
    void encodeDecodeRoundTrip() {
        byte[] pubkey = new byte[32];
        for (int i = 0; i < 32; i++) {
            pubkey[i] = (byte) (i * 7 + 1);
        }
        String address = TorV3Address.encodePublicKey(pubkey);
        assertEquals(56 + ".onion".length(), address.length());
        assertArrayEquals(pubkey, TorV3Address.decodePublicKey(address));
    }

    /**
     * Canonical fixture: the corpus origin key
     * {@code Gp8y4JM7Qlkn8JXkJAOW8s3MSkkQNGHGC1c7-AK6Wpo} derives to
     * {@code dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion}.
     * Matching this confirms the encoder is byte-identical to the corpus
     * generator and to the Rust reference.
     */
    @Test
    void corpusFixture() {
        byte[] pubkey = Base64Url.decode("Gp8y4JM7Qlkn8JXkJAOW8s3MSkkQNGHGC1c7-AK6Wpo", 32);
        assertEquals(
                "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion",
                TorV3Address.encodePublicKey(pubkey));
    }

    @Test
    void rejectsWrongPubkeyLength() {
        assertThrows(
                TorV3Address.InvalidOnionAddress.class,
                () -> TorV3Address.encodePublicKey(new byte[31]));
    }
}
