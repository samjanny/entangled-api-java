package org.entangled.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Publisher Identity Phrase (PIP) derivation, section 05.
 *
 * <p>The PIP is a 24-word public phrase derived from the raw 32-byte Ed25519
 * public key {@code K_publisher.pub} using the BIP-39 English wordlist and
 * checksum procedure:
 * <ol>
 *   <li>{@code entropy = K_publisher.pub} (32 bytes);</li>
 *   <li>{@code checksum = first_8_bits(SHA-256(entropy))};</li>
 *   <li>{@code bits = entropy || checksum} (264 bits);</li>
 *   <li>split into 24 groups of 11 bits;</li>
 *   <li>each group indexes the BIP-39 English wordlist;</li>
 *   <li>join the 24 words with single ASCII spaces.</li>
 * </ol>
 *
 * <p>This is an encoding of a public key, not a wallet seed. The wordlist is the
 * canonical BIP-39 English list, bundled as a resource.
 */
public final class Bip39Pip {

    private static final List<String> WORDLIST = loadWordlist();

    private Bip39Pip() {
    }

    /** Derive the 24-word PIP from a 32-byte Ed25519 public key. */
    public static String derive(byte[] publisherPub) {
        if (publisherPub.length != 32) {
            throw new IllegalArgumentException("K_publisher.pub must be 32 bytes");
        }
        byte[] checksum = Sha.sha256(publisherPub);
        // 256 entropy bits + 8 checksum bits = 264 bits = 24 * 11.
        byte[] bits = new byte[33];
        System.arraycopy(publisherPub, 0, bits, 0, 32);
        bits[32] = checksum[0];

        List<String> words = new ArrayList<>(24);
        for (int i = 0; i < 24; i++) {
            int index = elevenBitsAt(bits, i * 11);
            words.add(WORDLIST.get(index));
        }
        return String.join(" ", words);
    }

    /** Extract the 11-bit big-endian group starting at bit offset {@code bitOffset}. */
    private static int elevenBitsAt(byte[] bits, int bitOffset) {
        int value = 0;
        for (int i = 0; i < 11; i++) {
            int bitIndex = bitOffset + i;
            int b = (bits[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
            value = (value << 1) | b;
        }
        return value;
    }

    private static List<String> loadWordlist() {
        List<String> words = new ArrayList<>(2048);
        try (InputStream in = Bip39Pip.class.getResourceAsStream("bip39_english.txt")) {
            if (in == null) {
                throw new IllegalStateException("bip39_english.txt resource missing");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String w = line.strip();
                if (!w.isEmpty()) {
                    words.add(w);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (words.size() != 2048) {
            throw new IllegalStateException("BIP-39 wordlist must have 2048 words, got " + words.size());
        }
        return words;
    }
}
