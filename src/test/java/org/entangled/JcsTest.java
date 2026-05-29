package org.entangled;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import org.entangled.json.Jcs;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.junit.jupiter.api.Test;

/**
 * JCS canonicalization, anchored on the section 04 test vector and its exact
 * 72-byte expected output.
 */
class JcsTest {

    @Test
    void section04TestVector() {
        String input = "{\n  \"kind\": \"content\",\n  \"spec_version\": \"1.0\","
                + "\n  \"value\": \"hello world\",\n  \"count\": 42\n}";
        String expected = "{\"count\":42,\"kind\":\"content\",\"spec_version\":\"1.0\",\"value\":\"hello world\"}";

        JsonValue parsed = JsonParser.parse(input);
        String canonical = Jcs.canonicalString(parsed);

        assertEquals(expected, canonical);

        byte[] expectedBytes = {
            0x7B, 0x22, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x22, 0x3A, 0x34, 0x32, 0x2C, 0x22, 0x6B, 0x69, 0x6E,
            0x64, 0x22, 0x3A, 0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x22, 0x2C, 0x22, 0x73, 0x70,
            0x65, 0x63, 0x5F, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x22, 0x31, 0x2E, 0x30,
            0x22, 0x2C, 0x22, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x22, 0x3A, 0x22, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x22, 0x7D
        };
        assertEquals(72, expectedBytes.length);
        assertArrayEquals(expectedBytes, Jcs.canonicalize(parsed));
    }

    @Test
    void largeIntegerKeepsExactDigits() {
        // Above 2^53, an Entangled integer keeps its exact decimal digits and is
        // not routed through binary64 (section 04 integer serialization override).
        String input = "{\"seq\":9007199254740993}";
        JsonValue parsed = JsonParser.parse(input);
        assertEquals("{\"seq\":9007199254740993}", Jcs.canonicalString(parsed));
    }

    @Test
    void minimalStringEscaping() {
        // Only ", \\, and control chars are escaped; non-ASCII is raw UTF-8.
        String input = "{\"k\":\"a\\\"b\\\\c\\nd\\u0001e\"}";
        JsonValue parsed = JsonParser.parse(input);
        String canonical = Jcs.canonicalString(parsed);
        assertEquals("{\"k\":\"a\\\"b\\\\c\\nd\\u0001e\"}", canonical);
    }

    @Test
    void nonAsciiEmittedRaw() {
        // A precomposed e-acute (U+00E9) is emitted as its raw UTF-8 bytes
        // (0xC3 0xA9), not escaped. The Java source stays ASCII by writing the
        // character with a \\u00e9 escape (a Java char literal, not a JSON escape).
        String input = "{\"k\":\"caf\u00e9\"}";
        JsonValue parsed = JsonParser.parse(input);
        byte[] canonical = Jcs.canonicalize(parsed);
        byte[] expected = ("{\"k\":\"caf\u00e9\"}").getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, canonical);
        // Confirm the e-acute is the two raw UTF-8 bytes, not a \\u escape.
        assertEquals((byte) 0xC3, canonical[canonical.length - 4]);
        assertEquals((byte) 0xA9, canonical[canonical.length - 3]);
    }
}
