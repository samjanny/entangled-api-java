package org.entangled.json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JSON Canonicalization Scheme (RFC 8785) over the restricted Entangled input
 * space (section 04).
 *
 * <p>Within Entangled's grammar JCS reduces to four rules:
 * <ul>
 *   <li>object members are emitted sorted by lexicographic comparison of the
 *       UTF-16 code units of their names (Java {@code String.compareTo} is
 *       exactly this comparison);</li>
 *   <li>strings use minimal escaping: only {@code "}, {@code \\}, and the
 *       control characters U+0000 through U+001F are escaped (with the short
 *       forms {@code \\b \\t \\n \\f \\r} where defined, otherwise
 *       {@code \\u00xx} with lowercase hex); every other character, including
 *       non-ASCII, is emitted as raw UTF-8;</li>
 *   <li>integers are serialized as their exact decimal digits with no leading
 *       zero, sign, decimal point, or exponent. This is the section 04 override
 *       of the RFC 8785 number profile: Entangled integers are never routed
 *       through a binary64 conversion, so values above 2^53 keep their exact
 *       digits;</li>
 *   <li>insignificant whitespace is eliminated.</li>
 * </ul>
 *
 * <p>Entangled conforming documents contain no {@code null} and no
 * floating-point numbers, so those branches are rejected at schema validation
 * before canonicalization is ever invoked. Canonicalizing such a value here is a
 * programming error and throws.
 */
public final class Jcs {

    private Jcs() {
    }

    /** Canonicalize a value to the RFC 8785 byte sequence (UTF-8). */
    public static byte[] canonicalize(JsonValue value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Canonicalize and return the UTF-8 string form (used by tests). */
    public static String canonicalString(JsonValue value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(JsonValue value, StringBuilder sb) {
        if (value instanceof JsonValue.Obj obj) {
            writeObject(obj, sb);
        } else if (value instanceof JsonValue.Arr arr) {
            writeArray(arr, sb);
        } else if (value instanceof JsonValue.Str str) {
            writeString(str.value(), sb);
        } else if (value instanceof JsonValue.Num num) {
            writeNumber(num, sb);
        } else if (value instanceof JsonValue.Bool b) {
            sb.append(b.value() ? "true" : "false");
        } else {
            // JsonValue.Null: not canonicalizable in a conforming document.
            throw new IllegalStateException("null literal cannot be canonicalized (section 04)");
        }
    }

    private static void writeObject(JsonValue.Obj obj, StringBuilder sb) {
        List<String> keys = new ArrayList<>(obj.members().keySet());
        // RFC 8785: sort by UTF-16 code-unit comparison of member names.
        keys.sort(Jcs::compareUtf16CodeUnits);
        sb.append('{');
        boolean first = true;
        for (String key : keys) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(key, sb);
            sb.append(':');
            write(obj.members().get(key), sb);
        }
        sb.append('}');
    }

    private static void writeArray(JsonValue.Arr arr, StringBuilder sb) {
        sb.append('[');
        boolean first = true;
        for (JsonValue element : arr.elements()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            write(element, sb);
        }
        sb.append(']');
    }

    private static void writeNumber(JsonValue.Num num, StringBuilder sb) {
        if (!num.conformingInteger()) {
            throw new IllegalStateException(
                    "non-integer number cannot be canonicalized (section 04): " + num.raw());
        }
        // Exact decimal digits of the magnitude; the conforming-integer flag
        // already guarantees no sign, leading zero, point, or exponent.
        sb.append(num.value().toString());
    }

    /**
     * Minimal JSON string escaping per RFC 8785. Java strings are UTF-16, which
     * is the code-unit basis RFC 8785 uses for both escaping decisions and key
     * ordering, so iterating by char is correct.
     */
    static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\t' -> sb.append("\\t");
                case '\n' -> sb.append("\\n");
                case '\f' -> sb.append("\\f");
                case '\r' -> sb.append("\\r");
                default -> {
                    if (c < 0x20) {
                        sb.append("\\u");
                        sb.append(hex4(c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static String hex4(int c) {
        String h = Integer.toHexString(c);
        return "0000".substring(h.length()) + h;
    }

    private static int compareUtf16CodeUnits(String a, String b) {
        // String.compareTo compares by UTF-16 code units, matching RFC 8785.
        return a.compareTo(b);
    }
}
