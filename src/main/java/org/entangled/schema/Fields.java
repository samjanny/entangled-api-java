package org.entangled.schema;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Set;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.crypto.Base64Url;
import org.entangled.json.JsonValue;

/**
 * Reusable Stage 5 field validators shared across document kinds (section 02,
 * section 03, section 06, section 07, section 08).
 *
 * <p>Each method enforces one normative field constraint and throws a
 * {@link RejectException} carrying the matching {@code E_SCHEMA_*} code. The
 * closed-schema discipline (every present key must be permitted, every required
 * key must be present, no {@code null}) is enforced by {@link Closed} together
 * with these primitives.
 *
 * <p>Numeric handling: a value flagged non-conforming-integer by the parser
 * (float, exponent, out of range) is {@code E_SCHEMA_NON_INTEGER}; a conforming
 * integer outside a field's declared range is {@code E_SCHEMA_FIELD_RANGE}
 * (section 11).
 */
public final class Fields {

    private Fields() {
    }

    // --- type extraction ---

    public static JsonValue.Obj obj(JsonValue v) {
        if (!(v instanceof JsonValue.Obj o)) {
            throw type();
        }
        return o;
    }

    public static JsonValue.Arr arr(JsonValue v) {
        if (!(v instanceof JsonValue.Arr a)) {
            throw type();
        }
        return a;
    }

    public static String str(JsonValue v) {
        if (!(v instanceof JsonValue.Str s)) {
            throw type();
        }
        return s.value();
    }

    public static boolean bool(JsonValue v) {
        if (!(v instanceof JsonValue.Bool b)) {
            throw type();
        }
        return b.value();
    }

    /** Require a conforming Entangled integer; non-integers are E_SCHEMA_NON_INTEGER. */
    public static BigInteger integer(JsonValue v) {
        if (!(v instanceof JsonValue.Num n)) {
            throw type();
        }
        if (!n.conformingInteger()) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_NON_INTEGER);
        }
        return n.value();
    }

    /** Require an integer in [min, max]; out-of-range is E_SCHEMA_FIELD_RANGE. */
    public static long integerInRange(JsonValue v, long min, long max) {
        BigInteger b = integer(v);
        if (b.compareTo(BigInteger.valueOf(min)) < 0 || b.compareTo(BigInteger.valueOf(max)) > 0) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_RANGE);
        }
        return b.longValueExact();
    }

    // --- string constraints ---

    public static int utf8Len(String s) {
        return s.getBytes(StandardCharsets.UTF_8).length;
    }

    /** Enforce a maximum UTF-8 byte length; over-cap is E_SCHEMA_FIELD_LENGTH. */
    public static void maxBytes(String s, int max) {
        if (utf8Len(s) > max) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
    }

    /** Reject control characters U+0000..U+001F and U+007F; optionally allow line feed. */
    public static void noControlChars(String s, boolean allowLineFeed) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' && allowLineFeed) {
                continue;
            }
            if (c < 0x20 || c == 0x7F) {
                throw syntax();
            }
        }
    }

    /** Require NFC for a user-visible text field (section 04); non-NFC is E_SCHEMA_FIELD_SYNTAX. */
    public static void requireNfc(String s) {
        if (!Normalizer.isNormalized(s, Normalizer.Form.NFC)) {
            throw syntax();
        }
    }

    /** Slug syntax: [a-z0-9_-], begins with [a-z0-9], 1..maxLen chars (section 03, section 07). */
    public static void slug(String s, int maxLen) {
        if (s.isEmpty() || s.length() > maxLen) {
            throw syntax();
        }
        char first = s.charAt(0);
        if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9'))) {
            throw syntax();
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) {
                throw syntax();
            }
        }
    }

    /** Base64url field of an exact decoded byte length; alphabet/length/canonical violations are E_SCHEMA_FIELD_SYNTAX. */
    public static byte[] base64url(String s, int expectedBytes) {
        try {
            return Base64Url.decode(s, expectedBytes);
        } catch (Base64Url.InvalidBase64Url e) {
            throw syntax();
        }
    }

    /**
     * RFC 3339 UTC timestamp in the only permitted form
     * {@code YYYY-MM-DDTHH:MM:SSZ}: integer seconds, no offset, no fraction, no
     * leap second. A lexically invalid timestamp is E_SCHEMA_FIELD_SYNTAX.
     */
    public static void rfc3339(String s) {
        if (!Rfc3339.isValid(s)) {
            throw syntax();
        }
    }

    /** A path field per section 02 path syntax; violations are E_SCHEMA_FIELD_SYNTAX. */
    public static void path(String s) {
        if (!Paths.isValidContentPath(s)) {
            throw syntax();
        }
    }

    /** Require the value to be one of an enumerated set; otherwise E_SCHEMA_ENUM_VIOLATION. */
    public static void inEnum(String value, Set<String> allowed) {
        if (!allowed.contains(value)) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
    }

    // --- shared throwers ---

    public static RejectException type() {
        return new RejectException(DiagnosticCode.E_SCHEMA_FIELD_TYPE);
    }

    public static RejectException syntax() {
        return new RejectException(DiagnosticCode.E_SCHEMA_FIELD_SYNTAX);
    }
}
