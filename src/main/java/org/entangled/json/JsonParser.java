package org.entangled.json;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;

/**
 * Strict JSON parser for Entangled Stage 3 (section 10, section 04).
 *
 * <p>The parser operates on a Java String that the caller has already validated
 * as strict UTF-8 with no BOM (Stage 2). It enforces, at parse time, the
 * normative parser limits (nesting depth 16, string length 100 KiB, array
 * length 10000, object keys 256 per object) and rejects duplicate member names.
 * Any structural malformation is reported as {@code E_PARSE_JSON}.
 *
 * <p>Number tokens are accepted as valid JSON and classified against the
 * Entangled integer grammar (section 04); non-conforming numbers (floats,
 * exponents, leading zeros, signs, out-of-range) are not rejected here but are
 * flagged for Stage 5 ({@code E_SCHEMA_NON_INTEGER}). The {@code null} literal is
 * parsed and rejected later at Stage 5 ({@code E_SCHEMA_NULL_VALUE}).
 */
public final class JsonParser {

    /** Section 10 parser limits. */
    static final int MAX_DEPTH = 16;
    static final int MAX_STRING_LENGTH = 100 * 1024;
    static final int MAX_ARRAY_LENGTH = 10000;
    static final int MAX_OBJECT_KEYS = 256;

    private static final BigInteger MAX_INT63 = BigInteger.valueOf(Long.MAX_VALUE); // 2^63 - 1

    private final String s;
    private int pos;

    private JsonParser(String s) {
        this.s = s;
    }

    /** Parse the whole input as a single JSON value; trailing non-whitespace is an error. */
    public static JsonValue parse(String input) {
        JsonParser p = new JsonParser(input);
        p.skipWs();
        JsonValue v = p.parseValue(0);
        p.skipWs();
        if (p.pos != p.s.length()) {
            throw parseError();
        }
        return v;
    }

    private JsonValue parseValue(int depth) {
        if (pos >= s.length()) {
            throw parseError();
        }
        char c = s.charAt(pos);
        return switch (c) {
            case '{' -> parseObject(depth);
            case '[' -> parseArray(depth);
            case '"' -> new JsonValue.Str(parseString());
            case 't', 'f' -> parseBool();
            case 'n' -> parseNull();
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield parseNumber();
                }
                throw parseError();
            }
        };
    }

    private JsonValue parseObject(int depth) {
        enterDepth(depth);
        expect('{');
        Map<String, JsonValue> members = new LinkedHashMap<>();
        skipWs();
        if (peek() == '}') {
            pos++;
            return new JsonValue.Obj(members);
        }
        while (true) {
            skipWs();
            if (peek() != '"') {
                throw parseError();
            }
            String key = parseString();
            if (members.containsKey(key)) {
                // Section 04: duplicate member names are rejected during parsing,
                // not first-wins or last-wins. Reported as E_PARSE_DUPLICATE_KEY.
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("duplicate_key", key);
                throw new RejectException(DiagnosticCode.E_PARSE_DUPLICATE_KEY, details);
            }
            skipWs();
            expect(':');
            skipWs();
            JsonValue value = parseValue(depth + 1);
            members.put(key, value);
            if (members.size() > MAX_OBJECT_KEYS) {
                throw new RejectException(DiagnosticCode.E_PARSE_OBJECT_KEYS);
            }
            skipWs();
            char n = next();
            if (n == ',') {
                continue;
            }
            if (n == '}') {
                break;
            }
            throw parseError();
        }
        return new JsonValue.Obj(members);
    }

    private JsonValue parseArray(int depth) {
        enterDepth(depth);
        expect('[');
        List<JsonValue> elements = new ArrayList<>();
        skipWs();
        if (peek() == ']') {
            pos++;
            return new JsonValue.Arr(elements);
        }
        while (true) {
            skipWs();
            JsonValue value = parseValue(depth + 1);
            elements.add(value);
            if (elements.size() > MAX_ARRAY_LENGTH) {
                throw new RejectException(DiagnosticCode.E_PARSE_ARRAY_LENGTH);
            }
            skipWs();
            char n = next();
            if (n == ',') {
                continue;
            }
            if (n == ']') {
                break;
            }
            throw parseError();
        }
        return new JsonValue.Arr(elements);
    }

    private String parseString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= s.length()) {
                throw parseError();
            }
            char c = s.charAt(pos++);
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                if (pos >= s.length()) {
                    throw parseError();
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> sb.append(parseUnicodeEscape());
                    default -> throw parseError();
                }
            } else if (c < 0x20) {
                // Raw control characters are not permitted in JSON strings.
                throw parseError();
            } else {
                sb.append(c);
            }
            if (sb.length() > MAX_STRING_LENGTH) {
                throw new RejectException(DiagnosticCode.E_PARSE_STRING_LENGTH);
            }
        }
        return sb.toString();
    }

    /**
     * Parse a {@code \\uXXXX} escape, joining a valid high/low surrogate pair.
     *
     * <p>Section 04 forbids isolated surrogate escapes and malformed Unicode
     * escapes. An isolated or mispaired surrogate, or a non-hex escape, is a
     * malformed-Unicode condition; on the wire it surfaces at Stage 5 as
     * {@code E_SCHEMA_MALFORMED_UNICODE}. Since this is detected during string
     * tokenizing, the parser raises that Stage 5 code directly so the
     * first-failing-stage report is correct (the structural JSON is otherwise
     * well formed). A non-hex {@code \\u} body is structural JSON malformation
     * and is reported as {@code E_PARSE_JSON}.
     */
    private char[] parseUnicodeEscape() {
        char first = readHex4();
        if (Character.isHighSurrogate(first)) {
            if (pos + 1 < s.length() && s.charAt(pos) == '\\' && s.charAt(pos + 1) == 'u') {
                pos += 2;
                char second = readHex4();
                if (Character.isLowSurrogate(second)) {
                    return new char[] {first, second};
                }
            }
            throw new RejectException(DiagnosticCode.E_SCHEMA_MALFORMED_UNICODE);
        }
        if (Character.isLowSurrogate(first)) {
            // An unpaired low surrogate escape.
            throw new RejectException(DiagnosticCode.E_SCHEMA_MALFORMED_UNICODE);
        }
        return new char[] {first};
    }

    private char readHex4() {
        if (pos + 4 > s.length()) {
            throw parseError();
        }
        int v = 0;
        for (int i = 0; i < 4; i++) {
            char h = s.charAt(pos++);
            int d = Character.digit(h, 16);
            if (d < 0) {
                throw parseError();
            }
            v = (v << 4) | d;
        }
        return (char) v;
    }

    private JsonValue parseNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        // integer part
        if (pos >= s.length()) {
            throw parseError();
        }
        char d0 = s.charAt(pos);
        if (d0 == '0') {
            pos++;
        } else if (d0 >= '1' && d0 <= '9') {
            pos++;
            while (pos < s.length() && isDigit(s.charAt(pos))) {
                pos++;
            }
        } else {
            throw parseError();
        }
        // fraction
        if (pos < s.length() && s.charAt(pos) == '.') {
            pos++;
            if (pos >= s.length() || !isDigit(s.charAt(pos))) {
                throw parseError();
            }
            while (pos < s.length() && isDigit(s.charAt(pos))) {
                pos++;
            }
        }
        // exponent
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            pos++;
            if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                pos++;
            }
            if (pos >= s.length() || !isDigit(s.charAt(pos))) {
                throw parseError();
            }
            while (pos < s.length() && isDigit(s.charAt(pos))) {
                pos++;
            }
        }
        String raw = s.substring(start, pos);
        return classifyNumber(raw);
    }

    /** Classify a well-formed JSON number token against the Entangled integer grammar (section 04). */
    static JsonValue.Num classifyNumber(String raw) {
        boolean conforming = matchesIntegerGrammar(raw);
        BigInteger value = null;
        if (conforming) {
            value = new BigInteger(raw);
            if (value.compareTo(MAX_INT63) > 0) {
                // Lexically integer-shaped but out of the [0, 2^63 - 1] range:
                // not a conforming Entangled integer (section 04 range bound).
                conforming = false;
                value = null;
            }
        }
        return new JsonValue.Num(raw, conforming, value);
    }

    /** ABNF from section 04: integer = "0" / non-zero-digit *digit ; no sign, no leading zero. */
    private static boolean matchesIntegerGrammar(String raw) {
        if (raw.isEmpty()) {
            return false;
        }
        if (raw.equals("0")) {
            return true;
        }
        char first = raw.charAt(0);
        if (first < '1' || first > '9') {
            return false;
        }
        for (int i = 1; i < raw.length(); i++) {
            if (!isDigit(raw.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private JsonValue parseBool() {
        if (s.startsWith("true", pos)) {
            pos += 4;
            return new JsonValue.Bool(true);
        }
        if (s.startsWith("false", pos)) {
            pos += 5;
            return new JsonValue.Bool(false);
        }
        throw parseError();
    }

    private JsonValue parseNull() {
        if (s.startsWith("null", pos)) {
            pos += 4;
            return new JsonValue.Null();
        }
        throw parseError();
    }

    private void enterDepth(int depth) {
        // depth is the count of containers already open; the new container makes depth+1.
        if (depth + 1 > MAX_DEPTH) {
            throw new RejectException(DiagnosticCode.E_PARSE_NESTING_DEPTH);
        }
    }

    private void skipWs() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= s.length()) {
            throw parseError();
        }
        return s.charAt(pos);
    }

    private char next() {
        if (pos >= s.length()) {
            throw parseError();
        }
        return s.charAt(pos++);
    }

    private void expect(char c) {
        if (pos >= s.length() || s.charAt(pos) != c) {
            throw parseError();
        }
        pos++;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static RejectException parseError() {
        return new RejectException(DiagnosticCode.E_PARSE_JSON);
    }
}
