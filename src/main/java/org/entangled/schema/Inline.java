package org.entangled.schema;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.json.JsonValue;

/**
 * Inline content arrays and the link-target schema, section 03.
 *
 * <p>An inline array holds {@code text} and {@code link} elements; both carry
 * {@code kind}, {@code value} (a UTF-8 visible string), and {@code marks} (zero
 * or more of bold/italic/code/strikethrough, no duplicates). A {@code link}
 * element additionally carries {@code target}. Inline {@code value} strings are
 * NFC, contain no control characters, and contain no line feed.
 */
public final class Inline {

    private static final Set<String> MARKS = Set.of("bold", "italic", "code", "strikethrough");
    private static final Set<String> TARGET_KINDS = Set.of("same_site", "entangled", "carrier", "citation");

    private static final int MAX_ELEMENTS = 256;
    private static final int MAX_VALUE_BYTES = 2048;

    private Inline() {
    }

    /**
     * Validate an inline content array and return the total UTF-8 byte count of
     * its {@code value} strings (callers enforce the per-block aggregate cap).
     *
     * @param allowLinks whether inline {@code link} elements are permitted here
     *                   ({@code link.label} and {@code submit_form.label} forbid them)
     * @param requireNonEmpty whether the array must contain at least one element
     */
    public static int validate(JsonValue v, boolean allowLinks, boolean requireNonEmpty) {
        List<JsonValue> elements = Fields.arr(v).elements();
        if (requireNonEmpty && elements.isEmpty()) {
            // An empty mandatory inline array is a missing required element
            // (AMB-13, rc.31): E_SCHEMA_REQUIRED_FIELD, not a length/syntax code.
            throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
        }
        if (elements.size() > MAX_ELEMENTS) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        int totalBytes = 0;
        for (JsonValue elemValue : elements) {
            totalBytes += validateElement(elemValue, allowLinks);
        }
        return totalBytes;
    }

    private static int validateElement(JsonValue elemValue, boolean allowLinks) {
        JsonValue.Obj e = Fields.obj(elemValue);
        String kind = Fields.str(require(e, "kind"));
        return switch (kind) {
            case "text" -> {
                Closed.check(e, Set.of("kind", "value", "marks"), Set.of("kind", "value", "marks"));
                String value = validateValue(Fields.str(e.get("value")));
                validateMarks(e.get("marks"));
                yield Fields.utf8Len(value);
            }
            case "link" -> {
                if (!allowLinks) {
                    // A link element where only text is permitted (link.label,
                    // submit_form.label) is a kind appearing where it is not
                    // permitted (AMB-14, rc.31): E_SCHEMA_BLOCK_NOT_PERMITTED, not
                    // E_SCHEMA_ENUM_VIOLATION.
                    throw new RejectException(DiagnosticCode.E_SCHEMA_BLOCK_NOT_PERMITTED);
                }
                Closed.check(e, Set.of("kind", "value", "marks", "target"),
                        Set.of("kind", "value", "marks", "target"));
                String value = validateValue(Fields.str(e.get("value")));
                validateMarks(e.get("marks"));
                validateTarget(e.get("target"));
                yield Fields.utf8Len(value);
            }
            default -> throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        };
    }

    private static String validateValue(String value) {
        if (Fields.utf8Len(value) > MAX_VALUE_BYTES) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_FIELD_LENGTH);
        }
        // Inline value: no control chars, no line feed (section 03), NFC (section 04).
        Fields.noControlChars(value, false);
        Fields.requireNfc(value);
        return value;
    }

    private static void validateMarks(JsonValue marksValue) {
        List<JsonValue> marks = Fields.arr(marksValue).elements();
        Set<String> seen = new HashSet<>();
        for (JsonValue m : marks) {
            String mark = Fields.str(m);
            if (!MARKS.contains(mark)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
            }
            if (!seen.add(mark)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_DUPLICATE_ENTRY);
            }
        }
    }

    /** Validate a link target object (shared by inline links and link blocks). */
    public static void validateTarget(JsonValue targetValue) {
        JsonValue.Obj t = Fields.obj(targetValue);
        String kind = Fields.str(require(t, "kind"));
        switch (kind) {
            case "same_site" -> {
                Closed.check(t, Set.of("kind", "path"), Set.of("kind", "path"));
                Fields.path(Fields.str(t.get("path")));
            }
            case "entangled" -> {
                Closed.check(t, Set.of("kind", "carrier", "address", "path", "expected_publisher_pubkey"),
                        Set.of("kind", "carrier", "address", "path"));
                requireTorV3(Fields.str(t.get("carrier")));
                // address: a 56-char onion + .onion; validated structurally here.
                validateOnionAddress(Fields.str(t.get("address")));
                Fields.path(Fields.str(t.get("path")));
                if (t.has("expected_publisher_pubkey")) {
                    Fields.base64url(Fields.str(t.get("expected_publisher_pubkey")), 32);
                }
            }
            case "carrier" -> {
                Closed.check(t, Set.of("kind", "carrier", "url"), Set.of("kind", "carrier", "url"));
                requireTorV3(Fields.str(t.get("carrier")));
                validateCarrierUrl(Fields.str(t.get("url")));
            }
            case "citation" -> {
                Closed.check(t, Set.of("kind", "url"), Set.of("kind", "url"));
                validateCitationUrl(Fields.str(t.get("url")));
            }
            default -> throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
    }

    private static void requireTorV3(String carrier) {
        // Section 03: a non-"tor-v3" carrier on a link target is rejected like a
        // non-tor-v3 manifest carrier; the value is a syntactically valid string
        // outside the permitted set, hence an enum violation.
        if (!carrier.equals("tor-v3")) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_ENUM_VIOLATION);
        }
    }

    private static void validateOnionAddress(String address) {
        if (!address.endsWith(".onion")) {
            throw Fields.syntax();
        }
        String body = address.substring(0, address.length() - ".onion".length());
        if (body.length() != 56) {
            throw Fields.syntax();
        }
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
            if (!ok) {
                throw Fields.syntax();
            }
        }
    }

    private static void validateCarrierUrl(String url) {
        if (!url.startsWith("http://") || Fields.utf8Len(url) > 1024) {
            throw Fields.syntax();
        }
        rfc3986Chars(url);
        // section 03:584: the URL host MUST be a valid carrier address for the
        // declared carrier; for tor-v3, a 56-char onion address plus ".onion".
        validateOnionAddress(authorityHost(url.substring("http://".length())));
    }

    /**
     * Extract the host from the authority of a URL slice that follows the
     * scheme prefix: stop at the first {@code /}, {@code ?}, or {@code #};
     * strip optional userinfo before {@code @}; strip an optional {@code :port}
     * suffix. Returns "" when no host is present, which
     * {@link #validateOnionAddress} then rejects.
     */
    private static String authorityHost(String afterScheme) {
        int end = afterScheme.length();
        for (int i = 0; i < afterScheme.length(); i++) {
            char c = afterScheme.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                end = i;
                break;
            }
        }
        String authority = afterScheme.substring(0, end);
        int at = authority.lastIndexOf('@');
        String hostPort = (at >= 0) ? authority.substring(at + 1) : authority;
        int colon = hostPort.lastIndexOf(':');
        return (colon >= 0) ? hostPort.substring(0, colon) : hostPort;
    }

    private static void validateCitationUrl(String url) {
        if (!url.startsWith("https://") || Fields.utf8Len(url) > 1024) {
            throw Fields.syntax();
        }
        rfc3986Chars(url);
    }

    /**
     * RFC 3986 URL character validation (section 03:586 carrier, section 03:616
     * citation): a url may contain only unreserved / reserved characters and
     * complete percent-encoded triplets. Any other byte (control characters, the
     * space 0x20, characters such as {@code <} {@code >}, and any byte
     * {@code >= 0x80}) or a malformed percent-triplet is E_SCHEMA_FIELD_SYNTAX.
     * Mirrors the Rust reference (validate_url_common). This subsumes the prior
     * control-character-only check.
     */
    private static void rfc3986Chars(String url) {
        byte[] bytes = url.getBytes(StandardCharsets.UTF_8);
        int i = 0;
        while (i < bytes.length) {
            int b = bytes[i] & 0xFF;
            if (b == '%') {
                if (i + 2 >= bytes.length || !isHexByte(bytes[i + 1]) || !isHexByte(bytes[i + 2])) {
                    throw Fields.syntax();
                }
                i += 3;
                continue;
            }
            if (!isRfc3986UnencodedByte(b)) {
                throw Fields.syntax();
            }
            i++;
        }
    }

    private static boolean isHexByte(byte b) {
        int c = b & 0xFF;
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    /** RFC 3986 unreserved + gen-delims + sub-delims: the bytes legal unencoded. */
    private static boolean isRfc3986UnencodedByte(int b) {
        return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
                || b == '-' || b == '.' || b == '_' || b == '~'
                || b == ':' || b == '/' || b == '?' || b == '#' || b == '[' || b == ']' || b == '@'
                || b == '!' || b == '$' || b == '&' || b == '\'' || b == '(' || b == ')' || b == '*'
                || b == '+' || b == ',' || b == ';' || b == '=';
    }

    static JsonValue require(JsonValue.Obj obj, String key) {
        JsonValue v = obj.get(key);
        if (v == null) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
        }
        return v;
    }
}
