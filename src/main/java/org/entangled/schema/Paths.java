package org.entangled.schema;

/**
 * Content/transaction/image path syntax, section 02.
 *
 * <p>A valid path:
 * <ul>
 *   <li>begins with {@code /};</li>
 *   <li>contains only ASCII characters in {@code [A-Za-z0-9._~/-]};</li>
 *   <li>contains no consecutive {@code /};</li>
 *   <li>contains no {@code .} or {@code ..} path segment;</li>
 *   <li>contains no query string, fragment, scheme, or host (these are excluded
 *       by the character class plus the leading-slash rule);</li>
 *   <li>is not {@code /manifest.json} or {@code /content_index.json} (reserved);</li>
 *   <li>does not exceed 256 ASCII characters.</li>
 * </ul>
 */
public final class Paths {

    public static final String RESERVED_MANIFEST = "/manifest.json";
    public static final String RESERVED_CONTENT_INDEX = "/content_index.json";

    private Paths() {
    }

    public static boolean isValidContentPath(String p) {
        if (p.isEmpty() || p.charAt(0) != '/' || p.length() > 256) {
            return false;
        }
        if (p.equals(RESERVED_MANIFEST) || p.equals(RESERVED_CONTENT_INDEX)) {
            return false;
        }
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '~' || c == '/' || c == '-';
            if (!ok) {
                return false;
            }
        }
        // No consecutive slashes.
        if (p.contains("//")) {
            return false;
        }
        // No "." or ".." segments. Split on '/'; the leading slash yields an
        // empty first segment, which is fine (and any other empty segment would
        // be a "//" already rejected above).
        String[] segments = p.split("/", -1);
        for (String seg : segments) {
            if (seg.equals(".") || seg.equals("..")) {
                return false;
            }
        }
        return true;
    }
}
