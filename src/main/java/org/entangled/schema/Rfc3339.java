package org.entangled.schema;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * The single RFC 3339 timestamp form Entangled permits (section 02, section 06,
 * section 08): {@code YYYY-MM-DDTHH:MM:SSZ}.
 *
 * <p>Integer seconds only; no numeric UTC offset, no fractional seconds, no
 * leap-second values, uppercase {@code T} and {@code Z}. The string is validated
 * both lexically (exact shape) and as a real calendar instant.
 */
public final class Rfc3339 {

    // Strict shape: 4-2-2 'T' 2:2:2 'Z'. Lexical gate before calendar parsing.
    private static final java.util.regex.Pattern SHAPE =
            java.util.regex.Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z");

    private static final DateTimeFormatter PARSER =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private Rfc3339() {
    }

    /** True iff {@code s} is exactly the permitted form and a real instant. */
    public static boolean isValid(String s) {
        if (!SHAPE.matcher(s).matches()) {
            return false;
        }
        // A "60" seconds field is a leap second and is forbidden; ResolverStyle
        // STRICT rejects it along with impossible dates.
        try {
            parse(s);
            return true;
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /** Parse a validated timestamp to an instant in epoch seconds (UTC). */
    public static long epochSeconds(String s) {
        return parse(s).toEpochSecond();
    }

    private static OffsetDateTime parse(String s) {
        return OffsetDateTime.parse(s,
                PARSER.withResolverStyle(java.time.format.ResolverStyle.STRICT));
    }
}
