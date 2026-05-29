package org.entangled.schema;

import java.util.Set;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.json.JsonValue;

/**
 * Closed-schema discipline for a single object level (section 02).
 *
 * <p>Given the permitted key set (required plus optional) and the required key
 * set for an object, this verifies:
 * <ul>
 *   <li>every present key is permitted, else {@code E_SCHEMA_UNKNOWN_FIELD};</li>
 *   <li>every required key is present, else {@code E_SCHEMA_REQUIRED_FIELD};</li>
 *   <li>no permitted present value is the JSON {@code null} literal, else
 *       {@code E_SCHEMA_NULL_VALUE} (section 04 forbids {@code null} anywhere).</li>
 * </ul>
 *
 * <p>Order: unknown-field detection runs first (a stray key is a closed-schema
 * breach regardless of its value), then required-presence, then the null check
 * on the permitted values at this level. Nested objects run their own
 * {@code Closed} check, so a {@code null} at any depth is caught at its level.
 */
public final class Closed {

    private Closed() {
    }

    public static void check(JsonValue.Obj obj, Set<String> permitted, Set<String> required) {
        for (String key : obj.members().keySet()) {
            if (!permitted.contains(key)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_UNKNOWN_FIELD);
            }
        }
        for (String key : required) {
            if (!obj.members().containsKey(key)) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_REQUIRED_FIELD);
            }
        }
        for (JsonValue value : obj.members().values()) {
            if (value instanceof JsonValue.Null) {
                throw new RejectException(DiagnosticCode.E_SCHEMA_NULL_VALUE);
            }
        }
    }

    /** Convenience: a value that must not be the null literal at this position. */
    public static void notNull(JsonValue value) {
        if (value instanceof JsonValue.Null) {
            throw new RejectException(DiagnosticCode.E_SCHEMA_NULL_VALUE);
        }
    }
}
