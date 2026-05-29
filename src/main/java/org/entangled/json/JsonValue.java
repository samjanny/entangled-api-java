package org.entangled.json;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * A parsed JSON value, restricted to the forms Entangled documents may contain.
 *
 * <p>Numbers retain their raw lexical token text so that the Entangled integer
 * grammar (section 04) can be enforced at schema validation (Stage 5) rather
 * than during parsing: a well-formed JSON number that is a float, has an
 * exponent, a leading zero, a sign, or is out of range is valid JSON but is
 * rejected as {@code E_SCHEMA_NON_INTEGER} at Stage 5. The parser therefore
 * accepts it lexically and defers the integer-grammar judgment.
 *
 * <p>The JSON literal {@code null} is likewise parsed (so the document is
 * structurally understood) and rejected at Stage 5 as {@code E_SCHEMA_NULL_VALUE}
 * (section 04, section 02).
 */
public sealed interface JsonValue
        permits JsonValue.Obj, JsonValue.Arr, JsonValue.Str, JsonValue.Num,
                JsonValue.Bool, JsonValue.Null {

    /** A JSON object. Member order is preserved as parsed; keys are unique (duplicates rejected at Stage 3). */
    record Obj(Map<String, JsonValue> members) implements JsonValue {
        public boolean has(String key) {
            return members.containsKey(key);
        }

        public JsonValue get(String key) {
            return members.get(key);
        }
    }

    /** A JSON array. */
    record Arr(List<JsonValue> elements) implements JsonValue {
    }

    /** A JSON string, already decoded from its wire escapes to a Java String. */
    record Str(String value) implements JsonValue {
    }

    /**
     * A JSON number. {@code raw} is the exact lexical token as it appeared on the
     * wire. {@code conformingInteger} is true only when {@code raw} matches the
     * Entangled integer grammar (section 04): {@code 0 | [1-9][0-9]*}, no sign,
     * no leading zero, no decimal point, no exponent, value in {@code [0, 2^63-1]}.
     * When true, {@code value} holds the decoded magnitude.
     */
    record Num(String raw, boolean conformingInteger, BigInteger value) implements JsonValue {
    }

    /** A JSON boolean. */
    record Bool(boolean value) implements JsonValue {
    }

    /** The JSON literal {@code null}; never valid in a conforming Entangled document. */
    record Null() implements JsonValue {
    }
}
