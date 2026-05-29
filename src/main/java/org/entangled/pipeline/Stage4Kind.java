package org.entangled.pipeline;

import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.json.JsonValue;

/**
 * Stage 4 document-kind discrimination (section 10, section 02):
 * <ul>
 *   <li>{@code spec_version}, {@code kind}, and {@code sig} are present and have
 *       the right primitive type (string), else {@code E_KIND_MISSING_FIELDS};</li>
 *   <li>{@code spec_version} is exactly {@code "1.0"}, else
 *       {@code E_KIND_SPEC_VERSION};</li>
 *   <li>{@code kind} is one of {@code manifest}/{@code content}/{@code transaction},
 *       else {@code E_KIND_UNKNOWN}.</li>
 * </ul>
 *
 * <p>This obtains the minimum needed to select a schema for Stage 5; full
 * closed-schema validation happens there.
 */
public final class Stage4Kind {

    /** The three document kinds. */
    public enum Kind { MANIFEST, CONTENT, TRANSACTION }

    private Stage4Kind() {
    }

    public static Kind discriminate(JsonValue root) {
        if (!(root instanceof JsonValue.Obj obj)) {
            // The top-level document must be a JSON object.
            throw new RejectException(DiagnosticCode.E_KIND_MISSING_FIELDS);
        }
        String specVersion = requireString(obj, "spec_version");
        requireString(obj, "kind");
        requireString(obj, "sig");

        if (!specVersion.equals("1.0")) {
            throw new RejectException(DiagnosticCode.E_KIND_SPEC_VERSION);
        }
        String kind = ((JsonValue.Str) obj.get("kind")).value();
        return switch (kind) {
            case "manifest" -> Kind.MANIFEST;
            case "content" -> Kind.CONTENT;
            case "transaction" -> Kind.TRANSACTION;
            default -> throw new RejectException(DiagnosticCode.E_KIND_UNKNOWN);
        };
    }

    private static String requireString(JsonValue.Obj obj, String key) {
        JsonValue v = obj.get(key);
        if (!(v instanceof JsonValue.Str s)) {
            // Absent or wrong primitive type.
            throw new RejectException(DiagnosticCode.E_KIND_MISSING_FIELDS);
        }
        return s.value();
    }
}
