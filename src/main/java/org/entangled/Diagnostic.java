package org.entangled;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A single diagnostic: a normative {@link DiagnosticCode} plus an optional
 * structured {@code details} map (section 11 "Structured diagnostic format").
 *
 * <p>The {@code details} map mirrors the structured {@code details} object the
 * spec defines per code (for example {@code component}/{@code declared_bytes}/
 * {@code budget_bytes} for {@code E_SUBMIT_BUDGET}). Conformance vectors that
 * carry {@code diagnostic_details} are matched against this map exactly.
 */
public final class Diagnostic {

    private final DiagnosticCode code;
    private final Map<String, Object> details;

    private Diagnostic(DiagnosticCode code, Map<String, Object> details) {
        this.code = code;
        this.details = Collections.unmodifiableMap(details);
    }

    public static Diagnostic of(DiagnosticCode code) {
        return new Diagnostic(code, new LinkedHashMap<>());
    }

    public static Diagnostic of(DiagnosticCode code, Map<String, Object> details) {
        return new Diagnostic(code, new LinkedHashMap<>(details));
    }

    public DiagnosticCode code() {
        return code;
    }

    public Map<String, Object> details() {
        return details;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Diagnostic other)) {
            return false;
        }
        return code == other.code && details.equals(other.details);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, details);
    }

    @Override
    public String toString() {
        return details.isEmpty() ? code.name() : code.name() + " " + details;
    }
}
