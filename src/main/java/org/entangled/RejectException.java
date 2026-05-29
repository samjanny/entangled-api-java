package org.entangled;

import java.util.Map;

/**
 * Internal control-flow exception used by the validation pipeline to abort at
 * the first failing stage (section 10 error precedence). It carries the single
 * {@link Diagnostic} that becomes the rejection verdict.
 *
 * <p>This is never surfaced to callers; the pipeline catches it and converts it
 * to a {@link Verdict#reject}.
 */
public final class RejectException extends RuntimeException {

    private final transient Diagnostic diagnostic;

    public RejectException(Diagnostic diagnostic) {
        super(diagnostic.code().name());
        this.diagnostic = diagnostic;
    }

    public RejectException(DiagnosticCode code) {
        this(Diagnostic.of(code));
    }

    public RejectException(DiagnosticCode code, Map<String, Object> details) {
        this(Diagnostic.of(code, details));
    }

    public Diagnostic diagnostic() {
        return diagnostic;
    }
}
