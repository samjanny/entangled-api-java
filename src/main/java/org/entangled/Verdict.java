package org.entangled;

import java.util.Map;

/**
 * The outcome of running a document (or scenario) through the validation
 * pipeline: either {@code accept}, or {@code reject} with a single
 * {@link Diagnostic}.
 *
 * <p>Per section 10 error precedence, a rejection reports the first failing
 * stage; this type therefore carries exactly one diagnostic.
 */
public final class Verdict {

    private final boolean accepted;
    private final Diagnostic diagnostic;

    private Verdict(boolean accepted, Diagnostic diagnostic) {
        this.accepted = accepted;
        this.diagnostic = diagnostic;
    }

    public static Verdict accept() {
        return new Verdict(true, null);
    }

    public static Verdict reject(Diagnostic diagnostic) {
        return new Verdict(false, diagnostic);
    }

    public static Verdict reject(DiagnosticCode code) {
        return reject(Diagnostic.of(code));
    }

    public static Verdict reject(DiagnosticCode code, Map<String, Object> details) {
        return reject(Diagnostic.of(code, details));
    }

    public boolean isAccepted() {
        return accepted;
    }

    public Diagnostic diagnostic() {
        return diagnostic;
    }

    @Override
    public String toString() {
        return accepted ? "ACCEPT" : "REJECT(" + diagnostic + ")";
    }
}
