package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.Test;

/**
 * Error-precedence between the Stage 6 signature check and the Stage 8 canary
 * checks (AMB-16, section 11:209). The canary timestamp, ordering, and interval
 * checks are Stage 8 (E_CANARY_INVALID), which runs AFTER Stage 6. So a manifest
 * that has both a bad signature and a canary-integrity violation must be
 * rejected as E_SIG_VERIFICATION (the first failing stage), not E_CANARY_INVALID.
 *
 * <p>Before the stage fix these canary checks ran during Stage 5 schema
 * validation, ahead of Stage 6, so such a manifest was wrongly reported as
 * E_CANARY_INVALID. The corpus does not catch this because its three
 * E_CANARY_INVALID vectors all carry a valid signature.
 */
class CanaryPrecedenceTest {

    private static final long CLOCK_NOW = Rfc3339.epochSeconds("2026-05-07T00:01:00Z");
    private static final String ORIGIN_ADDRESS =
            "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";

    private Context manifestContext() {
        Context ctx = new Context(CLOCK_NOW);
        ctx.expectedKind = Stage4Kind.Kind.MANIFEST;
        ctx.fetchedOriginAddress = ORIGIN_ADDRESS;
        return ctx;
    }

    @Test
    void canaryIntervalViolationAloneIsCanaryInvalid() {
        // Control: vector 182 (canary interval below the 7-day minimum), signed
        // correctly, is rejected at Stage 8 as E_CANARY_INVALID. This pins that
        // moving the interval check to Stage 8 preserves the verdict.
        byte[] manifest = CorpusFiles.vectorInput("182-canary-invalid");
        Verdict verdict = new Pipeline(manifestContext()).run(manifest);
        assertFalse(verdict.isAccepted());
        assertEquals(DiagnosticCode.E_CANARY_INVALID, verdict.diagnostic().code(),
                "a sound signature with a bad canary interval is E_CANARY_INVALID at Stage 8");
    }

    @Test
    void badSignatureWinsOverCanaryInterval() {
        // Vector 182 with a corrupted signature: now the manifest has both a
        // Stage 6 signature failure and a Stage 8 canary-interval violation.
        // Error precedence (first failing stage) requires E_SIG_VERIFICATION,
        // because Stage 6 runs before Stage 8.
        byte[] manifest = corruptSignature(CorpusFiles.vectorInput("182-canary-invalid"));
        Verdict verdict = new Pipeline(manifestContext()).run(manifest);
        assertFalse(verdict.isAccepted());
        assertEquals(DiagnosticCode.E_SIG_VERIFICATION, verdict.diagnostic().code(),
                "a bad signature must be reported ahead of the Stage 8 canary check");
    }

    @Test
    void badSignatureWinsOverMalformedCanaryTimestamp() {
        // Vector 186 (malformed canary.next_expected) with a corrupted signature:
        // a malformed canary timestamp is a Stage 8 check, so the Stage 6
        // signature failure takes precedence.
        byte[] manifest = corruptSignature(CorpusFiles.vectorInput("186-canary-malformed-timestamp"));
        Verdict verdict = new Pipeline(manifestContext()).run(manifest);
        assertFalse(verdict.isAccepted());
        assertEquals(DiagnosticCode.E_SIG_VERIFICATION, verdict.diagnostic().code(),
                "a bad signature must be reported ahead of the Stage 8 malformed-timestamp check");
    }

    /**
     * Flip one base64url character of the manifest's "sig" value so the signature
     * no longer verifies, leaving the rest of the document (and its canary
     * violation) intact. The flip stays within the base64url alphabet so the
     * schema-level sig syntax check at Stage 5 still passes and the failure
     * surfaces at Stage 6.
     */
    private static byte[] corruptSignature(byte[] manifest) {
        String text = new String(manifest, StandardCharsets.UTF_8);
        String marker = "\"sig\": \"";
        int start = text.indexOf(marker);
        if (start < 0) {
            marker = "\"sig\":\"";
            start = text.indexOf(marker);
        }
        int valueStart = start + marker.length();
        char c = text.charAt(valueStart);
        char replacement = c == 'A' ? 'B' : 'A';
        String corrupted = text.substring(0, valueStart) + replacement + text.substring(valueStart + 1);
        return corrupted.getBytes(StandardCharsets.UTF_8);
    }
}
