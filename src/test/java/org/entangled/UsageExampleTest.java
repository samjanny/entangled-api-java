package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.Test;

/**
 * Executable mirror of the README usage examples, so the documented API is kept
 * honest: if these stop compiling or passing, the README is wrong.
 */
class UsageExampleTest {

    private static final long CLOCK = Rfc3339.epochSeconds("2026-05-07T00:01:00Z");
    private static final String ORIGIN =
            "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";
    private static final String RUNTIME_PUB = "jzFtziEJkbIdjI15I4u3ni3bBa6IFElyyjEmMVSGF7o";

    @Test
    void verifyAManifest() {
        byte[] manifest = CorpusFiles.vectorInput("001-manifest-valid-minimal");

        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.MANIFEST;
        ctx.fetchedOriginAddress = ORIGIN;

        Verdict verdict = new Pipeline(ctx).run(manifest);

        assertTrue(verdict.isAccepted());
    }

    @Test
    void verifyAContentDocument() {
        byte[] content = CorpusFiles.vectorInput("003-content-valid-minimal");

        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.CONTENT;
        ctx.fetchedPath = "/articles/first-post";
        ctx.expectedRuntimePubkey = RUNTIME_PUB;

        Verdict verdict = new Pipeline(ctx).run(content);

        assertTrue(verdict.isAccepted());
    }

    @Test
    void inspectARejection() {
        byte[] tampered = CorpusFiles.vectorInput("150-sig-modified-payload");

        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.MANIFEST;
        ctx.fetchedOriginAddress = ORIGIN;

        Verdict verdict = new Pipeline(ctx).run(tampered);

        assertFalse(verdict.isAccepted());
        assertEquals(DiagnosticCode.E_SIG_VERIFICATION, verdict.diagnostic().code());
        // verdict.diagnostic().details() carries the structured details map.
    }
}
