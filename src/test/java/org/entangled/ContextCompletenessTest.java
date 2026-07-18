package org.entangled;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.Test;

/** Security-critical fetch context must be present and match the received document. */
class ContextCompletenessTest {

    private static final long CLOCK = Rfc3339.epochSeconds("2026-05-07T00:01:00Z");
    private static final String RUNTIME_PUBKEY =
            "jzFtziEJkbIdjI15I4u3ni3bBa6IFElyyjEmMVSGF7o";

    @Test
    void expectedKindIsRequired() {
        Context ctx = new Context(CLOCK);
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(CorpusFiles.vectorInput("001-manifest-valid-minimal")));
    }

    @Test
    void discriminatedKindMustMatchExpectedKind() {
        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.MANIFEST;
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(CorpusFiles.vectorInput("003-content-valid-minimal")));
    }

    @Test
    void manifestOriginIsRequired() {
        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.MANIFEST;
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(CorpusFiles.vectorInput("001-manifest-valid-minimal")));
    }

    @Test
    void contentPathIsRequired() {
        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.CONTENT;
        ctx.expectedRuntimePubkey = RUNTIME_PUBKEY;
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(CorpusFiles.vectorInput("003-content-valid-minimal")));
    }

    @Test
    void transactionSubmitContextIsRequired() {
        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.TRANSACTION;
        ctx.expectedRuntimePubkey = RUNTIME_PUBKEY;
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(CorpusFiles.vectorInput("005-transaction-valid-minimal")));
    }

    @Test
    void stateUpdatesRequireVerifiedManifestHistory() {
        Context ctx = new Context(CLOCK);
        ctx.expectedKind = Stage4Kind.Kind.TRANSACTION;
        ctx.expectedRuntimePubkey = RUNTIME_PUBKEY;
        ctx.submitPath = "/contact";
        ctx.submitBody = CorpusFiles.bytes("vectors/011-transaction-valid-state-updates/submit_body.json");
        assertThrows(IllegalStateException.class,
                () -> new Pipeline(ctx).run(
                        CorpusFiles.vectorInput("011-transaction-valid-state-updates")));
    }
}
