package org.entangled.fuzz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.entangled.RejectException;
import org.entangled.Verdict;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage2Input;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.Rfc3339;

/**
 * One-shot differential evaluator: turn raw document bytes into a normalized
 * verdict string for comparison against the Rust reference (entangled-core).
 *
 * <p>This models the verifier surface both reference implementations expose: a
 * function from response bytes to an accept/reject outcome. The harness feeds
 * bytes alone (no fetched-endpoint hint); the document kind is self-discriminated
 * from {@code kind} exactly as {@link Pipeline} does, and the byte cap applied is
 * that discriminated kind's cap. The cross-endpoint case (a caller that fetched
 * {@code /manifest.json} but received a content document, where the 64 KiB vs
 * 1 MiB caps differ) is a Stage 1 client concern outside both verifier cores and
 * is not exercised here.
 *
 * <p>The fixed context is pinned to the corpus's canonical values (origin,
 * runtime key, paths, clock) so the three minimal valid vectors (001 manifest,
 * 003 content, 005 transaction) reach an accept and the deep accept-path stages
 * (canary, origin binding, request binding) are exercised; every other input
 * rejects, and the harness only cares that both implementations reject with the
 * same code.
 *
 * <p>The normalized verdict is {@code "A"} for accept, {@code "R:<CODE>"} for a
 * reject carrying the section 11 diagnostic code, or {@code "X:<Type>"} for an
 * unexpected throwable (which is itself a finding: the Rust side reports a panic
 * to the fuzzer, so a one-sided crash always surfaces as a divergence).
 */
public final class DiffEval {

    // Canonical corpus context (corpus.json clock_now and the values used by the
    // 001/003/005 minimal vectors). These MUST stay byte-identical to the
    // constants the Rust fuzz target pins, or the two sides diverge spuriously.
    private static final String CLOCK_NOW = "2026-05-07T00:01:00Z";
    private static final String ORIGIN_ADDRESS =
            "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";
    private static final String RUNTIME_PUBKEY = "jzFtziEJkbIdjI15I4u3ni3bBa6IFElyyjEmMVSGF7o";
    private static final String CONTENT_PATH = "/articles/first-post";
    private static final String SUBMIT_PATH = "/contact";
    private static final String SUBMIT_BODY_VECTOR =
            "vectors/005-transaction-valid-minimal/submit_body.json";

    private final long clockNow;
    private final byte[] submitBody;

    /**
     * @param corpusRoot the corpus directory (the same path the Rust harness
     *                   resolves via {@code ENTANGLED_CORPUS_PATH}); used only to
     *                   load the fixed submit body for the transaction
     *                   accept-path vector
     */
    public DiffEval(Path corpusRoot) {
        this.clockNow = Rfc3339.epochSeconds(CLOCK_NOW);
        try {
            this.submitBody = Files.readAllBytes(corpusRoot.resolve(SUBMIT_BODY_VECTOR));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** Build a DiffEval resolving the corpus root from {@code ENTANGLED_CORPUS_PATH}. */
    public static DiffEval fromEnv() {
        String p = System.getenv("ENTANGLED_CORPUS_PATH");
        if (p == null || p.isEmpty()) {
            throw new IllegalStateException(
                    "ENTANGLED_CORPUS_PATH must point at the conformance corpus directory");
        }
        return new DiffEval(Paths.get(p));
    }

    /** Evaluate one document body to its normalized verdict string. */
    public String evaluate(byte[] body) {
        try {
            // Probe at the most permissive cap purely to discriminate the kind;
            // the probe never accepts. Pipeline.run below re-validates from
            // scratch under the discriminated kind's own cap, so a manifest in
            // (64 KiB, 1 MiB] still rejects E_INPUT_BYTE_CAP there, matching Rust.
            String text = Stage2Input.validateAndDecode(body, Stage2Input.CONTENT_BYTE_CAP);
            JsonValue root = JsonParser.parse(text);
            Stage4Kind.Kind kind = Stage4Kind.discriminate(root);

            Context ctx = fixedContext();
            ctx.expectedKind = kind;
            return normalize(new Pipeline(ctx).run(body));
        } catch (RejectException e) {
            // A probe-stage rejection (Stage 2 byte/UTF-8/BOM, Stage 3 parse,
            // Stage 4 kind) is itself the verdict.
            return reject(e.diagnostic().code());
        } catch (Throwable t) {
            // Any other throwable (e.g. a StackOverflowError on deep nesting, or
            // an implementation bug) is a distinct outcome; surfacing it as its
            // own verdict makes a one-sided crash a visible divergence.
            return "X:" + t.getClass().getSimpleName();
        }
    }

    private Context fixedContext() {
        Context ctx = new Context(clockNow);
        // All fixed fields are set unconditionally; Pipeline reads only those the
        // discriminated kind needs, so the unused ones are inert.
        ctx.fetchedOriginAddress = ORIGIN_ADDRESS;
        ctx.fetchedPath = CONTENT_PATH;
        ctx.expectedRuntimePubkey = RUNTIME_PUBKEY;
        ctx.submitPath = SUBMIT_PATH;
        ctx.submitBody = submitBody;
        return ctx;
    }

    private static String normalize(Verdict v) {
        if (v.isAccepted()) {
            return "A";
        }
        return reject(v.diagnostic().code());
    }

    /**
     * Encode a rejection as {@code R:<CODE>:<STAGE>}. The stage lets the Rust
     * conformance check separate within-stage code latitude (allowed, section 11)
     * from a cross-stage first-failing-stage violation.
     */
    private static String reject(org.entangled.DiagnosticCode code) {
        return "R:" + code.name() + ":" + code.stage();
    }

    /** UTF-8 bytes of a verdict string, for the wire protocol. */
    public static byte[] encode(String verdict) {
        return verdict.getBytes(StandardCharsets.UTF_8);
    }
}
