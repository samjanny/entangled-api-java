package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The normative conformance suite (corpus/README.md): drive every corpus vector
 * through the validation pipeline and assert the implementation's outcome
 * against the recorded {@code expected} verdict, diagnostic code, and structured
 * details. This is the code-vs-corpus verification; success is 108/108 driven (110 vectors, 2 out of scope for this library).
 *
 * <p>The clock is mocked to {@code corpus.json.clock_now}. Each vector's
 * {@code context} block is mapped onto a {@link Context}: fetched origin/path,
 * submit path and body, the authorized runtime key, the seeded publisher history
 * ({@code previously_verified} / {@code previously_verified_history}), and the
 * successor manifest for migration scenarios.
 */
class ConformanceTest {

    private static final java.nio.file.Path ROOT = CorpusFiles.ROOT;

    /**
     * Vectors that exercise functionality this library documents as out of scope
     * (the section 10 Stage 7 trust-state machine). Like the Rust reference
     * crate, this library is a verifier: it covers the per-document pipeline
     * (Stages 2 through 9) but deliberately leaves trust-state resolution - TOFU
     * pinning, externally-verified PIP, retained-identity mismatch detection, and
     * the publisher-history persistence those require - to an embedding client
     * layer. These vectors are reported as skipped with a printed count rather
     * than counted as failures, so the scope boundary is visible and never
     * silently passes. Each entry is {@code id -> reason}.
     */
    private static final java.util.Map<String, String> OUT_OF_SCOPE = java.util.Map.of(
            "210-trust-publisher-key-mismatch",
            "Stage 7 trust-state machine is out of scope for this library",
            "211-trust-user-rejected-new-identity",
            "Stage 7 trust-state machine is out of scope for this library");

    @TestFactory
    List<DynamicTest> corpusVectors() {
        JsonValue.Obj corpus = (JsonValue.Obj) JsonParser.parse(
                new String(CorpusFiles.bytes("corpus.json"), StandardCharsets.UTF_8));
        long clockNow = Rfc3339.epochSeconds(str(corpus.get("clock_now")));

        // The corpus rc_target must match the spec revision this code was read
        // against, so a corpus bump and a code bump cannot drift apart silently.
        assertEquals(Entangled.SPEC_REVISION, str(corpus.get("rc_target")),
                "corpus rc_target must match Entangled.SPEC_REVISION");

        List<JsonValue> vectors = ((JsonValue.Arr) corpus.get("vectors")).elements();
        List<DynamicTest> tests = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (JsonValue vEntry : vectors) {
            JsonValue.Obj vector = (JsonValue.Obj) vEntry;
            String id = str(vector.get("id"));
            String outOfScopeReason = OUT_OF_SCOPE.get(id);
            if (outOfScopeReason != null) {
                skipped.add("[" + id + "] " + outOfScopeReason);
                continue;
            }
            tests.add(DynamicTest.dynamicTest(id, () -> runVector(vector, clockNow)));
        }
        if (!skipped.isEmpty()) {
            System.out.println(skipped.size() + " of " + vectors.size()
                    + " vectors skipped as out of scope:\n  - "
                    + String.join("\n  - ", skipped));
        }
        // Guard against silently testing fewer vectors than the corpus declares.
        assertEquals(vectors.size() - OUT_OF_SCOPE.size(), tests.size(),
                "corpus vector count (after out-of-scope skips)");
        return tests;
    }

    private void runVector(JsonValue.Obj vector, long clockNow) {
        String id = str(vector.get("id"));
        String inputRel = str(vector.get("input"));
        byte[] body = CorpusFiles.bytes(inputRel);

        Context ctx = new Context(clockNow);
        ctx.expectedKind = switch (str(vector.get("kind"))) {
            case "manifest" -> org.entangled.pipeline.Stage4Kind.Kind.MANIFEST;
            case "content" -> org.entangled.pipeline.Stage4Kind.Kind.CONTENT;
            case "transaction" -> org.entangled.pipeline.Stage4Kind.Kind.TRANSACTION;
            default -> null;
        };
        JsonValue ctxValue = vector.get("context");
        if (ctxValue instanceof JsonValue.Obj c) {
            applyContext(c, ctx);
        }

        Verdict verdict = new Pipeline(ctx).run(body);

        JsonValue.Obj expected = (JsonValue.Obj) vector.get("expected");
        String expectedVerdict = str(expected.get("verdict"));

        if (expectedVerdict.equals("accept")) {
            if (!verdict.isAccepted()) {
                fail(id + ": expected accept but got " + verdict);
            }
            return;
        }

        // reject
        assertTrue(!verdict.isAccepted(), id + ": expected reject but accepted");
        String expectedCode = str(expected.get("diagnostic"));
        assertEquals(expectedCode, verdict.diagnostic().code().name(), id + ": diagnostic code");

        if (expected.has("diagnostic_details")) {
            Map<String, Object> want = toJavaMap((JsonValue.Obj) expected.get("diagnostic_details"));
            Map<String, Object> got = verdict.diagnostic().details();
            assertEquals(want, got, id + ": diagnostic details");
        }
    }

    private void applyContext(JsonValue.Obj c, Context ctx) {
        if (c.has("fetched_origin_address")) {
            ctx.fetchedOriginAddress = str(c.get("fetched_origin_address"));
        }
        if (c.has("fetched_path")) {
            ctx.fetchedPath = str(c.get("fetched_path"));
        }
        if (c.has("submit_path")) {
            ctx.submitPath = str(c.get("submit_path"));
        }
        if (c.has("expected_runtime_pubkey")) {
            ctx.expectedRuntimePubkey = str(c.get("expected_runtime_pubkey"));
        }
        if (c.has("submit_body_path")) {
            ctx.submitBody = CorpusFiles.bytes(str(c.get("submit_body_path")));
        }
        if (c.has("successor_origin_address")) {
            ctx.successorOriginAddress = str(c.get("successor_origin_address"));
        }
        if (c.has("successor_manifest_path")) {
            ctx.successorManifest = CorpusFiles.bytes(str(c.get("successor_manifest_path")));
        }
        if (c.has("content_index_path")) {
            ctx.contentIndex = CorpusFiles.bytes(str(c.get("content_index_path")));
        }
        if (c.has("content_root")) {
            ctx.contentRoot = str(c.get("content_root"));
        }
        if (c.has("previously_verified")) {
            ctx.publisherHistory.add(CorpusFiles.bytes(str(c.get("previously_verified"))));
        }
        if (c.has("previously_verified_history")) {
            for (JsonValue p : ((JsonValue.Arr) c.get("previously_verified_history")).elements()) {
                ctx.publisherHistory.add(CorpusFiles.bytes(str(p)));
            }
        }
    }

    // --- JSON helpers (using the implementation's own parser) ---

    private static String str(JsonValue v) {
        return ((JsonValue.Str) v).value();
    }

    /** Convert a parsed details object to the Java map shape the pipeline produces. */
    private static Map<String, Object> toJavaMap(JsonValue.Obj obj) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, JsonValue> e : obj.members().entrySet()) {
            out.put(e.getKey(), toJava(e.getValue()));
        }
        return out;
    }

    private static Object toJava(JsonValue v) {
        if (v instanceof JsonValue.Str s) {
            return s.value();
        }
        if (v instanceof JsonValue.Num n) {
            // Corpus details integers compare against Long values the pipeline emits.
            BigInteger b = n.value();
            return b == null ? n.raw() : b.longValueExact();
        }
        if (v instanceof JsonValue.Bool b) {
            return b.value();
        }
        return v.toString();
    }
}
