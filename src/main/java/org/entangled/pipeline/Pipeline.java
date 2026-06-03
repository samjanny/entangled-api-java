package org.entangled.pipeline;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.entangled.Diagnostic;
import org.entangled.DiagnosticCode;
import org.entangled.RejectException;
import org.entangled.Verdict;
import org.entangled.crypto.Base64Url;
import org.entangled.crypto.Ed25519;
import org.entangled.crypto.Sha;
import org.entangled.crypto.TorV3Address;
import org.entangled.json.Jcs;
import org.entangled.json.JsonParser;
import org.entangled.json.JsonValue;
import org.entangled.schema.DocumentSchema;
import org.entangled.schema.Rfc3339;

/**
 * The 10-stage validation pipeline (section 10), evaluating a single document
 * (with its {@link Context}) to a {@link Verdict}.
 *
 * <p>Stages run in order and the first failing stage determines the rejection
 * (section 10 error precedence): a {@link RejectException} thrown by any stage is
 * caught here and converted to the verdict. Stages that depend on an
 * already-verified manifest are adapted per document kind.
 *
 * <p>Stage 1 (transport) is not exercised by the corpus (wire-body only, no
 * response metadata), so it is not modeled here; the byte cap is selected by
 * document kind at Stage 2.
 */
public final class Pipeline {

    private static final String CTX_MANIFEST = "ENTANGLED-v1 manifest";
    private static final String CTX_CONTENT = "ENTANGLED-v1 content";
    private static final String CTX_TRANSACTION = "ENTANGLED-v1 transaction";

    private final Context ctx;

    public Pipeline(Context ctx) {
        this.ctx = ctx;
    }

    /** Run the pipeline on the raw document bytes. */
    public Verdict run(byte[] body) {
        try {
            // Stage 2: the byte cap is document-kind specific and is enforced
            // before parsing (section 10 Stage 2). The expected kind comes from
            // the fetch context (a real client knows it fetched /manifest.json,
            // a content path, or a submit response); the corpus supplies it as
            // the vector's kind. When unknown, fall back to the most permissive
            // 1 MiB cap so UTF-8/BOM are still checked before parse.
            int cap = capForExpectedKind();
            String text = Stage2Input.validateAndDecode(body, cap);

            // Stage 3: parse.
            JsonValue root = JsonParser.parse(text);

            // Stage 4: kind discrimination.
            Stage4Kind.Kind kind = Stage4Kind.discriminate(root);
            JsonValue.Obj doc = (JsonValue.Obj) root;

            switch (kind) {
                case MANIFEST -> runManifest(doc, body);
                case CONTENT -> runContent(doc, body);
                case TRANSACTION -> runTransaction(doc, body);
            }
            return Verdict.accept();
        } catch (RejectException e) {
            return Verdict.reject(e.diagnostic());
        }
    }

    private int capForExpectedKind() {
        if (ctx.expectedKind == null) {
            return Stage2Input.CONTENT_BYTE_CAP;
        }
        return switch (ctx.expectedKind) {
            case MANIFEST -> Stage2Input.MANIFEST_BYTE_CAP;
            case CONTENT -> Stage2Input.CONTENT_BYTE_CAP;
            case TRANSACTION -> Stage2Input.TRANSACTION_BYTE_CAP;
        };
    }

    // --- Manifest ---

    private void runManifest(JsonValue.Obj doc, byte[] body) {
        // Stage 5: closed schema + cross-field semantic checks.
        DocumentSchema.validateManifest(doc, ctx.nowEpoch);

        // Stage 6: signature under publisher_pubkey (first contact uses the
        // manifest's own key; the corpus single-document manifests have no
        // retained identity to mismatch against).
        byte[] pub = decode32(strField(doc, "publisher_pubkey"));
        verifyOrThrow(pub, doc, CTX_MANIFEST);

        // Stage 8: canary state, future-skew, anti-downgrade, conflict, runtime reuse.
        Stage8Canary.evaluate(doc, ctx);

        // Stage 9: origin binding, not_after expiry, migration.
        Stage9Binding.manifest(doc, ctx);

        // Stage 9b: when the manifest declares content_root, verify the served
        // content index against it and structurally validate the index.
        Stage9ContentIndex.verifyManifestIndex(doc, ctx.contentIndex);
    }

    // --- Content ---

    private void runContent(JsonValue.Obj doc, byte[] body) {
        DocumentSchema.validateContent(doc);

        // Stage 6: verify under the authorized runtime key. The corpus supplies
        // it via context.expected_runtime_pubkey (the key the current manifest
        // would authorize). Absence means no verified manifest -> E_SIG_INVALID_KEY.
        byte[] runtimePub = runtimeKeyOrInvalid();
        verifyOrThrow(runtimePub, doc, CTX_CONTENT);

        // Stage 9: path binding (byte-exact against the fetched path).
        Stage9Binding.contentPath(doc, ctx);

        // Stage 9b: when a verified content index applies (content_root in
        // context), compare this document's seq and body hash against the
        // committed entry for its path.
        Stage9ContentIndex.verifyContentSeq(doc, body, ctx.contentRoot, ctx.contentIndex);
    }

    // --- Transaction ---

    private void runTransaction(JsonValue.Obj doc, byte[] body) {
        DocumentSchema.validateTransaction(doc);

        byte[] runtimePub = runtimeKeyOrInvalid();
        verifyOrThrow(runtimePub, doc, CTX_TRANSACTION);

        // Stage 5 (policy-aware): when the manifest under which this transaction
        // is verified is available, every state_updates (namespace, key) must be
        // declared in its state_policy (E_STATE_UNDECLARED). The standalone Stage 5
        // form/range checks above do not need the manifest; this half does.
        JsonValue.Arr statePolicy = pinnedStatePolicy();
        if (statePolicy != null) {
            DocumentSchema.checkStateUpdatesDeclared(doc, statePolicy);
        }

        // Stage 9: in_response_to / request_id / request_hash binding.
        Stage9Binding.transaction(doc, ctx);
    }

    /**
     * The {@code state_policy} of the manifest under which the current document
     * is verified, taken from the most recent entry in the seeded publisher
     * history, or null when no manifest is available. The history bytes were
     * already verified when seeded; here we only re-read the declared policy.
     */
    private JsonValue.Arr pinnedStatePolicy() {
        if (ctx.publisherHistory.isEmpty()) {
            return null;
        }
        byte[] manifestBytes = ctx.publisherHistory.get(ctx.publisherHistory.size() - 1);
        JsonValue parsed = JsonParser.parse(new String(manifestBytes, StandardCharsets.UTF_8));
        if (parsed instanceof JsonValue.Obj manifest
                && manifest.get("state_policy") instanceof JsonValue.Arr policy) {
            return policy;
        }
        return null;
    }

    private byte[] runtimeKeyOrInvalid() {
        if (ctx.expectedRuntimePubkey == null) {
            // No verified manifest from which to obtain the authorized runtime key.
            throw new RejectException(DiagnosticCode.E_SIG_INVALID_KEY);
        }
        return decode32(ctx.expectedRuntimePubkey);
    }

    // --- signature helpers ---

    /** Verify the document signature; throw E_SIG_VERIFICATION on failure. */
    static void verifyOrThrow(byte[] pub, JsonValue.Obj doc, String context) {
        byte[] sig = decode64(strField(doc, "sig"));
        byte[] input = signatureInput(context, canonicalPayloadMinusSig(doc));
        if (!Ed25519.verify(pub, sig, input)) {
            throw new RejectException(DiagnosticCode.E_SIG_VERIFICATION);
        }
    }

    /** JCS of the document object with the top-level sig removed. */
    static byte[] canonicalPayloadMinusSig(JsonValue.Obj doc) {
        Map<String, JsonValue> members = new LinkedHashMap<>(doc.members());
        members.remove("sig");
        return Jcs.canonicalize(new JsonValue.Obj(members));
    }

    static byte[] signatureInput(String context, byte[] jcs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(context.getBytes(StandardCharsets.US_ASCII));
        out.write(0x00);
        out.writeBytes(jcs);
        return out.toByteArray();
    }

    static String strField(JsonValue.Obj doc, String key) {
        return ((JsonValue.Str) doc.get(key)).value();
    }

    static byte[] decode32(String b64u) {
        return Base64Url.decode(b64u, 32);
    }

    static byte[] decode64(String b64u) {
        return Base64Url.decode(b64u, 64);
    }
}
