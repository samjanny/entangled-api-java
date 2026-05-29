package org.entangled.pipeline;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-evaluation context supplied to the validation pipeline.
 *
 * <p>This carries the out-of-band facts a real client would hold and that the
 * corpus supplies through each vector's {@code context} block (corpus/README.md):
 * the mocked clock, the carrier origin and path a document was fetched from, the
 * submit body and submit path for transaction binding, the seeded publisher
 * history (prior verified manifests) for anti-downgrade / canary-conflict /
 * runtime-reuse, and the successor manifest material for migration scenarios.
 *
 * <p>The pipeline reads only what each document kind needs; absent fields are
 * left null and the corresponding stage adapts (for example, a content document
 * with no fetched path cannot run Stage 9 path binding).
 */
public final class Context {

    /** Mocked current time, epoch seconds (corpus clock_now). */
    public final long nowEpoch;

    /**
     * The document kind the client expects from the fetch context (manifest from
     * /manifest.json, content from a content path, transaction from a submit
     * response). This selects the Stage 2 byte cap, which the spec enforces
     * before parsing (section 10 Stage 2): a manifest is capped at 64 KiB,
     * content/transaction at 1 MiB. A real client knows this from which endpoint
     * it fetched; the corpus supplies it as the vector's {@code kind}.
     */
    public Stage4Kind.Kind expectedKind;

    /** Carrier origin address a manifest was fetched from (Stage 9 origin binding). */
    public String fetchedOriginAddress;

    /** Path a content document was fetched from (Stage 9 path binding). */
    public String fetchedPath;

    /**
     * The runtime public key the current manifest authorizes, supplied for
     * content/transaction vectors (corpus context.expected_runtime_pubkey).
     * Null means no verified manifest is available -> Stage 6 E_SIG_INVALID_KEY.
     */
    public String expectedRuntimePubkey;

    /** Path a submit was sent to (Stage 9 transaction in_response_to binding). */
    public String submitPath;

    /** Exact bytes of the submit body the client sent (Stage 9 request_hash / request_id binding). */
    public byte[] submitBody;

    /** Prior verified manifests for the same publisher, oldest first (publisher history seed). */
    public final List<byte[]> publisherHistory = new ArrayList<>();

    /** Successor manifest bytes for a migration scenario (Stage 9 successor verification). */
    public byte[] successorManifest;

    /** Announced successor origin address for a migration scenario. */
    public String successorOriginAddress;

    public Context(long nowEpoch) {
        this.nowEpoch = nowEpoch;
    }
}
