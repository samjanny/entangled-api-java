package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.entangled.pipeline.Context;
import org.entangled.pipeline.Pipeline;
import org.entangled.pipeline.Stage4Kind;
import org.entangled.schema.Rfc3339;
import org.junit.jupiter.api.Test;

/**
 * Focused Stage 9 transaction-binding tests (section 10), complementing the
 * corpus-driven {@link ConformanceTest}. Exercises the {@code request_id}
 * binding ({@code E_BIND_REQUEST_ID}), which the transaction stage previously
 * omitted (it checked {@code in_response_to} and {@code request_hash} only).
 *
 * <p>The negative case uses the pre-signed bytes of spec corpus vector
 * {@code 173-bind-request-id-mismatch} (rc.34): the transaction's
 * {@code request_id} ({@code BAECAwQFBgcICQoLDA0ODw}) differs from the one the
 * client placed in the submit body ({@code AAECAwQFBgcICQoLDA0ODw}), while
 * {@code in_response_to} matches the submit path and {@code request_hash}
 * matches the recorded submit body, so {@code E_BIND_REQUEST_ID} is the only
 * live Stage 9 violation. {@link org.entangled.crypto.Ed25519} is verify-only,
 * so the signed bytes are sourced from the corpus generator rather than signed
 * in-process. The positive control reuses the vendored
 * {@code 005-transaction-valid-minimal} vector (matching {@code request_id}) to
 * confirm the added check does not over-reject.
 */
class Stage9BindingTest {

    private static final long CLOCK_NOW = Rfc3339.epochSeconds("2026-05-07T00:01:00Z");

    // Runtime key the corpus authorizes for transaction vectors
    // (corpus/keys.json "runtime".pub_b64u; derived from a fixed test seed).
    private static final String RUNTIME_PUBKEY = "jzFtziEJkbIdjI15I4u3ni3bBa6IFElyyjEmMVSGF7o";
    private static final String SUBMIT_PATH = "/contact";

    // Spec corpus vector 173-bind-request-id-mismatch (rc.34), verbatim.
    private static final String TX_173 =
            "{\"spec_version\":\"1.0\",\"kind\":\"transaction\",\"in_response_to\":\"/contact\","
            + "\"request_id\":\"BAECAwQFBgcICQoLDA0ODw\","
            + "\"request_hash\":\"sha-256:-EvECkoil9nNYYBfRQE85W5pWojAP0K9UG830mtQn0M\","
            + "\"state_updates\":[],\"blocks\":[{\"kind\":\"feedback\",\"variant\":\"success\","
            + "\"content\":[{\"kind\":\"text\",\"value\":\"Received.\",\"marks\":[]}]}],"
            + "\"sig\":\"d-WhzcG365ICBdvq0gCHm7KRAH1w8Em92TMSaI8lebuJpZLGGsQPrxfBnMMtfmM8Qrc33m_5kf2XOhz9BkrdCA\"}";

    private static final String SUBMIT_173 =
            "{\"fields\":{\"message\":\"hello\",\"name\":\"alice\"},\"request_state\":[],"
            + "\"request_id\":\"AAECAwQFBgcICQoLDA0ODw\"}";

    private Context transactionContext(byte[] submitBody) {
        Context ctx = new Context(CLOCK_NOW);
        ctx.expectedKind = Stage4Kind.Kind.TRANSACTION;
        ctx.submitPath = SUBMIT_PATH;
        ctx.submitBody = submitBody;
        ctx.expectedRuntimePubkey = RUNTIME_PUBKEY;
        return ctx;
    }

    @Test
    void requestIdMismatchRejected() {
        Context ctx = transactionContext(SUBMIT_173.getBytes(StandardCharsets.UTF_8));
        Verdict verdict = new Pipeline(ctx).run(TX_173.getBytes(StandardCharsets.UTF_8));
        assertFalse(verdict.isAccepted(),
                "transaction whose request_id differs from the submit body must be rejected");
        assertEquals(DiagnosticCode.E_BIND_REQUEST_ID, verdict.diagnostic().code(),
                "request_id mismatch is E_BIND_REQUEST_ID");
    }

    @Test
    void validTransactionAccepted() {
        // Positive control: the vendored 005 vector has a matching request_id and
        // must still be accepted after the request_id check is added.
        byte[] tx = CorpusFiles.vectorInput("005-transaction-valid-minimal");
        byte[] submit = CorpusFiles.bytes("vectors/005-transaction-valid-minimal/submit_body.json");
        Context ctx = transactionContext(submit);
        Verdict verdict = new Pipeline(ctx).run(tx);
        assertTrue(verdict.isAccepted(),
                "valid transaction with matching request_id must be accepted: " + verdict);
    }
}
