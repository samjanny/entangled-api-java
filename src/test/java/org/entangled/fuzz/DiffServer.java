package org.entangled.fuzz;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;

/**
 * Persistent differential server: one warm JVM that the Rust fuzz target drives
 * over stdin/stdout so the JVM startup cost is paid once per campaign rather than
 * once per input.
 *
 * <p>Wire protocol, both directions length-prefixed with a 4-byte big-endian
 * count (the {@link DataInputStream#readInt()} / {@link DataOutputStream#writeInt(int)}
 * encoding):
 *
 * <pre>
 *   request:  [int32 n]            then n body bytes        (n == -1 -&gt; shutdown)
 *   response: [int32 m]            then m verdict bytes      (UTF-8 "A" / "R:CODE" / "X:Type")
 * </pre>
 *
 * <p>Nothing else may be written to stdout; diagnostics go to stderr. The body
 * length may be zero (the empty document is a valid fuzz input).
 */
public final class DiffServer {

    private DiffServer() {
    }

    public static void main(String[] args) throws Exception {
        DiffEval eval = DiffEval.fromEnv();

        DataInputStream in = new DataInputStream(new BufferedInputStream(System.in));
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(System.out));

        // Signal readiness on stderr so the parent can wait for warm-up if it
        // wants; the protocol itself is request-driven and needs no handshake.
        System.err.println("entangled diff-server ready");
        System.err.flush();

        while (true) {
            int n;
            try {
                n = in.readInt();
            } catch (EOFException e) {
                break; // parent closed the pipe
            }
            if (n < 0) {
                break; // shutdown sentinel
            }
            byte[] body = new byte[n];
            in.readFully(body);

            String verdict = eval.evaluate(body);
            byte[] encoded = DiffEval.encode(verdict);
            out.writeInt(encoded.length);
            out.write(encoded);
            out.flush();
        }
    }
}
