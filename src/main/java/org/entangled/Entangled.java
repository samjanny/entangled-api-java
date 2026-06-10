package org.entangled;

/**
 * Entangled v1.0 reference implementation (Java).
 *
 * <p>This is an independent implementation built solely from the Entangled
 * specification at samjanny/entangled tag v1.0-rc.53 (specs/, docs/, corpus/).
 * It was written without reference to any other implementation of the protocol.
 *
 * <p>The protocol version targeted on the wire is exactly "1.0"; the spec
 * revision this code was read against is recorded in {@link #SPEC_REVISION}.
 */
public final class Entangled {

    /** The on-the-wire protocol version every document must declare (section 02, section 11). */
    public static final String SPEC_VERSION = "1.0";

    /** The spec revision this implementation was read against. */
    public static final String SPEC_REVISION = "1.0-rc.53";

    private Entangled() {
    }
}
