package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class SmokeTest {

    @Test
    void specConstants() {
        assertEquals("1.0", Entangled.SPEC_VERSION);
        assertEquals("1.0-rc.40", Entangled.SPEC_REVISION);
    }
}
