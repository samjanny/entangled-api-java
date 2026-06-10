package org.entangled;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SmokeTest {

    @Test
    void specConstants() {
        assertEquals("1.0", Entangled.SPEC_VERSION);
        assertEquals("1.0-rc.55", Entangled.SPEC_REVISION);
    }

    /**
     * AMB-24: the user-visible-string assigned-only gate (Fields.requireNfc) uses
     * Character.isDefined, which reflects the JDK's Unicode version. The pinned
     * baseline is Unicode 15.0, which is the JDK 21 UCD. These probes fail loudly
     * if the running JDK moves off Unicode 15.0, which would silently change the
     * gate's accepted code-point set away from the spec baseline.
     */
    @Test
    void unicodeBaselineIsBaseline15_0() {
        assertTrue(Character.isDefined(0x0870), "U+0870 (Unicode 14.0) must be assigned");
        assertTrue(Character.isDefined(0x1E030), "U+1E030 (Unicode 15.0) must be assigned");
        assertFalse(Character.isDefined(0x2EBF0), "U+2EBF0 (Unicode 15.1) must be unassigned at the 15.0 baseline");
        assertFalse(Character.isDefined(0x0897), "U+0897 (Unicode 16.0) must be unassigned at the 15.0 baseline");
    }
}
