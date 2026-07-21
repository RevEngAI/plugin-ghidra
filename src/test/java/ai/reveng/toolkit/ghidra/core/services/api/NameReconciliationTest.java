package ai.reveng.toolkit.ghidra.core.services.api;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the name-reconciliation helpers that back the analysis-sync push-back
 * (de-duplication and invalid-name detection), mirroring the IDA plugin's {@code apply_deduped_name}
 * and invalid-name handling.
 */
public class NameReconciliationTest {

    @Test
    public void deduplicateName_appendsFirstFreeSuffix() {
        assertEquals("foo_1", GhidraRevengService.deduplicateName("foo", Set.of("foo")));
    }

    @Test
    public void deduplicateName_skipsUsedSuffixes() {
        assertEquals("foo_3", GhidraRevengService.deduplicateName("foo", Set.of("foo", "foo_1", "foo_2")));
    }

    @Test
    public void isInvalidGhidraName_rejectsBlankAndNull() {
        assertTrue(GhidraRevengService.isInvalidGhidraName(null));
        assertTrue(GhidraRevengService.isInvalidGhidraName(""));
        assertTrue(GhidraRevengService.isInvalidGhidraName("   "));
    }

    @Test
    public void isInvalidGhidraName_rejectsNamesWithSpaces() {
        assertTrue(GhidraRevengService.isInvalidGhidraName("std::vector<int> foo"));
    }

    @Test
    public void isInvalidGhidraName_acceptsPlainIdentifiers() {
        assertFalse(GhidraRevengService.isInvalidGhidraName("process_input"));
        assertFalse(GhidraRevengService.isInvalidGhidraName("_start"));
    }
}
