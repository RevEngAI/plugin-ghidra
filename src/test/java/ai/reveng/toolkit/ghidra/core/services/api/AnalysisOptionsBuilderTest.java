package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.AnalysisCreateRequest;
import ai.reveng.model.Tag;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class AnalysisOptionsBuilderTest {

    @Test
    public void testToAnalysisCreateRequest_WithNoTags() {
        // Create a builder with no tags
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("a".repeat(64)))
                .fileName("test.bin");

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        // Verify that tags are either null or empty, but not containing empty tags
        if (request.getTags() != null) {
            assertTrue("Tags list should be empty when no tags are added", request.getTags().isEmpty());
        }
    }

    @Test
    public void testToAnalysisCreateRequest_WithValidTags() {
        // Create a builder with valid tags
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("b".repeat(64)))
                .fileName("test.bin")
                .addTag("malware")
                .addTag("suspicious");

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        // Verify that tags are properly set
        assertNotNull("Tags should not be null", request.getTags());
        assertEquals("Should have 2 tags", 2, request.getTags().size());

        List<String> tagNames = request.getTags().stream()
                .map(Tag::getName)
                .toList();

        assertTrue("Should contain 'malware' tag", tagNames.contains("malware"));
        assertTrue("Should contain 'suspicious' tag", tagNames.contains("suspicious"));
    }

    @Test
    public void testToAnalysisCreateRequest_WithEmptyStringTag() {
        // Create a builder with an empty string tag
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("c".repeat(64)))
                .fileName("test.bin")
                .addTag("")
                .addTag("   ") // whitespace only
                .addTag("valid-tag");

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        // Verify that empty/whitespace tags are filtered out
        assertNotNull("Tags should not be null", request.getTags());
        assertEquals("Should only have 1 valid tag after filtering", 1, request.getTags().size());
        assertEquals("Should only contain the valid tag", "valid-tag", request.getTags().getFirst().getName());
    }

    @Test
    public void testToAnalysisCreateRequest_WithMultipleTags() {
        // Create a builder with multiple tags using addTags method
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("d".repeat(64)))
                .fileName("test.bin")
                .addTags(Arrays.asList("tag1", "tag2", "tag3"));

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        // Verify that all tags are properly set
        assertNotNull("Tags should not be null", request.getTags());
        assertEquals("Should have 3 tags", 3, request.getTags().size());
    }

    @Test
    public void testToAnalysisCreateRequest_WithOnlyEmptyTags() {
        // Create a builder with only empty/whitespace tags
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("e".repeat(64)))
                .fileName("test.bin")
                .addTag("")
                .addTag("   ")
                .addTag("\t");

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        // Verify that no tags are set when all are empty
        if (request.getTags() != null) {
            assertTrue("Tags list should be empty when only empty tags are added", request.getTags().isEmpty());
        }
    }

    @Test
    public void testToAnalysisCreateRequest_BasicFields() {
        // Test that basic fields are properly set
        String filename = "myfile.exe";
        String hash = "f".repeat(64);

        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash(hash))
                .fileName(filename);

        AnalysisCreateRequest request = builder.toAnalysisCreateRequest();

        assertEquals("Filename should match", filename, request.getFilename());
        assertEquals("SHA256 hash should match", hash, request.getSha256Hash());
    }

    @Test
    public void testGetTags() {
        // Test the getTags method
        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("a".repeat(64)))
                .fileName("test.bin");

        // Initially should be empty
        assertTrue("Tags should initially be empty", builder.getTags().isEmpty());

        // Add tags
        builder.addTag("tag1").addTag("tag2");

        List<String> tags = builder.getTags();
        assertEquals("Should have 2 tags", 2, tags.size());
        assertTrue("Should contain tag1", tags.contains("tag1"));
        assertTrue("Should contain tag2", tags.contains("tag2"));
    }
}

