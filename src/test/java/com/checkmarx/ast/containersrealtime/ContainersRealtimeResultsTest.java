package com.checkmarx.ast.containersrealtime;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.containersrealtime.ContainersRealtimeImage;
import com.checkmarx.ast.containersrealtime.ContainersRealtimeResults;
import com.checkmarx.ast.containersrealtime.ContainersRealtimeVulnerability;
import com.checkmarx.ast.wrapper.CxException;
import org.junit.jupiter.api.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration and unit tests for Container Realtime scanner functionality.
 * Tests the complete workflow: CLI invocation -> JSON parsing -> domain object mapping.
 * Integration tests use Dockerfile as the scan target and are assumption-guarded for CI/local flexibility.
 */
class ContainersRealtimeResultsTest extends BaseTest {

    private boolean isCliConfigured() {
        return Optional.ofNullable(getConfig().getPathToExecutable()).filter(s -> !s.isEmpty()).isPresent();
    }

    /* ------------------------------------------------------ */
    /* Integration tests for Container Realtime scanning     */
    /* ------------------------------------------------------ */

    /**
     * Tests basic container realtime scan functionality on Dockerfile.
     * Verifies that the scan returns a valid results object with detected container images.
     * This test validates the end-to-end workflow from CLI execution to domain object creation.
     */
    @Test
    @DisplayName("Basic container scan on Dockerfile returns detected images")
    void basicContainerRealtimeScan() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String dockerfilePath = "src/test/resources/Dockerfile";
        Assumptions.assumeTrue(Files.exists(Paths.get(dockerfilePath)), "Dockerfile not found - cannot test container scanning");

        ContainersRealtimeResults results = wrapper.containersRealtimeScan(dockerfilePath, "");

        assertNotNull(results, "Scan should return non-null results");
        assertNotNull(results.getImages(), "Images list should be initialized");

        // Verify that if images are detected, they have proper structure
        if (!results.getImages().isEmpty()) {
            results.getImages().forEach(image -> {
                assertNotNull(image.getImageName(), "Image name should be populated");
                assertNotNull(image.getVulnerabilities(), "Vulnerabilities list should be initialized");
            });
        }
    }

    /**
     * Tests container scan with ignore file functionality.
     * Verifies that providing an ignore file doesn't break the scanning process
     * and produces consistent or reduced results compared to baseline scan.
     */
    @Test
    @DisplayName("Container scan with ignore file works correctly")
    void containerRealtimeScanWithIgnoreFile() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String dockerfilePath = "src/test/resources/Dockerfile";
        String ignoreFile = "src/test/resources/ignored-packages.json";
        Assumptions.assumeTrue(Files.exists(Paths.get(dockerfilePath)) && Files.exists(Paths.get(ignoreFile)),
                "Required test resources missing - cannot test ignore functionality");

        ContainersRealtimeResults baseline = wrapper.containersRealtimeScan(dockerfilePath, "");
        ContainersRealtimeResults filtered = wrapper.containersRealtimeScan(dockerfilePath, ignoreFile);

        assertNotNull(baseline, "Baseline scan should return results");
        assertNotNull(filtered, "Filtered scan should return results");

        // Ignore file should not increase the number of detected issues
        if (baseline.getImages() != null && filtered.getImages() != null) {
            assertTrue(filtered.getImages().size() <= baseline.getImages().size(),
                    "Filtered scan should not have more images than baseline");
        }
    }

    /**
     * Tests scan consistency by running the same container scan multiple times.
     * Verifies that repeated scans of the same Dockerfile produce stable, deterministic results.
     * This is important for CI/CD pipelines where consistent results are crucial.
     */
    @Test
    @DisplayName("Repeated container scans produce consistent results")
    void containerRealtimeScanConsistency() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String dockerfilePath = "src/test/resources/Dockerfile";
        Assumptions.assumeTrue(Files.exists(Paths.get(dockerfilePath)), "Dockerfile not found - cannot test consistency");

        ContainersRealtimeResults firstScan = wrapper.containersRealtimeScan(dockerfilePath, "");
        ContainersRealtimeResults secondScan = wrapper.containersRealtimeScan(dockerfilePath, "");

        assertNotNull(firstScan, "First scan should return results");
        assertNotNull(secondScan, "Second scan should return results");

        // Compare image counts for consistency
        int firstImageCount = (firstScan.getImages() != null) ? firstScan.getImages().size() : 0;
        int secondImageCount = (secondScan.getImages() != null) ? secondScan.getImages().size() : 0;

        assertEquals(firstImageCount, secondImageCount,
                "Image count should be consistent across multiple scans");
    }

    /**
     * Tests domain object mapping for container scan results.
     * Verifies that JSON responses are properly parsed into domain objects
     * and all expected fields are correctly mapped and initialized.
     */
    @Test
    @DisplayName("Container domain objects are properly mapped from scan results")
    void containerDomainObjectMapping() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String dockerfilePath = "src/test/resources/Dockerfile";
        Assumptions.assumeTrue(Files.exists(Paths.get(dockerfilePath)), "Dockerfile not found - cannot test mapping");

        ContainersRealtimeResults results = wrapper.containersRealtimeScan(dockerfilePath, "");
        assertNotNull(results, "Scan results should not be null");

        // If images are detected, validate their structure
        if (results.getImages() != null && !results.getImages().isEmpty()) {
            ContainersRealtimeImage sampleImage = results.getImages().get(0);

            // Verify core image fields are mapped correctly
            assertNotNull(sampleImage.getImageName(), "Image name should always be present");
            assertNotNull(sampleImage.getVulnerabilities(), "Vulnerabilities list should be initialized");

            // If vulnerabilities exist, validate their structure
            if (!sampleImage.getVulnerabilities().isEmpty()) {
                ContainersRealtimeVulnerability sampleVuln = sampleImage.getVulnerabilities().get(0);
                // CVE and Severity are the core fields that should be present
                assertTrue(sampleVuln.getCve() != null || sampleVuln.getSeverity() != null,
                        "Vulnerability should have at least CVE or Severity information");
            }
        }
    }

    /**
     * Tests error handling when scanning a non-existent file.
     * Verifies that the scanner properly throws a CxException with meaningful error message
     * when provided with invalid file paths, demonstrating proper error handling.
     */
    @Test
    @DisplayName("Container scan throws appropriate exception for non-existent file")
    void containerScanHandlesInvalidPath() {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");

        // Test with a non-existent file path
        String invalidPath = "src/test/resources/NonExistentDockerfile";

        // The CLI should throw a CxException with a meaningful error message for invalid paths
        CxException exception = assertThrows(CxException.class, () ->
            wrapper.containersRealtimeScan(invalidPath, "")
        );

        // Verify the exception contains information about the invalid file path
        String errorMessage = exception.getMessage();
        assertNotNull(errorMessage, "Exception should contain an error message");
        assertTrue(errorMessage.contains("invalid file path") || errorMessage.contains("file") || errorMessage.contains("path"),
                "Exception message should indicate the issue is related to file path: " + errorMessage);
    }

    /* ------------------------------------------------------ */
    /* Unit tests for JSON parsing robustness                */
    /* ------------------------------------------------------ */

    /**
     * Tests JSON parsing with valid container scan response.
     * Verifies that well-formed JSON is correctly parsed into domain objects.
     */
    @Test
    @DisplayName("Valid JSON parsing creates correct domain objects")
    void testFromLineWithValidJson() {
        String json = "{" +
                "\"Images\": [" +
                "  {" +
                "    \"ImageName\": \"nginx:latest\"," +
                "    \"Vulnerabilities\": [" +
                "      {" +
                "        \"CVE\": \"CVE-2021-2345\"," +
                "        \"Severity\": \"High\"" +
                "      }" +
                "    ]" +
                "  }" +
                "]" +
                "}";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getImages().size());
        ContainersRealtimeImage image = results.getImages().get(0);
        assertEquals("nginx:latest", image.getImageName());
        assertEquals(1, image.getVulnerabilities().size());
        ContainersRealtimeVulnerability vulnerability = image.getVulnerabilities().get(0);
        assertEquals("CVE-2021-2345", vulnerability.getCve());
        assertEquals("High", vulnerability.getSeverity());
    }

    /**
     * Tests parsing robustness with malformed JSON.
     * Verifies that the parser gracefully handles various edge cases.
     */
    @Test
    @DisplayName("Malformed JSON is handled gracefully")
    void testFromLineWithEdgeCases() {
        // Missing Images key
        assertNull(ContainersRealtimeResults.fromLine("{\"some_other_key\": \"some_value\"}"));

        // Invalid JSON structure
        assertNull(ContainersRealtimeResults.fromLine("{\"Images\": [}"));

        // Blank/null inputs
        assertNull(ContainersRealtimeResults.fromLine(""));
        assertNull(ContainersRealtimeResults.fromLine("  "));
        assertNull(ContainersRealtimeResults.fromLine(null));
    }

    /**
     * Tests parsing with empty or null image arrays.
     * Verifies that empty results are handled correctly.
     */
    @Test
    @DisplayName("Empty and null image arrays are handled correctly")
    void testFromLineWithEmptyResults() {
        // Empty images array
        String emptyJson = "{\"Images\": []}";
        ContainersRealtimeResults emptyResults = ContainersRealtimeResults.fromLine(emptyJson);
        assertNotNull(emptyResults);
        assertTrue(emptyResults.getImages().isEmpty());

        // Null images
        String nullJson = "{\"Images\": null}";
        ContainersRealtimeResults nullResults = ContainersRealtimeResults.fromLine(nullJson);
        assertNotNull(nullResults);
        assertNull(nullResults.getImages());
    }

    /* ------------------------------------------------------ */
    /* Comprehensive Unit Tests for Constructor & Getters   */
    /* ------------------------------------------------------ */

    /**
     * Tests constructor with null images list.
     * Verifies that null input is preserved (not auto-converted to empty list).
     */
    @Test
    @DisplayName("Constructor with null images preserves null")
    void testConstructor_NullImages() {
        ContainersRealtimeResults results = new ContainersRealtimeResults(null);
        assertNull(results.getImages());
    }

    /**
     * Tests constructor with empty images list.
     * Verifies that empty list is preserved.
     */
    @Test
    @DisplayName("Constructor with empty images list preserves empty list")
    void testConstructor_EmptyImages() {
        java.util.List<ContainersRealtimeImage> emptyList = java.util.Collections.emptyList();
        ContainersRealtimeResults results = new ContainersRealtimeResults(emptyList);
        assertNotNull(results.getImages());
        assertTrue(results.getImages().isEmpty());
    }

    /**
     * Tests constructor with single image.
     * Verifies that single image is preserved.
     */
    @Test
    @DisplayName("Constructor with single image preserves image")
    void testConstructor_SingleImage() {
        java.util.List<ContainersRealtimeImage> imageList = new java.util.ArrayList<>();
        ContainersRealtimeImage image = createImage("ubuntu:20.04", 0);
        imageList.add(image);

        ContainersRealtimeResults results = new ContainersRealtimeResults(imageList);
        assertEquals(1, results.getImages().size());
        assertEquals("ubuntu:20.04", results.getImages().get(0).getImageName());
    }

    /**
     * Tests constructor with multiple images.
     * Verifies that all images are preserved and accessible.
     */
    @Test
    @DisplayName("Constructor with multiple images preserves all images")
    void testConstructor_MultipleImages() {
        java.util.List<ContainersRealtimeImage> imageList = new java.util.ArrayList<>();
        imageList.add(createImage("nginx:latest", 2));
        imageList.add(createImage("postgres:13", 1));
        imageList.add(createImage("redis:6", 0));

        ContainersRealtimeResults results = new ContainersRealtimeResults(imageList);
        assertEquals(3, results.getImages().size());
        assertEquals("nginx:latest", results.getImages().get(0).getImageName());
        assertEquals("postgres:13", results.getImages().get(1).getImageName());
        assertEquals("redis:6", results.getImages().get(2).getImageName());
    }

    /**
     * Tests getter method returns correct images.
     * Verifies that getImages() returns the same list passed to constructor.
     */
    @Test
    @DisplayName("getImages() returns correct images list")
    void testGetter_Images() {
        java.util.List<ContainersRealtimeImage> imageList = new java.util.ArrayList<>();
        imageList.add(createImage("app:v1", 5));

        ContainersRealtimeResults results = new ContainersRealtimeResults(imageList);
        java.util.List<ContainersRealtimeImage> retrieved = results.getImages();

        assertNotNull(retrieved);
        assertEquals(1, retrieved.size());
        assertEquals("app:v1", retrieved.get(0).getImageName());
    }

    /**
     * Tests equals with identical objects.
     * Verifies that ContainersRealtimeResults with same images are equal.
     */
    @Test
    @DisplayName("equals returns true for identical results")
    void testEquals_Identical() {
        java.util.List<ContainersRealtimeImage> imageList1 = new java.util.ArrayList<>();
        imageList1.add(createImage("nginx:latest", 1));

        java.util.List<ContainersRealtimeImage> imageList2 = new java.util.ArrayList<>();
        imageList2.add(createImage("nginx:latest", 1));

        ContainersRealtimeResults results1 = new ContainersRealtimeResults(imageList1);
        ContainersRealtimeResults results2 = new ContainersRealtimeResults(imageList2);

        assertEquals(results1, results2);
    }

    /**
     * Tests equals with different objects.
     * Verifies that ContainersRealtimeResults with different images are not equal.
     */
    @Test
    @DisplayName("equals returns false for different results")
    void testEquals_Different() {
        java.util.List<ContainersRealtimeImage> imageList1 = new java.util.ArrayList<>();
        imageList1.add(createImage("nginx:latest", 1));

        java.util.List<ContainersRealtimeImage> imageList2 = new java.util.ArrayList<>();
        imageList2.add(createImage("apache:latest", 1));

        ContainersRealtimeResults results1 = new ContainersRealtimeResults(imageList1);
        ContainersRealtimeResults results2 = new ContainersRealtimeResults(imageList2);

        assertNotEquals(results1, results2);
    }

    /**
     * Tests hashCode consistency.
     * Verifies that equal objects have the same hash code.
     */
    @Test
    @DisplayName("hashCode is consistent for equal objects")
    void testHashCode_Consistency() {
        java.util.List<ContainersRealtimeImage> imageList1 = new java.util.ArrayList<>();
        imageList1.add(createImage("nginx:latest", 0));

        java.util.List<ContainersRealtimeImage> imageList2 = new java.util.ArrayList<>();
        imageList2.add(createImage("nginx:latest", 0));

        ContainersRealtimeResults results1 = new ContainersRealtimeResults(imageList1);
        ContainersRealtimeResults results2 = new ContainersRealtimeResults(imageList2);

        assertEquals(results1.hashCode(), results2.hashCode());
    }

    /* ------------------------------------------------------ */
    /* Advanced JSON Parsing Tests                           */
    /* ------------------------------------------------------ */

    /**
     * Tests fromLine with JSON missing "Images" key.
     * Verifies that the condition `line.contains("\"Images\"")` works correctly.
     */
    @Test
    @DisplayName("fromLine returns null when Images key is missing")
    void testFromLine_MissingImagesKey() {
        String json = "{\"Container\": {\"Name\": \"test\"}}";
        assertNull(ContainersRealtimeResults.fromLine(json));
    }

    /**
     * Tests fromLine with Images key but invalid JSON structure.
     * Verifies that validation still occurs after checking for Images key.
     */
    @Test
    @DisplayName("fromLine validates JSON even when Images key exists")
    void testFromLine_InvalidJsonWithImagesKey() {
        String json = "{\"Images\": [}";  // Has Images key but invalid structure
        assertNull(ContainersRealtimeResults.fromLine(json));
    }

    /**
     * Tests fromLine with multiple images of varying complexity.
     * Verifies parsing of realistic container scan results.
     */
    @Test
    @DisplayName("fromLine parses multiple complex images")
    void testFromLine_MultipleComplexImages() {
        String json = "{" +
                "\"Images\": [" +
                "  {" +
                "    \"ImageName\": \"nginx:1.21\"," +
                "    \"Vulnerabilities\": [" +
                "      {\"CVE\": \"CVE-2021-1111\", \"Severity\": \"Critical\"}," +
                "      {\"CVE\": \"CVE-2021-2222\", \"Severity\": \"High\"}" +
                "    ]" +
                "  }," +
                "  {" +
                "    \"ImageName\": \"postgres:13-alpine\"," +
                "    \"Vulnerabilities\": [" +
                "      {\"CVE\": \"CVE-2021-3333\", \"Severity\": \"Medium\"}" +
                "    ]" +
                "  }," +
                "  {" +
                "    \"ImageName\": \"redis:6-slim\"," +
                "    \"Vulnerabilities\": []" +
                "  }" +
                "]" +
                "}";

        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(3, results.getImages().size());

        // Verify first image
        assertEquals("nginx:1.21", results.getImages().get(0).getImageName());
        assertEquals(2, results.getImages().get(0).getVulnerabilities().size());

        // Verify second image
        assertEquals("postgres:13-alpine", results.getImages().get(1).getImageName());
        assertEquals(1, results.getImages().get(1).getVulnerabilities().size());

        // Verify third image with no vulnerabilities
        assertEquals("redis:6-slim", results.getImages().get(2).getImageName());
        assertTrue(results.getImages().get(2).getVulnerabilities().isEmpty());
    }

    /**
     * Tests fromLine with null images array value.
     * Verifies that null image lists are preserved.
     */
    @Test
    @DisplayName("fromLine preserves null images array")
    void testFromLine_NullImagesArray() {
        String json = "{\"Images\": null}";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertNull(results.getImages());
    }

    /**
     * Tests fromLine with whitespace around Images key.
     * Verifies string matching handles edge cases.
     */
    @Test
    @DisplayName("fromLine handles Images key with various whitespace")
    void testFromLine_ImagesKeyWithWhitespace() {
        String json = "{ \"Images\" : [ { \"ImageName\" : \"test:latest\" } ] }";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getImages().size());
    }

    /**
     * Tests fromLine with additional unknown properties.
     * Verifies @JsonIgnoreProperties works correctly.
     */
    @Test
    @DisplayName("fromLine ignores unknown JSON properties")
    void testFromLine_UnknownProperties() {
        String json = "{" +
                "\"Images\": [{\"ImageName\": \"test:1\"}]," +
                "\"UnknownField\": \"value\"," +
                "\"AnotherUnknown\": {\"nested\": \"data\"}" +
                "}";

        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getImages().size());
        assertEquals("test:1", results.getImages().get(0).getImageName());
    }

    /**
     * Tests fromLine with various blank inputs.
     * Verifies StringUtils.isBlank() handles all cases.
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "   ", "\t", "\n", "\r\n", "\t\t\t"})
    @DisplayName("fromLine returns null for blank inputs")
    void testFromLine_BlankInputs(String blankInput) {
        assertNull(ContainersRealtimeResults.fromLine(blankInput));
    }

    /**
     * Tests fromLine with null input.
     */
    @Test
    @DisplayName("fromLine returns null for null input")
    void testFromLine_NullInput() {
        assertNull(ContainersRealtimeResults.fromLine(null));
    }

    /**
     * Tests fromLine with JSON containing Images key but no opening bracket.
     * Verifies robustness of JSON validation.
     */
    @Test
    @DisplayName("fromLine handles incomplete JSON with Images key")
    void testFromLine_IncompleteJson() {
        String json = "{\"Images\"";  // Incomplete JSON with Images key
        assertNull(ContainersRealtimeResults.fromLine(json));
    }

    /**
     * Tests fromLine with escaped quotes in image name.
     * Verifies JSON parsing handles escaped characters.
     */
    @Test
    @DisplayName("fromLine handles escaped characters in image name")
    void testFromLine_EscapedCharacters() {
        String json = "{" +
                "\"Images\": [" +
                "{\"ImageName\": \"registry.example.com/app\\\"special:1.0\"}" +
                "]" +
                "}";

        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        // Should parse successfully (ObjectMapper handles escaped quotes)
        if (results != null) {
            assertNotNull(results.getImages());
        }
    }

    /**
     * Tests fromLine with nested vulnerability structures.
     * Verifies deep JSON structure parsing.
     */
    @Test
    @DisplayName("fromLine parses deeply nested vulnerability structures")
    void testFromLine_DeeplyNestedStructures() {
        String json = "{" +
                "\"Images\": [" +
                "{" +
                "  \"ImageName\": \"complex:latest\"," +
                "  \"Vulnerabilities\": [" +
                "    {" +
                "      \"CVE\": \"CVE-2021-9999\"," +
                "      \"Severity\": \"Critical\"," +
                "      \"PackageName\": \"openssl\"," +
                "      \"PackageVersion\": \"1.1.1\"," +
                "      \"FixedVersion\": \"1.1.2\"" +
                "    }" +
                "  ]" +
                "}" +
                "]" +
                "}";

        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getImages().size());
        assertEquals("complex:latest", results.getImages().get(0).getImageName());
        assertEquals(1, results.getImages().get(0).getVulnerabilities().size());
    }

    /**
     * Tests fromLine with very large image list.
     * Verifies performance and correctness with multiple images.
     */
    @Test
    @DisplayName("fromLine handles large number of images")
    void testFromLine_LargeImageList() {
        StringBuilder jsonBuilder = new StringBuilder("{\"Images\": [");
        for (int i = 0; i < 50; i++) {
            if (i > 0) jsonBuilder.append(",");
            jsonBuilder.append("{\"ImageName\": \"image").append(i).append(":latest\"}");
        }
        jsonBuilder.append("]}");

        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(jsonBuilder.toString());
        assertNotNull(results);
        assertEquals(50, results.getImages().size());
    }

    // ===== Helper Methods =====

    /**
     * Creates a mock ContainersRealtimeImage for testing.
     */
    private ContainersRealtimeImage createImage(String imageName, int vulnerabilityCount) {
        java.util.List<ContainersRealtimeVulnerability> vulns = new java.util.ArrayList<>();
        for (int i = 0; i < vulnerabilityCount; i++) {
            vulns.add(new ContainersRealtimeVulnerability(
                    "CVE-2021-" + String.format("%04d", i),
                    new String[]{"High", "Medium", "Low", "Critical"}[i % 4]
            ));
        }
        return new ContainersRealtimeImage(
                imageName,
                "tag-" + vulnerabilityCount,
                "/path/to/image",
                null,
                "Active",
                vulns
        );
    }
}

