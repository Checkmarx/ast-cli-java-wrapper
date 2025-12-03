package com.checkmarx.ast;

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
}

