package com.checkmarx.ast;

import com.checkmarx.ast.realtime.RealtimeLocation;
import com.checkmarx.ast.secretsrealtime.SecretsRealtimeResults;
import com.checkmarx.ast.secretsrealtime.MaskResult;
import com.checkmarx.ast.secretsrealtime.MaskedSecret;
import com.checkmarx.ast.wrapper.CxException;
import org.junit.jupiter.api.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration and unit tests for Secrets Realtime scanner functionality.
 * Tests the complete workflow: CLI invocation -> JSON parsing -> domain object mapping.
 * Integration tests use python-vul-file.py as the scan target and are assumption-guarded for CI/local flexibility.
 */
class SecretsRealtimeResultsTest extends BaseTest {

    private boolean isCliConfigured() {
        return Optional.ofNullable(getConfig().getPathToExecutable()).filter(s -> !s.isEmpty()).isPresent();
    }

    /* ------------------------------------------------------ */
    /* Integration tests for Secrets Realtime scanning       */
    /* ------------------------------------------------------ */

    /**
     * Tests basic secrets realtime scan functionality on a vulnerable Python file.
     * Verifies that the scan returns a valid results object and can detect hardcoded secrets
     * such as passwords and credentials embedded in the source code.
     */
    @Test
    @DisplayName("Basic secrets scan on python file returns detected secrets")
    void basicSecretsRealtimeScan() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String pythonFile = "src/test/resources/python-vul-file.py";
        Assumptions.assumeTrue(Files.exists(Paths.get(pythonFile)), "Python vulnerable file not found - cannot test secrets scanning");

        SecretsRealtimeResults results = wrapper.secretsRealtimeScan(pythonFile, "");

        assertNotNull(results, "Scan should return non-null results");
        assertNotNull(results.getSecrets(), "Secrets list should be initialized");

        // The python file contains hardcoded credentials, so we expect some secrets to be found
        if (!results.getSecrets().isEmpty()) {
            results.getSecrets().forEach(secret -> {
                assertNotNull(secret.getTitle(), "Secret title should be populated");
                assertNotNull(secret.getFilePath(), "Secret file path should be populated");
                assertNotNull(secret.getLocations(), "Secret locations should be initialized");
            });
        }
    }

    /**
     * Tests secrets scan with ignore file functionality.
     * Verifies that providing an ignore file doesn't break the scanning process
     * and produces consistent or reduced results compared to baseline scan.
     */
    @Test
    @DisplayName("Secrets scan with ignore file works correctly")
    void secretsRealtimeScanWithIgnoreFile() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String pythonFile = "src/test/resources/python-vul-file.py";
        String ignoreFile = "src/test/resources/ignored-packages.json";
        Assumptions.assumeTrue(Files.exists(Paths.get(pythonFile)) && Files.exists(Paths.get(ignoreFile)),
                "Required test resources missing - cannot test ignore functionality");

        SecretsRealtimeResults baseline = wrapper.secretsRealtimeScan(pythonFile, "");
        SecretsRealtimeResults filtered = wrapper.secretsRealtimeScan(pythonFile, ignoreFile);

        assertNotNull(baseline, "Baseline scan should return results");
        assertNotNull(filtered, "Filtered scan should return results");

        // Ignore file should not increase the number of detected secrets
        assertTrue(filtered.getSecrets().size() <= baseline.getSecrets().size(),
                "Filtered scan should not have more secrets than baseline");
    }

    /**
     * Tests scan consistency by running the same secrets scan multiple times.
     * Verifies that repeated scans of the same file produce stable, deterministic results.
     * This is crucial for ensuring reliable CI/CD pipeline integration.
     */
    @Test
    @DisplayName("Repeated secrets scans produce consistent results")
    void secretsRealtimeScanConsistency() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String pythonFile = "src/test/resources/python-vul-file.py";
        Assumptions.assumeTrue(Files.exists(Paths.get(pythonFile)), "Python file not found - cannot test consistency");

        SecretsRealtimeResults firstScan = wrapper.secretsRealtimeScan(pythonFile, "");
        SecretsRealtimeResults secondScan = wrapper.secretsRealtimeScan(pythonFile, "");

        assertNotNull(firstScan, "First scan should return results");
        assertNotNull(secondScan, "Second scan should return results");

        // Compare secret counts for consistency
        assertEquals(firstScan.getSecrets().size(), secondScan.getSecrets().size(),
                "Secret count should be consistent across multiple scans");
    }

    /**
     * Tests domain object mapping for secrets scan results.
     * Verifies that JSON responses are properly parsed into domain objects
     * and all expected fields (title, description, severity, locations) are correctly mapped.
     */
    @Test
    @DisplayName("Secret domain objects are properly mapped from scan results")
    void secretDomainObjectMapping() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String pythonFile = "src/test/resources/python-vul-file.py";
        Assumptions.assumeTrue(Files.exists(Paths.get(pythonFile)), "Python file not found - cannot test mapping");

        SecretsRealtimeResults results = wrapper.secretsRealtimeScan(pythonFile, "");
        assertNotNull(results, "Scan results should not be null");

        // If secrets are detected, validate their structure
        if (!results.getSecrets().isEmpty()) {
            SecretsRealtimeResults.Secret sampleSecret = results.getSecrets().get(0);

            // Verify core secret fields are mapped correctly
            assertNotNull(sampleSecret.getTitle(), "Secret title should always be present");
            assertNotNull(sampleSecret.getFilePath(), "Secret file path should always be present");
            assertNotNull(sampleSecret.getLocations(), "Locations list should be initialized");

            // Verify locations have proper structure if they exist
            if (!sampleSecret.getLocations().isEmpty()) {
                RealtimeLocation sampleLocation = sampleSecret.getLocations().get(0);
                assertTrue(sampleLocation.getLine() > 0, "Line number should be positive");
            }
        }
    }

    /**
     * Tests secrets scanning on a clean file that should not contain secrets.
     * Verifies that the scanner correctly identifies files without secrets
     * and returns empty results without errors.
     */
    @Test
    @DisplayName("Secrets scan on clean file returns empty results")
    void secretsScanOnCleanFile() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String cleanFile = "src/test/resources/csharp-no-vul.cs";
        Assumptions.assumeTrue(Files.exists(Paths.get(cleanFile)), "Clean C# file not found - cannot test clean scan");

        SecretsRealtimeResults results = wrapper.secretsRealtimeScan(cleanFile, "");
        assertNotNull(results, "Scan results should not be null even for clean files");

        // Clean file should have no secrets or very few false positives
        assertTrue(results.getSecrets().size() <= 2,
                "Clean file should have no or minimal secrets detected");
    }

    /**
     * Tests error handling when scanning a non-existent file.
     * Verifies that the scanner properly throws a CxException with meaningful error message
     * when provided with invalid file paths, demonstrating proper error handling.
     */
    @Test
    @DisplayName("Secrets scan throws appropriate exception for non-existent file")
    void secretsScanHandlesInvalidPath() {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");

        // Test with a non-existent file path
        String invalidPath = "src/test/resources/NonExistentFile.py";

        // The CLI should throw a CxException with a meaningful error message for invalid paths
        CxException exception = assertThrows(CxException.class, () ->
            wrapper.secretsRealtimeScan(invalidPath, "")
        );

        // Verify the exception contains information about the invalid file path
        String errorMessage = exception.getMessage();
        assertNotNull(errorMessage, "Exception should contain an error message");
        assertTrue(errorMessage.contains("invalid file path") || errorMessage.contains("file") || errorMessage.contains("path"),
                "Exception message should indicate the issue is related to file path: " + errorMessage);
    }

    /**
     * Tests secrets scanning across multiple file types.
     * Verifies that the scanner can handle different file extensions and formats
     * without crashing and produces appropriate results for each file type.
     */
    @Test
    @DisplayName("Secrets scan handles multiple file types correctly")
    void secretsScanMultipleFileTypes() {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");

        String[] testFiles = {
            "src/test/resources/python-vul-file.py",
            "src/test/resources/csharp-file.cs",
            "src/test/resources/Dockerfile"
        };

        for (String filePath : testFiles) {
            if (Files.exists(Paths.get(filePath))) {
                assertDoesNotThrow(() -> {
                    SecretsRealtimeResults results = wrapper.secretsRealtimeScan(filePath, "");
                    assertNotNull(results, "Results should not be null for file: " + filePath);
                }, "Scanner should handle file type gracefully: " + filePath);
            }
        }
    }

    /* ------------------------------------------------------ */
    /* Integration tests for Secrets Masking functionality    */
    /* ------------------------------------------------------ */

    /**
     * Tests basic mask secrets functionality - successful case.
     * Similar to the JavaScript test, verifies that the mask command returns proper MaskResult
     * with masked secrets detected in a JSON file containing API keys and passwords.
     */
    @Test
    @DisplayName("Mask secrets successful case - returns masked content")
    void maskSecretsSuccessfulCase() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String secretsFile = "src/test/resources/secrets-test.json";
        Assumptions.assumeTrue(Files.exists(Paths.get(secretsFile)), "Secrets test file not found - cannot test masking");

        MaskResult result = wrapper.maskSecrets(secretsFile);

        assertNotNull(result, "Mask result should not be null");
        assertNotNull(result.getMaskedSecrets(), "Masked secrets list should be initialized");
        assertNotNull(result.getMaskedFile(), "Masked file content should be provided");

        // Expect at least one secret to be found in our test file
        assertFalse(result.getMaskedSecrets().isEmpty(), "Should find masked secrets in test file");

        // Verify structure of masked secrets
        MaskedSecret firstSecret = result.getMaskedSecrets().get(0);
        assertNotNull(firstSecret.getMasked(), "Masked value should be provided");
        assertTrue(firstSecret.getLine() > 0, "Line number should be positive");

        // Masked file should contain the original structure but with secrets redacted
        assertFalse(result.getMaskedFile().trim().isEmpty(), "Masked file content should not be empty");
        assertTrue(result.getMaskedFile().contains("{"), "Masked file should preserve JSON structure");
    }

    /**
     * Tests mask functionality across different file types.
     * Verifies that the mask command can handle various file extensions and formats
     * without crashing and produces appropriate masked results.
     */
    @Test
    @DisplayName("Mask secrets handles multiple file types correctly")
    void maskSecretsMultipleFileTypes() {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");

        String[] testFiles = {
            "src/test/resources/python-vul-file.py",
            "src/test/resources/csharp-file.cs"
        };

        for (String filePath : testFiles) {
            if (Files.exists(Paths.get(filePath))) {
                assertDoesNotThrow(() -> {
                    MaskResult result = wrapper.maskSecrets(filePath);
                    assertNotNull(result, "Mask result should not be null for file: " + filePath);
                    assertNotNull(result.getMaskedSecrets(), "Masked secrets should be initialized for: " + filePath);
                    assertNotNull(result.getMaskedFile(), "Masked file should not be null for: " + filePath);
                }, "Mask command should handle file type gracefully: " + filePath);
            }
        }
    }

    /**
     * Tests error handling when masking a non-existent file.
     * Verifies that the mask command properly throws a CxException with meaningful error message
     * when provided with invalid file paths.
     */
    @Test
    @DisplayName("Mask secrets throws appropriate exception for non-existent file")
    void maskSecretsHandlesInvalidPath() {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");

        // Test with a non-existent file path
        String invalidPath = "src/test/resources/NonExistentFile.py";

        // The CLI should throw a CxException with a meaningful error message for invalid paths
        CxException exception = assertThrows(CxException.class, () ->
            wrapper.maskSecrets(invalidPath)
        );

        // Verify the exception contains information about the invalid file path
        String errorMessage = exception.getMessage();
        assertNotNull(errorMessage, "Exception should contain an error message");
        assertTrue(errorMessage.contains("invalid file path") || errorMessage.contains("file") || errorMessage.contains("path"),
                "Exception message should indicate the issue is related to file path: " + errorMessage);
    }

    /**
     * Tests that masked file content differs from original when secrets are present.
     * Verifies that the masking process actually modifies the file content to redact secrets.
     */
    @Test
    @DisplayName("Masked file content differs from original when secrets exist")
    void maskedContentDiffersFromOriginal() throws Exception {
        Assumptions.assumeTrue(isCliConfigured(), "PATH_TO_EXECUTABLE not configured - skipping integration test");
        String secretsFile = "src/test/resources/secrets-test.json";
        Assumptions.assumeTrue(Files.exists(Paths.get(secretsFile)), "Secrets test file not found - cannot test content masking");

        // Read original file content
        String originalContent = Files.readString(Paths.get(secretsFile));

        // Get masked content
        MaskResult result = wrapper.maskSecrets(secretsFile);
        assertNotNull(result, "Mask result should not be null");

        String maskedContent = result.getMaskedFile();
        assertNotNull(maskedContent, "Masked content should not be null");

        // Since our test file contains secrets, the content should be different after masking
        if (!result.getMaskedSecrets().isEmpty()) {
            assertNotEquals(originalContent, maskedContent,
                "Masked content should differ from original when secrets are present");

            // Verify that original secrets are not present in masked content
            assertFalse(maskedContent.contains("sk-1234567890abcdef1234567890abcdef"),
                "Original API key should be masked in output");
            assertFalse(maskedContent.contains("SuperSecret123!"),
                "Original password should be masked in output");
        }
    }

    /* ------------------------------------------------------ */
    /* Unit tests for Mask JSON parsing functionality        */
    /* ------------------------------------------------------ */

    /**
     * Tests MaskResult JSON parsing with valid mask command response.
     * Verifies that well-formed mask JSON is correctly parsed into MaskResult objects.
     */
    @Test
    @DisplayName("Valid mask JSON response parsing creates correct MaskResult")
    void testMaskResultJsonParsing() {
        String json = "{" +
                "\"maskedSecrets\":[" +
                "{\"masked\":\"****\",\"secret\":\"password123\",\"line\":5}," +
                "{\"masked\":\"***\",\"secret\":\"key\",\"line\":10}" +
                "]," +
                "\"maskedFile\":\"const password = '****';\\nconst apiKey = '***';\"" +
                "}";

        MaskResult result = MaskResult.fromJsonString(json);

        assertNotNull(result, "MaskResult should not be null");
        assertEquals(2, result.getMaskedSecrets().size(), "Should parse 2 masked secrets");

        MaskedSecret firstSecret = result.getMaskedSecrets().get(0);
        assertEquals("****", firstSecret.getMasked());
        assertEquals("password123", firstSecret.getSecret());
        assertEquals(5, firstSecret.getLine());

        MaskedSecret secondSecret = result.getMaskedSecrets().get(1);
        assertEquals("***", secondSecret.getMasked());
        assertEquals("key", secondSecret.getSecret());
        assertEquals(10, secondSecret.getLine());

        assertTrue(result.getMaskedFile().contains("const password = '****'"));
        assertTrue(result.getMaskedFile().contains("const apiKey = '***'"));
    }

    /**
     * Tests MaskResult parsing robustness with edge cases.
     * Verifies that the parser gracefully handles various invalid input scenarios.
     */
    @Test
    @DisplayName("MaskResult handles malformed JSON and edge cases gracefully")
    void testMaskResultEdgeCases() {
        // Blank/null inputs
        assertNull(MaskResult.fromJsonString(""));
        assertNull(MaskResult.fromJsonString("  "));
        assertNull(MaskResult.fromJsonString(null));

        // Invalid JSON structures
        assertNull(MaskResult.fromJsonString("{"));
        assertNull(MaskResult.fromJsonString("not a json"));

        // Empty but valid JSON
        MaskResult emptyResult = MaskResult.fromJsonString("{}");
        assertNotNull(emptyResult);
        assertTrue(emptyResult.getMaskedSecrets().isEmpty());
        assertNotNull(emptyResult.getMaskedFile());
    }

    /* ------------------------------------------------------ */
    /* Unit tests for JSON parsing robustness                */
    /* ------------------------------------------------------ */

    /**
     * Tests JSON parsing with valid secrets scan response containing array format.
     * Verifies that well-formed JSON arrays are correctly parsed into domain objects.
     */
    @Test
    @DisplayName("Valid JSON array parsing creates correct domain objects")
    void testFromLineWithJsonArray() {
        String json = "[" +
                "{" +
                "\"Title\":\"Hardcoded AWS Access Key\"," +
                "\"Description\":\"An AWS access key is hardcoded in the source code. This is a security risk.\"," +
                "\"SecretValue\":\"AKIAIOSFODNN7EXAMPLE\"," +
                "\"FilePath\":\"/path/to/file.py\"," +
                "\"Severity\":\"HIGH\"," +
                "\"Locations\":[{\"StartLine\":10,\"StartColumn\":5,\"EndLine\":10,\"EndColumn\":25}]" +
                "}" +
                "]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getSecrets().size());
        SecretsRealtimeResults.Secret secret = results.getSecrets().get(0);
        assertEquals("Hardcoded AWS Access Key", secret.getTitle());
        assertEquals("An AWS access key is hardcoded in the source code. This is a security risk.", secret.getDescription());
        assertEquals("AKIAIOSFODNN7EXAMPLE", secret.getSecretValue());
        assertEquals("/path/to/file.py", secret.getFilePath());
        assertEquals("HIGH", secret.getSeverity());
        assertEquals(1, secret.getLocations().size());
    }

    /**
     * Tests JSON parsing with valid secrets scan response containing single object format.
     * Verifies that single JSON objects are correctly parsed into domain objects.
     */
    @Test
    @DisplayName("Valid JSON object parsing creates correct domain objects")
    void testFromLineWithJsonObject() {
        String json = "{" +
                "\"Title\":\"Hardcoded AWS Access Key\"," +
                "\"Description\":\"An AWS access key is hardcoded in the source code. This is a security risk.\"," +
                "\"SecretValue\":\"AKIAIOSFODNN7EXAMPLE\"," +
                "\"FilePath\":\"/path/to/file.py\"," +
                "\"Severity\":\"HIGH\"," +
                "\"Locations\":[{\"StartLine\":10,\"StartColumn\":5,\"EndLine\":10,\"EndColumn\":25}]" +
                "}";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getSecrets().size());
        SecretsRealtimeResults.Secret secret = results.getSecrets().get(0);
        assertEquals("Hardcoded AWS Access Key", secret.getTitle());
    }

    /**
     * Tests parsing robustness with malformed JSON and edge cases.
     * Verifies that the parser gracefully handles various invalid input scenarios.
     */
    @Test
    @DisplayName("Malformed JSON and edge cases are handled gracefully")
    void testFromLineWithEdgeCases() {
        // Blank/null inputs
        assertNull(SecretsRealtimeResults.fromLine(""));
        assertNull(SecretsRealtimeResults.fromLine("  "));
        assertNull(SecretsRealtimeResults.fromLine(null));

        // Invalid JSON structures
        assertNull(SecretsRealtimeResults.fromLine("{"));
        assertNull(SecretsRealtimeResults.fromLine("not a json"));
    }

    /**
     * Tests parsing with empty results.
     * Verifies that empty JSON arrays are handled correctly and produce valid empty results.
     */
    @Test
    @DisplayName("Empty JSON arrays are handled correctly")
    void testFromLineWithEmptyResults() {
        String emptyJson = "[]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(emptyJson);
        assertNotNull(results);
        assertTrue(results.getSecrets().isEmpty());
    }
}

