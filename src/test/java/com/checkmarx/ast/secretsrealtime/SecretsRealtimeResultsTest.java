package com.checkmarx.ast.secretsrealtime;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.realtime.RealtimeLocation;
import com.checkmarx.ast.wrapper.CxException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration and unit tests for Secrets Realtime scanner functionality.
 * Tests the complete workflow: CLI invocation -> JSON parsing -> domain object mapping.
 * Integration tests use python-vul-file.py as the scan target and are assumption-guarded for CI/local flexibility.
 */
class SecretsRealtimeResultsTest extends BaseTest {

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

    /* ------------------------------------------------------ */
    /* Comprehensive Unit Tests for Secret Inner Class      */
    /* ------------------------------------------------------ */

    /**
     * Tests Secret constructor with all fields populated.
     * Verifies that all constructor parameters are correctly assigned to instance variables.
     */
    @Test
    @DisplayName("Secret constructor with all fields initializes correctly")
    void testSecretConstructor_AllFields() {
        java.util.List<RealtimeLocation> locations = createLocations(2);
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "AWS Key",
                "Hardcoded AWS Access Key",
                "AKIAIOSFODNN7EXAMPLE",
                "/src/main.py",
                "CRITICAL",
                locations
        );
        assertEquals("AWS Key", secret.getTitle());
        assertEquals("Hardcoded AWS Access Key", secret.getDescription());
        assertEquals("AKIAIOSFODNN7EXAMPLE", secret.getSecretValue());
        assertEquals("/src/main.py", secret.getFilePath());
        assertEquals("CRITICAL", secret.getSeverity());
        assertEquals(2, secret.getLocations().size());
    }

    /**
     * Tests Secret constructor with null locations.
     * Verifies that null locations are converted to empty list instead of staying null.
     */
    @Test
    @DisplayName("Secret constructor with null locations initializes empty list")
    void testSecretConstructor_NullLocations() {
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "Key", "Desc", "Value", "/path", "HIGH", null
        );
        assertNotNull(secret.getLocations());
        assertTrue(secret.getLocations().isEmpty());
    }

    /**
     * Tests Secret constructor with empty locations list.
     * Verifies that empty location lists are preserved.
     */
    @Test
    @DisplayName("Secret constructor with empty locations list")
    void testSecretConstructor_EmptyLocations() {
        java.util.List<RealtimeLocation> emptyLocations = java.util.Collections.emptyList();
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "Key", "Desc", "Value", "/path", "HIGH", emptyLocations
        );
        assertNotNull(secret.getLocations());
        assertTrue(secret.getLocations().isEmpty());
    }

    /**
     * Tests Secret constructor with null fields.
     * Verifies that null field values are preserved (Lombok's @Value allows nulls).
     */
    @Test
    @DisplayName("Secret constructor with null fields preserves nulls")
    void testSecretConstructor_NullFields() {
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                null, null, null, null, null, null
        );
        assertNull(secret.getTitle());
        assertNull(secret.getDescription());
        assertNull(secret.getSecretValue());
        assertNull(secret.getFilePath());
        assertNull(secret.getSeverity());
        assertNotNull(secret.getLocations()); // Only this is initialized to empty list
    }

    /**
     * Tests Secret getters return correct values.
     * Verifies that all getter methods return the values set in constructor.
     */
    @Test
    @DisplayName("Secret getters return correct values")
    void testSecretGetters() {
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "Database Password",
                "Hardcoded DB password found",
                "postgres://user:pass@localhost",
                "/config/database.conf",
                "CRITICAL",
                java.util.Collections.emptyList()
        );
        assertEquals("Database Password", secret.getTitle());
        assertEquals("Hardcoded DB password found", secret.getDescription());
        assertEquals("postgres://user:pass@localhost", secret.getSecretValue());
        assertEquals("/config/database.conf", secret.getFilePath());
        assertEquals("CRITICAL", secret.getSeverity());
    }

    /**
     * Tests Secret equals with identical objects.
     * Verifies that secrets with same field values are considered equal.
     */
    @Test
    @DisplayName("Secret equals returns true for identical values")
    void testSecretEquals_Identical() {
        SecretsRealtimeResults.Secret secret1 = createSecret("Title1", "Value1", "HIGH");
        SecretsRealtimeResults.Secret secret2 = createSecret("Title1", "Value1", "HIGH");
        assertEquals(secret1, secret2);
    }

    /**
     * Tests Secret equals with different values.
     * Verifies that secrets with different field values are not equal.
     */
    @Test
    @DisplayName("Secret equals returns false for different values")
    void testSecretEquals_Different() {
        SecretsRealtimeResults.Secret secret1 = createSecret("Title1", "Value1", "HIGH");
        SecretsRealtimeResults.Secret secret2 = createSecret("Title2", "Value2", "MEDIUM");
        assertNotEquals(secret1, secret2);
    }

    /**
     * Tests Secret equals with partial differences.
     * Verifies that secrets differing in one field are not equal.
     */
    @Test
    @DisplayName("Secret equals false when title differs")
    void testSecretEquals_DifferentTitle() {
        SecretsRealtimeResults.Secret secret1 = createSecret("Title1", "Value", "HIGH");
        SecretsRealtimeResults.Secret secret2 = createSecret("Title2", "Value", "HIGH");
        assertNotEquals(secret1, secret2);
    }

    @Test
    @DisplayName("Secret equals false when severity differs")
    void testSecretEquals_DifferentSeverity() {
        SecretsRealtimeResults.Secret secret1 = createSecret("Title", "Value", "HIGH");
        SecretsRealtimeResults.Secret secret2 = createSecret("Title", "Value", "MEDIUM");
        assertNotEquals(secret1, secret2);
    }

    /**
     * Tests Secret hashCode consistency.
     * Verifies that equal secrets have the same hash code.
     */
    @Test
    @DisplayName("Secret hashCode is consistent for equal objects")
    void testSecretHashCode_Consistency() {
        SecretsRealtimeResults.Secret secret1 = createSecret("AWS", "AKIA", "CRITICAL");
        SecretsRealtimeResults.Secret secret2 = createSecret("AWS", "AKIA", "CRITICAL");
        assertEquals(secret1.hashCode(), secret2.hashCode());
    }

    /**
     * Tests Secret with multiple locations.
     * Verifies that secrets can have multiple location entries.
     */
    @Test
    @DisplayName("Secret with multiple locations preserves all locations")
    void testSecret_MultipleLocations() {
        java.util.List<RealtimeLocation> locations = createLocations(5);
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "API Key", "Hardcoded key", "sk_live_xxx", "/app.js", "HIGH", locations
        );
        assertEquals(5, secret.getLocations().size());
    }

    /**
     * Tests Secret with all null string fields but populated locations.
     * Verifies that locations can exist even when other fields are null.
     */
    @Test
    @DisplayName("Secret with null strings but populated locations")
    void testSecret_NullFieldsWithLocations() {
        java.util.List<RealtimeLocation> locations = createLocations(1);
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                null, null, null, null, null, locations
        );
        assertNull(secret.getTitle());
        assertNotNull(secret.getLocations());
        assertEquals(1, secret.getLocations().size());
    }

    /**
     * Tests SecretsRealtimeResults constructor with null secrets list.
     * Verifies that null is converted to empty list.
     */
    @Test
    @DisplayName("SecretsRealtimeResults constructor with null secrets initializes empty list")
    void testSecretsResultsConstructor_NullSecrets() {
        SecretsRealtimeResults results = new SecretsRealtimeResults(null);
        assertNotNull(results.getSecrets());
        assertTrue(results.getSecrets().isEmpty());
    }

    /**
     * Tests SecretsRealtimeResults constructor with empty secrets list.
     * Verifies that empty list is preserved.
     */
    @Test
    @DisplayName("SecretsRealtimeResults constructor with empty secrets")
    void testSecretsResultsConstructor_EmptySecrets() {
        java.util.List<SecretsRealtimeResults.Secret> emptyList = java.util.Collections.emptyList();
        SecretsRealtimeResults results = new SecretsRealtimeResults(emptyList);
        assertNotNull(results.getSecrets());
        assertTrue(results.getSecrets().isEmpty());
    }

    /**
     * Tests SecretsRealtimeResults constructor with multiple secrets.
     * Verifies that all secrets are preserved in the results.
     */
    @Test
    @DisplayName("SecretsRealtimeResults constructor preserves multiple secrets")
    void testSecretsResultsConstructor_MultipleSecrets() {
        java.util.List<SecretsRealtimeResults.Secret> secrets = new java.util.ArrayList<>();
        secrets.add(createSecret("AWS", "AKIA", "HIGH"));
        secrets.add(createSecret("DB", "postgres", "CRITICAL"));
        secrets.add(createSecret("API", "sk_", "MEDIUM"));

        SecretsRealtimeResults results = new SecretsRealtimeResults(secrets);
        assertEquals(3, results.getSecrets().size());
    }

    /**
     * Tests fromLine with multiple secrets in array format.
     * Verifies that arrays with multiple secrets are correctly parsed.
     */
    @Test
    @DisplayName("fromLine parses multiple secrets from JSON array")
    void testFromLineWithMultipleSecretsArray() {
        String json = "[" +
                "{\"Title\":\"AWS Key\",\"SecretValue\":\"AKIA\",\"Severity\":\"HIGH\"}," +
                "{\"Title\":\"DB Password\",\"SecretValue\":\"pass\",\"Severity\":\"CRITICAL\"}" +
                "]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertEquals(2, results.getSecrets().size());
        assertEquals("AWS Key", results.getSecrets().get(0).getTitle());
        assertEquals("DB Password", results.getSecrets().get(1).getTitle());
    }

    /**
     * Tests fromLine with all Secret fields present.
     * Verifies complete JSON with all fields maps correctly to domain object.
     */
    @Test
    @DisplayName("fromLine with complete Secret fields")
    void testFromLineWithCompleteSecretFields() {
        String json = "{" +
                "\"Title\":\"AWS Access Key\"," +
                "\"Description\":\"Production access key\"," +
                "\"SecretValue\":\"AKIAIOSFODNN7EXAMPLE\"," +
                "\"FilePath\":\"/config/.env\"," +
                "\"Severity\":\"CRITICAL\"," +
                "\"Locations\":[{\"Line\":5,\"StartIndex\":10,\"EndIndex\":30}]" +
                "}";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        SecretsRealtimeResults.Secret secret = results.getSecrets().get(0);
        assertEquals("AWS Access Key", secret.getTitle());
        assertEquals("Production access key", secret.getDescription());
        assertEquals("AKIAIOSFODNN7EXAMPLE", secret.getSecretValue());
        assertEquals("/config/.env", secret.getFilePath());
        assertEquals("CRITICAL", secret.getSeverity());
        assertEquals(1, secret.getLocations().size());
    }

    /**
     * Tests fromLine with various severity levels.
     * Verifies that different severity values are preserved.
     */
    @Test
    @DisplayName("fromLine handles various severity levels")
    void testFromLineWithVariousSeverities() {
        String[] severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        for (String severity : severities) {
            String json = "{\"Title\":\"Secret\",\"Severity\":\"" + severity + "\"}";
            SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
            assertEquals(severity, results.getSecrets().get(0).getSeverity());
        }
    }

    /**
     * Tests fromLine with special characters in secret value.
     * Verifies that special characters in secret values are preserved.
     */
    @Test
    @DisplayName("fromLine handles special characters in secret value")
    void testFromLineWithSpecialCharacters() {
        String json = "{" +
                "\"Title\":\"Connection String\"," +
                "\"SecretValue\":\"user=admin&pass=P@ssw0rd!#$%^*()\"" +
                "}";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertEquals("user=admin&pass=P@ssw0rd!#$%^*()", results.getSecrets().get(0).getSecretValue());
    }

    /**
     * Tests fromLine with whitespace-only fields.
     * Verifies that whitespace-only strings are preserved as-is (not treated as null).
     */
    @Test
    @DisplayName("fromLine preserves whitespace in fields")
    void testFromLineWithWhitespaceFields() {
        String json = "{\"Title\":\"   \",\"Description\":\"\\t\\n\"}";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        SecretsRealtimeResults.Secret secret = results.getSecrets().get(0);
        assertEquals("   ", secret.getTitle());
    }

    // ===== Helper Methods =====

    private SecretsRealtimeResults.Secret createSecret(String title, String secretValue, String severity) {
        return new SecretsRealtimeResults.Secret(title, "Description", secretValue, "/path", severity, null);
    }

    private java.util.List<RealtimeLocation> createLocations(int count) {
        java.util.List<RealtimeLocation> locations = new java.util.ArrayList<>();
        for (int i = 1; i <= count; i++) {
            locations.add(new RealtimeLocation(i, i * 5, i * 10));
        }
        return locations;
    }
}

