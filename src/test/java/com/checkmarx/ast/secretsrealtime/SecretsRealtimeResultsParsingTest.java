package com.checkmarx.ast.secretsrealtime;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecretsRealtimeResultsParsingTest {

    @Test
    void testFromLineWithValidJsonArray() {
        String json = "[" +
                "  {" +
                "    \"Title\": \"AWS Secret Key\"," +
                "    \"Description\": \"Found AWS secret key\"," +
                "    \"SecretValue\": \"abc123\"," +
                "    \"FilePath\": \"/src/config.yml\"," +
                "    \"Severity\": \"High\"" +
                "  }" +
                "]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getSecrets().size());
        SecretsRealtimeResults.Secret secret = results.getSecrets().get(0);
        assertEquals("AWS Secret Key", secret.getTitle());
        assertEquals("Found AWS secret key", secret.getDescription());
        assertEquals("abc123", secret.getSecretValue());
        assertEquals("/src/config.yml", secret.getFilePath());
        assertEquals("High", secret.getSeverity());
    }

    @Test
    void testFromLineWithValidJsonObject() {
        String json = "{" +
                "  \"Title\": \"Single Secret\"," +
                "  \"SecretValue\": \"tok-xyz\"," +
                "  \"Severity\": \"Medium\"" +
                "}";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getSecrets().size());
        assertEquals("Single Secret", results.getSecrets().get(0).getTitle());
        assertEquals("Medium", results.getSecrets().get(0).getSeverity());
    }

    @Test
    void testFromLineWithEmptyJsonArray() {
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine("[]");
        assertNotNull(results);
        assertTrue(results.getSecrets().isEmpty());
    }

    @Test
    void testFromLineWithBlankAndNull() {
        assertNull(SecretsRealtimeResults.fromLine(""));
        assertNull(SecretsRealtimeResults.fromLine("   "));
        assertNull(SecretsRealtimeResults.fromLine(null));
    }

    @Test
    void testFromLineWithInvalidJson() {
        assertNull(SecretsRealtimeResults.fromLine("{"));
        assertNull(SecretsRealtimeResults.fromLine("[{invalid}]"));
    }

    @Test
    void testFromLineWithValidJsonNonObjectNonArray() {
        // Valid JSON that is neither array nor object — falls through both ifs and returns null
        assertNull(SecretsRealtimeResults.fromLine("42"));
        assertNull(SecretsRealtimeResults.fromLine("\"bare string\""));
        assertNull(SecretsRealtimeResults.fromLine("true"));
    }

    @Test
    void testConstructorWithNullSecrets() {
        SecretsRealtimeResults results = new SecretsRealtimeResults(null);
        assertNotNull(results);
        assertTrue(results.getSecrets().isEmpty());
    }

    @Test
    void testConstructorWithNonNullSecrets() {
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "Title", "Desc", "val", "/path", "Low", null);
        SecretsRealtimeResults results = new SecretsRealtimeResults(
                Collections.singletonList(secret));
        assertEquals(1, results.getSecrets().size());
        assertEquals("Title", results.getSecrets().get(0).getTitle());
    }

    @Test
    void testSecretConstructorWithNullLocations() {
        SecretsRealtimeResults.Secret secret = new SecretsRealtimeResults.Secret(
                "T", "D", "v", "/f", "High", null);
        assertTrue(secret.getLocations().isEmpty());
    }

    @Test
    void testSecretConstructorWithNonNullLocations() {
        String json = "[{" +
                "  \"Title\": \"Loc Secret\"," +
                "  \"Severity\": \"Critical\"," +
                "  \"Locations\": [{\"Line\": 5, \"StartIndex\": 0, \"EndIndex\": 10}]" +
                "}]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getSecrets().size());
        List<?> locations = results.getSecrets().get(0).getLocations();
        assertEquals(1, locations.size());
    }

    @Test
    void testFromLineWithMultipleSecrets() {
        String json = "[" +
                "  {\"Title\": \"Secret A\", \"Severity\": \"High\"}," +
                "  {\"Title\": \"Secret B\", \"Severity\": \"Low\"}" +
                "]";
        SecretsRealtimeResults results = SecretsRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(2, results.getSecrets().size());
        assertEquals("Secret A", results.getSecrets().get(0).getTitle());
        assertEquals("Secret B", results.getSecrets().get(1).getTitle());
    }
}
