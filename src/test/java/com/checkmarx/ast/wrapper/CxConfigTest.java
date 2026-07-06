package com.checkmarx.ast.wrapper;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CxConfig")
class CxConfigTest {

    // UUID constants for testing
    private static final String TEST_TENANT_ID = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
    private static final String TEST_CLIENT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    @Test
    @DisplayName("toArguments with API key auth only")
    void testToArguments_WithApiKeyOnly_IncludesApiKeyArg() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--apikey"));
        assertTrue(args.contains("test-api-key-123"));
        assertFalse(args.stream().anyMatch(arg -> arg.equals("--client-id")));
    }

    @Test
    @DisplayName("toArguments with client ID and API key auth")
    void testToArguments_WithClientIdAndApiKey_IncludesBoth() {
        CxConfig config = CxConfig.builder()
            .clientId(TEST_CLIENT_ID)
            .apiKey("test-api-key-123")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--client-id"));
        assertTrue(args.contains(TEST_CLIENT_ID));
        assertTrue(args.contains("--apikey"));
        assertTrue(args.contains("test-api-key-123"));
    }

    @Test
    @DisplayName("toArguments with client ID and secret auth")
    void testToArguments_WithClientIdAndSecret_IncludesBoth() {
        CxConfig config = CxConfig.builder()
            .clientId(TEST_CLIENT_ID)
            .clientSecret("test-secret-456")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--client-id"));
        assertTrue(args.contains(TEST_CLIENT_ID));
        assertTrue(args.contains("--client-secret"));
        assertTrue(args.contains("test-secret-456"));
        assertFalse(args.stream().anyMatch(arg -> arg.equals("--api-key")));
    }

    @Test
    @DisplayName("toArguments with tenant parameter")
    void testToArguments_WithTenant_IncludesTenantArg() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .tenant(TEST_TENANT_ID)
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--tenant"));
        assertTrue(args.contains(TEST_TENANT_ID));
    }

    @Test
    @DisplayName("toArguments with base URI parameter")
    void testToArguments_WithBaseUri_IncludesBaseUriArg() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .baseUri("https://api.checkmarx.com")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--base-uri"));
        assertTrue(args.contains("https://api.checkmarx.com"));
    }

    @Test
    @DisplayName("toArguments with base auth URI parameter")
    void testToArguments_WithBaseAuthUri_IncludesBaseAuthUriArg() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .baseAuthUri("https://auth.checkmarx.com")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--base-auth-uri"));
        assertTrue(args.contains("https://auth.checkmarx.com"));
    }

    @Test
    @DisplayName("toArguments with agent name parameter")
    void testToArguments_WithAgentName_IncludesAgentArg() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .agentName("JETBRAINS")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--agent"));
        assertTrue(args.contains("JETBRAINS"));
    }

    @Test
    @DisplayName("toArguments with additional parameters")
    void testToArguments_WithAdditionalParameters_IncludesAdditionalParams() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-api-key-123")
            .additionalParameters("--param1 value1 --param2 value2")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--param1"));
        assertTrue(args.contains("value1"));
        assertTrue(args.contains("--param2"));
        assertTrue(args.contains("value2"));
    }

    @Test
    @DisplayName("toArguments with all parameters set")
    void testToArguments_WithAllParameters_IncludesAllArgs() {
        CxConfig config = CxConfig.builder()
            .clientId(TEST_CLIENT_ID)
            .apiKey("test-api-key-123")
            .tenant(TEST_TENANT_ID)
            .baseUri("https://api.checkmarx.com")
            .baseAuthUri("https://auth.checkmarx.com")
            .agentName("JETBRAINS")
            .additionalParameters("--project MyProject")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--client-id"));
        assertTrue(args.contains("--apikey"));
        assertTrue(args.contains("--tenant"));
        assertTrue(args.contains("--base-uri"));
        assertTrue(args.contains("--base-auth-uri"));
        assertTrue(args.contains("--agent"));
        assertTrue(args.contains("--project"));
    }

    @Test
    @DisplayName("toArguments with empty auth configuration")
    void testToArguments_WithNoAuthProvided_NoAuthArgsIncluded() {
        CxConfig config = CxConfig.builder()
            .build();

        List<String> args = config.toArguments();

        assertFalse(args.stream().anyMatch(arg -> arg.equals("--api-key")));
        assertFalse(args.stream().anyMatch(arg -> arg.equals("--client-id")));
        assertFalse(args.stream().anyMatch(arg -> arg.equals("--client-secret")));
    }

    @Test
    @DisplayName("toArguments ignores blank auth values")
    void testToArguments_WithBlankAuthValues_IgnoresBlankFields() {
        CxConfig config = CxConfig.builder()
            .apiKey("")
            .clientId("  ")
            .tenant("")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.isEmpty());
    }

    @ParameterizedTest
    @CsvSource({
        "'--param1 value1','--param1','value1'",
        "'\"--quoted-param\" value','--quoted-param','value'",
        "'param1 param2 param3','param1','param2'",
    })
    @DisplayName("parseAdditionalParameters with various input formats")
    void testParseAdditionalParameters_WithVariousFormats(String input, String expectedParam1, String expectedParam2) {
        List<String> result = CxConfig.parseAdditionalParameters(input);

        assertNotNull(result);
        assertTrue(result.contains(expectedParam1));
        assertTrue(result.contains(expectedParam2));
    }

    @Test
    @DisplayName("parseAdditionalParameters with null input")
    void testParseAdditionalParameters_WithNullInput_ReturnsEmptyList() {
        List<String> result = CxConfig.parseAdditionalParameters(null);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("parseAdditionalParameters with blank input")
    void testParseAdditionalParameters_WithBlankInput_ReturnsEmptyList() {
        List<String> result = CxConfig.parseAdditionalParameters("");
        assertTrue(result.isEmpty());

        result = CxConfig.parseAdditionalParameters("   ");
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("parseAdditionalParameters with quoted strings")
    void testParseAdditionalParameters_WithQuotedStrings_RemovesQuotes() {
        List<String> result = CxConfig.parseAdditionalParameters("\"--param with spaces\" \"--another param\"");

        assertNotNull(result);
        assertTrue(result.contains("--param with spaces"));
        assertTrue(result.contains("--another param"));
    }

    @Test
    @DisplayName("setAdditionalParameters delegates to parseAdditionalParameters")
    void testSetAdditionalParameters_CallsParser() {
        CxConfig config = CxConfig.builder()
            .build();

        config.setAdditionalParameters("--param1 value1");

        List<String> params = config.getAdditionalParameters();
        assertNotNull(params);
        assertTrue(params.contains("--param1"));
        assertTrue(params.contains("value1"));
    }

    @Test
    @DisplayName("builder withAdditionalParameters correctly parses parameters")
    void testBuilder_WithAdditionalParameters_ParsesCorrectly() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-key")
            .additionalParameters("--scan-type sast --incremental")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--scan-type"));
        assertTrue(args.contains("sast"));
        assertTrue(args.contains("--incremental"));
    }

    @Test
    @DisplayName("clientId and apiKey takes precedence over clientSecret")
    void testToArguments_ClientIdAndApiKeyTakePrecedenceOverSecret() {
        CxConfig config = CxConfig.builder()
            .clientId(TEST_CLIENT_ID)
            .apiKey("test-api-key-123")
            .clientSecret("should-not-be-used")
            .build();

        List<String> args = config.toArguments();

        assertTrue(args.contains("--apikey"));
        assertFalse(args.stream().anyMatch(arg -> arg.equals("--client-secret")));
    }

    @Test
    @DisplayName("agentName with empty string is not included")
    void testToArguments_WithEmptyAgentName_NotIncluded() {
        CxConfig config = CxConfig.builder()
            .apiKey("test-key")
            .agentName("")
            .build();

        List<String> args = config.toArguments();

        assertFalse(args.contains("--agent"));
    }
}
