package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.results.ReportFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CxWrapperArgumentsTest {

    private static final String EXECUTABLE = "dummy-cx";
    private static final UUID TEST_SCAN_ID =
            UUID.fromString("3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e");

    private CxWrapper wrapper;

    @BeforeEach
    void setUp() throws IOException {
        // Non-blank pathToExecutable skips getTempBinary() in the constructor
        CxConfig config = CxConfig.builder()
                .pathToExecutable(EXECUTABLE)
                .build();
        wrapper = new CxWrapper(config);
    }

    // --- buildScanCreateArguments ---

    @Test
    void testBuildScanCreateArguments_containsRequiredTokens() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("--project-name", "my-project");

        List<String> args = wrapper.buildScanCreateArguments(params, "");

        assertTrue(args.contains(EXECUTABLE), "list must start with executable");
        assertTrue(args.contains("scan"), "must contain 'scan' command");
        assertTrue(args.contains("create"), "must contain 'create' subcommand");
        assertTrue(args.contains("--scan-info-format"), "must contain format flag");
        assertTrue(args.contains("json"), "must contain format value");
        assertTrue(args.contains("--project-name"), "must contain param key");
        assertTrue(args.contains("my-project"), "must contain param value");
        assertEquals(EXECUTABLE, args.get(0), "executable must be first element");
    }

    @Test
    void testBuildScanCreateArguments_withAdditionalParameters() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("--source-type", "git");

        List<String> args = wrapper.buildScanCreateArguments(params, "--sast-preset-name \"custom preset\"");

        assertTrue(args.contains("--sast-preset-name"), "additional param key must be present");
        assertTrue(args.contains("custom preset"), "additional param value (quotes stripped) must be present");
    }

    @Test
    void testBuildScanCreateArguments_withNullAdditionalParameters() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("--branch", "main");

        // Should not throw — parseAdditionalParameters handles null gracefully
        List<String> args = assertDoesNotThrow(() ->
                wrapper.buildScanCreateArguments(params, null));
        assertNotNull(args);
        assertTrue(args.contains("--branch"));
        assertTrue(args.contains("main"));
    }

    @Test
    void testBuildScanCreateArguments_withEmptyParamsMap() {
        List<String> args = wrapper.buildScanCreateArguments(Map.of(), "");

        // Core tokens still present even with no params
        assertTrue(args.contains("scan"));
        assertTrue(args.contains("create"));
        assertTrue(args.contains("--scan-info-format"));
        assertTrue(args.contains("json"));
    }

    @Test
    void testBuildScanCreateArguments_executableIsFirst() {
        List<String> args = wrapper.buildScanCreateArguments(Map.of(), "");
        assertEquals(EXECUTABLE, args.get(0));
    }

    @Test
    void testBuildScanCreateArguments_multipleParamsAllPresent() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("--project-name", "proj");
        params.put("--branch", "develop");
        params.put("--scan-types", "sast,iac-security");

        List<String> args = wrapper.buildScanCreateArguments(params, "");

        assertTrue(args.contains("--project-name") && args.contains("proj"));
        assertTrue(args.contains("--branch") && args.contains("develop"));
        assertTrue(args.contains("--scan-types") && args.contains("sast,iac-security"));
    }

    // --- buildScanCancelArguments ---

    @Test
    void testBuildScanCancelArguments_containsRequiredTokens() {
        List<String> args = wrapper.buildScanCancelArguments(TEST_SCAN_ID);

        assertEquals(EXECUTABLE, args.get(0));
        assertTrue(args.contains("scan"));
        assertTrue(args.contains("cancel"));
        assertTrue(args.contains("--scan-id"));
        assertTrue(args.contains(TEST_SCAN_ID.toString()));
    }

    @Test
    void testBuildScanCancelArguments_scanIdIsCorrect() {
        UUID id = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        List<String> args = wrapper.buildScanCancelArguments(id);
        assertTrue(args.contains(id.toString()));
    }

    // --- buildResultsArguments ---

    @Test
    void testBuildResultsArguments_jsonFormat() {
        List<String> args = wrapper.buildResultsArguments(TEST_SCAN_ID, ReportFormat.json);

        assertEquals(EXECUTABLE, args.get(0));
        assertTrue(args.contains("results"));
        assertTrue(args.contains("show"));
        assertTrue(args.contains("--scan-id"));
        assertTrue(args.contains(TEST_SCAN_ID.toString()));
        assertTrue(args.contains("--report-format"));
        assertTrue(args.contains(ReportFormat.json.toString()));
    }

    @Test
    void testBuildResultsArguments_summaryJsonFormat() {
        List<String> args = wrapper.buildResultsArguments(TEST_SCAN_ID, ReportFormat.summaryJSON);

        assertTrue(args.contains(ReportFormat.summaryJSON.toString()));
        assertFalse(args.contains(ReportFormat.json.toString()),
                "summaryJSON and json are distinct format strings");
    }

    @Test
    void testBuildResultsArguments_sarifFormat() {
        List<String> args = wrapper.buildResultsArguments(TEST_SCAN_ID, ReportFormat.sarif);
        assertTrue(args.contains(ReportFormat.sarif.toString()));
    }
}
