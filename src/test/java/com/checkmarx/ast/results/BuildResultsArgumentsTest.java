package com.checkmarx.ast.results;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.results.ReportFormat;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

class BuildResultsArgumentsTest extends BaseTest {

    @Test
    void testBuildResultsArguments_CreatesValidArguments() {
        UUID scanId = UUID.randomUUID();
        ReportFormat format = ReportFormat.json;

        List<String> arguments = wrapper.buildResultsArguments(scanId, format);
        //

        Assertions.assertNotNull(arguments, "Arguments list should not be null");
        Assertions.assertFalse(arguments.isEmpty(), "Arguments list should not be empty");
        Assertions.assertTrue(arguments.contains(scanId.toString()), "Arguments should contain scan ID");
        Assertions.assertTrue(arguments.contains(format.toString()), "Arguments should contain the report format");
    }
}
