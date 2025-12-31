package com.checkmarx.ast;

import com.checkmarx.ast.wrapper.CxException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * Telemetry AI event test cases covering various parameter scenarios.
 */
class TelemetryTest extends BaseTest {

    @Test
    void testTelemetryAIEventSuccessfulCaseWithMinimalParametersAiLog() throws CxException, IOException, InterruptedException {
        // Test case: AI logging with specific parameters and some empty values
        Assertions.assertDoesNotThrow(() -> {
            String result = wrapper.telemetryAIEvent(
                    "Copilot",                         // aiProvider
                    "JetBrains IntelliJ IDEA",                  // agent
                    "click",                                    // eventType
                    "viewDetails",                              // subType
                    "secrets",                                  // engine
                    "high",                                     // problemSeverity
                    "",                                         // scanType (empty)
                    "",                                         // status (empty)
                    0                                           // totalCount
            );
        }, "Telemetry AI event should execute successfully");
    }

    @Test
    void testTelemetryAIEventSuccessfulCaseWithMinimalParametersDetectionLog() throws CxException, IOException, InterruptedException {
        // Test case: Detection logging with most parameters empty and specific scan data
        Assertions.assertDoesNotThrow(() -> {
            String result = wrapper.telemetryAIEvent(
                    "",                                // aiProvider (empty)
                    "",                                         // agent (empty)
                    "",                                         // eventType (empty)
                    "",                                         // subType (empty)
                    "",                                         // engine (empty)
                    "",                                         // problemSeverity (empty)
                    "asca",                                     // scanType
                    "Critical",                                 // status
                    10                                          // totalCount
            );
        }, "Telemetry AI event should execute successfully for detection log");
    }

    @Test
    void testTelemetryAIEventSuccessfulCaseWithEdgeCaseParameters() throws CxException, IOException, InterruptedException {
        // Test case: Edge case with minimal required parameters
        Assertions.assertDoesNotThrow(() -> {
            String result = wrapper.telemetryAIEvent(
                    "test-provider",                   // aiProvider (minimal value)
                    "java-wrapper",                             // agent (minimal value)
                    "",                                         // eventType (empty)
                    "",                                         // subType (empty)
                    "",                                         // engine (empty)
                    "",                                         // problemSeverity (empty)
                    "",                                         // scanType (empty)
                    "",                                         // status (empty)
                    0                                           // totalCount
            );
        }, "Telemetry AI event should execute successfully for edge case");
    }
}