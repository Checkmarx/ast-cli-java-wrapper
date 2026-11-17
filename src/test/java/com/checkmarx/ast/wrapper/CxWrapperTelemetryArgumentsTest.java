package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.telemetry.TelemetryEvent;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CxWrapperTelemetryArgumentsTest {

    @Test
    void testBuildTelemetryArguments_allAttributes() {
        TelemetryEvent event = TelemetryEvent.builder()
                .aiProvider("Copilot")
                .eventType("remediation")
                .subType("fixWithAIChat")
                .engine("Oss")
                .problemSeverity("High")
                .scanType("Oss")
                .status("success")
                .statusResult("ok")
                .totalCount(3)
                .agentVersion("2024.1")
                .cxPluginVersion("2.0.1")
                .pluginType("devassist")
                .repoUrl("https://github.com/org/repo")
                .installationId("inst-1")
                .authMethod("apiKey")
                .vulnerabilityId("CVE-2024-0001")
                .remediationMode("manual")
                .aiAgentSessionId("sess-1")
                .apiVersion("v1")
                .build();

        List<String> args = CxWrapper.buildTelemetryArguments(event);

        assertEquals(Arrays.asList(
                "telemetry", "ai",
                "--ai-provider", "Copilot",
                "--type", "remediation",
                "--sub-type", "fixWithAIChat",
                "--engine", "Oss",
                "--problem-severity", "High",
                "--scan-type", "Oss",
                "--status", "success",
                "--status-result", "ok",
                "--total-count", "3",
                "--agent-version", "2024.1",
                "--cx-plugin-version", "2.0.1",
                "--plugin-type", "devassist",
                "--repo-url", "https://github.com/org/repo",
                "--installation-id", "inst-1",
                "--auth-method", "apiKey",
                "--vulnerability-id", "CVE-2024-0001",
                "--remediation-mode", "manual",
                "--ai-agent-session-id", "sess-1",
                "--api-version", "v1"), args);
    }

    @Test
    void testBuildTelemetryArguments_omitsBlankAndNullAttributes() {
        TelemetryEvent event = TelemetryEvent.builder()
                .eventType("authentication")
                .status("success")
                .engine("")
                .authMethod("  ")
                .installationId("inst-1")
                .build();

        List<String> args = CxWrapper.buildTelemetryArguments(event);

        assertEquals(Arrays.asList(
                "telemetry", "ai",
                "--type", "authentication",
                "--status", "success",
                "--installation-id", "inst-1"), args);
    }

    @Test
    void testBuildTelemetryArguments_zeroTotalCountIsSent() {
        TelemetryEvent event = TelemetryEvent.builder().totalCount(0).build();

        List<String> args = CxWrapper.buildTelemetryArguments(event);

        assertEquals(Arrays.asList("telemetry", "ai", "--total-count", "0"), args);
    }

    @Test
    void testBuildTelemetryArguments_emptyEvent() {
        List<String> args = CxWrapper.buildTelemetryArguments(TelemetryEvent.builder().build());

        assertEquals(Arrays.asList("telemetry", "ai"), args);
    }
}
