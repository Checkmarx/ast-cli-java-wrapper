package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.telemetry.TelemetryEvent;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CxWrapperTelemetryArgumentsTest {

    @Test
    void testBuildTelemetryArguments_allAttributes() {
        TelemetryEvent event = TelemetryEvent.builder()
                .aiProvider("Copilot")
                .eventType("Click")
                .subType("fixWithAIChat")
                .engine("Oss")
                .problemSeverity("High")
                .scanType("Oss")
                .status("success")
                .statusResult("ok")
                .totalCount(3)
                .agent("Eclipse")
                .agentVersion("2024.1")
                .cxPluginVersion("2.0.1")
                .pluginType("IDE")
                .repoUrl("https://github.com/org/repo")
                .apiVersion("v2")
                .eventAttribute("vulnerabilityId", "CVE-2024-0001")
                .eventAttribute("remediationMode", "DevAssist")
                .build();

        List<String> args = CxWrapper.buildTelemetryArguments(event);

        assertEquals(Arrays.asList(
                "telemetry", "ai",
                "--ai-provider", "Copilot",
                "--type", "Click",
                "--sub-type", "fixWithAIChat",
                "--engine", "Oss",
                "--problem-severity", "High",
                "--scan-type", "Oss",
                "--status", "success",
                "--status-result", "ok",
                "--total-count", "3",
                "--agent", "Eclipse",
                "--agent-version", "2024.1",
                "--cx-plugin-version", "2.0.1",
                "--plugin-type", "IDE",
                "--repo-url", "https://github.com/org/repo",
                "--api-version", "v2",
                "--event-attributes", "vulnerabilityId=CVE-2024-0001;remediationMode=DevAssist"), args);
    }

    @Test
    void testBuildTelemetryArguments_omitsBlankAndNullAttributes() {
        TelemetryEvent event = TelemetryEvent.builder()
                .eventType("authentication")
                .status("success")
                .engine("")
                .agent("  ")
                .eventAttribute("authMethod", "API_KEY")
                .eventAttribute("blank", "  ")
                .build();

        List<String> args = CxWrapper.buildTelemetryArguments(event);

        assertEquals(Arrays.asList(
                "telemetry", "ai",
                "--type", "authentication",
                "--status", "success",
                "--event-attributes", "authMethod=API_KEY"), args);
    }

    @Test
    void testBuildTelemetryArguments_noEventAttributesFlagWhenAllAttributesInvalid() {
        TelemetryEvent event = TelemetryEvent.builder()
                .eventAttribute("a", "")
                .eventAttribute("b;c", "1")
                .build();

        assertEquals(Arrays.asList("telemetry", "ai"), CxWrapper.buildTelemetryArguments(event));
    }

    @Test
    void testBuildTelemetryArguments_apiVersionIsTopLevelFlagNotAnEventAttribute() {
        TelemetryEvent event = TelemetryEvent.builder().eventType("Scan").apiVersion("v2").build();

        assertEquals(Arrays.asList("telemetry", "ai", "--type", "Scan", "--api-version", "v2"),
                CxWrapper.buildTelemetryArguments(event));
    }

    @Test
    void testBuildTelemetryArguments_blankApiVersionIsOmitted() {
        TelemetryEvent event = TelemetryEvent.builder().apiVersion(" ").build();

        assertEquals(Arrays.asList("telemetry", "ai"), CxWrapper.buildTelemetryArguments(event));
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

    @Test
    void testSerializeEventAttributes_nullAndEmpty() {
        assertEquals("", CxWrapper.serializeEventAttributes(null));
        assertEquals("", CxWrapper.serializeEventAttributes(new LinkedHashMap<>()));
    }

    @Test
    void testSerializeEventAttributes_keepsInsertionOrder() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("apiVersion", "v2");
        attributes.put("authMethod", "API_KEY");

        assertEquals("apiVersion=v2;authMethod=API_KEY", CxWrapper.serializeEventAttributes(attributes));
    }

    @Test
    void testSerializeEventAttributes_sanitizesValuesAndDropsInvalidEntries() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("vulnerabilityId", "x;y=z");
        attributes.put("empty", "");
        attributes.put("nullValue", null);
        attributes.put("d=x", "2");
        attributes.put("e;y", "3");
        attributes.put(" ", "4");

        assertEquals("vulnerabilityId=x_y=z", CxWrapper.serializeEventAttributes(attributes));
    }

    @Test
    void testConfigArguments_agentIncludedByDefault() {
        CxConfig config = CxConfig.builder().apiKey("key").agentName("Eclipse_1.0.0").build();

        assertEquals(Arrays.asList("--apikey", "key", "--agent", "Eclipse_1.0.0"), config.toArguments());
        assertEquals(config.toArguments(), config.toArguments(true));
    }

    @Test
    void testConfigArguments_agentOmittedWhenEventSendsItsOwn() {
        CxConfig config = CxConfig.builder().apiKey("key").agentName("Eclipse_1.0.0").build();

        assertEquals(Arrays.asList("--apikey", "key"), config.toArguments(false));
    }
}
