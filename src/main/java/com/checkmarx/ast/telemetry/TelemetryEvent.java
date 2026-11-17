package com.checkmarx.ast.telemetry;

import lombok.Builder;
import lombok.Getter;

/**
 * Attributes of a Dev Assist telemetry event sent through {@code cx telemetry ai}.
 * <p>
 * Only non-blank values are forwarded to the CLI. The CLI itself adds the session, unique and machine identifiers.
 * The agent name is taken from the wrapper configuration ({@code CxConfig#getAgentName()}).
 */
@Getter
@Builder
public class TelemetryEvent {
    /** AI provider name (e.g. "Copilot"). */
    private final String aiProvider;
    /** Event type (e.g. "click", "authentication", "installation", "scan", "remediation"). */
    private final String eventType;
    /** Event sub type (e.g. "fixWithAIChat"). */
    private final String subType;
    /** Scan engine (e.g. "Oss", "Secrets", "IaC", "Asca", "Containers"). */
    private final String engine;
    /** Severity of the problem the event relates to. */
    private final String problemSeverity;
    /** Scan type for scan events. */
    private final String scanType;
    /** Event status (e.g. "success"). */
    private final String status;
    /** Detailed status / failure reason. */
    private final String statusResult;
    /** Number of findings, sent only when not null. */
    private final Integer totalCount;
    /** Version of the host IDE / agent. */
    private final String agentVersion;
    /** Version of the Checkmarx plugin. */
    private final String cxPluginVersion;
    /** Plugin type (e.g. "checkmarx", "devassist"). */
    private final String pluginType;
    /** Repository URL of the scanned project. */
    private final String repoUrl;
    /** Plugin installation identifier. */
    private final String installationId;
    /** Authentication method (e.g. "apiKey", "oauth"). */
    private final String authMethod;
    /** Identifier of the vulnerability being remediated. */
    private final String vulnerabilityId;
    /** Remediation mode. */
    private final String remediationMode;
    /** Identifier of the AI agent session. */
    private final String aiAgentSessionId;
    /** API version of the event schema. */
    private final String apiVersion;
}
