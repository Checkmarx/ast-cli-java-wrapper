package com.checkmarx.ast.telemetry;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.util.Map;

/**
 * Attributes of a Dev Assist telemetry event sent through {@code cx telemetry ai}.
 * <p>
 * Only non-blank values are forwarded to the CLI. The CLI itself adds the session, unique and machine identifiers.
 * Event specific values (for example {@code installationId}, {@code authMethod}, {@code vulnerabilityId},
 * {@code remediationMode}) go in {@link #eventAttributes} and are sent as a single
 * {@code --event-attributes "key=value;key=value"} argument, which the CLI nests under {@code eventAttributes}.
 */
@Getter
@Builder
public class TelemetryEvent {
    /** AI provider name (e.g. "Copilot"). */
    private final String aiProvider;
    /** Event type (e.g. "click", "authentication", "Scan"). */
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
    /**
     * IDE or agent name (e.g. "Eclipse"). When set, it is sent as {@code --agent} and replaces
     * {@code CxConfig#getAgentName()} for this call. When blank, the configured agent name is used.
     */
    private final String agent;
    /** Version of the host IDE / agent. */
    private final String agentVersion;
    /** Version of the Checkmarx plugin. */
    private final String cxPluginVersion;
    /** Plugin type (e.g. "IDE"). */
    private final String pluginType;
    /** Repository URL of the scanned project. */
    private final String repoUrl;
    /** Telemetry API version (e.g. "v2"). Sent as the top-level {@code --api-version} flag, like the JavaScript wrapper. */
    private final String apiVersion;
    /**
     * Event specific attributes, sent as {@code --event-attributes key=value;key=value}.
     * Entries with a blank value or an invalid key (blank, or containing ';' or '=') are left out,
     * and ';' inside a value is replaced with '_'.
     */
    @Singular
    private final Map<String, String> eventAttributes;
}
