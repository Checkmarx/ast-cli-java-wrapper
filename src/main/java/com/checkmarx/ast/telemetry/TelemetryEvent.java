package com.checkmarx.ast.telemetry;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.util.Map;

@Getter
@Builder
public class TelemetryEvent {
    private final String aiProvider;
    private final String eventType;
    private final String subType;
    private final String engine;
    private final String problemSeverity;
    private final String scanType;
    private final String status;
    private final String statusResult;
    private final Integer totalCount;
    private final String agent;
    private final String agentVersion;
    private final String cxPluginVersion;
    private final String pluginType;
    /** Must not contain credentials. */
    private final String repoUrl;
    private final String apiVersion;
    @Singular(ignoreNullCollections = true)
    private final Map<String, String> eventAttributes;
}
