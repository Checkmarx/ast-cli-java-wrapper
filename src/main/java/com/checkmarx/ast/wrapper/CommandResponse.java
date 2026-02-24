package com.checkmarx.ast.wrapper;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;

@Getter
public class CommandResponse {

    public final int exitCode;
    public final boolean success;
    public final String rawOutput;
    public final JsonNode jsonOutput;
    public final String errorMessage;

    public CommandResponse(
            int exitCode,
            boolean success,
            String rawOutput,
            JsonNode jsonOutput,
            String errorMessage
    ) {
        this.exitCode = exitCode;
        this.success = success;
        this.rawOutput = rawOutput;
        this.jsonOutput = jsonOutput;
        this.errorMessage = errorMessage;
    }
}
