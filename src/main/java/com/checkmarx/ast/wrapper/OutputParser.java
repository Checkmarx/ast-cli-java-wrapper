package com.checkmarx.ast.wrapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class OutputParser {
    private static final ObjectMapper mapper = new ObjectMapper();

    public CommandResponse parse(String output, int exitCode) {
        JsonNode json = null;
        String error = null;

        try {
            json = mapper.readTree(output);
        } catch (Exception ex) {
            error = "Invalid JSON output";
        }

        boolean success = (exitCode == 0);

        return new CommandResponse(
                exitCode,
                success,
                output,
                json,
                error
        );
    }
}
