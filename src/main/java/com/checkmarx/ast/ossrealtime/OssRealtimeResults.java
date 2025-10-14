package com.checkmarx.ast.ossrealtime;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.List;

@Value
@JsonDeserialize
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class OssRealtimeResults {
    @JsonProperty("Packages")
    List<OssRealtimeScanPackage> packages;

    @JsonCreator
    public OssRealtimeResults(@JsonProperty("Packages") List<OssRealtimeScanPackage> packages) {
        this.packages = packages;
    }

    public static OssRealtimeResults fromLine(String line) {
        if (StringUtils.isBlank(line)) {
            return null;
        }
        try {
            if (isValidJSON(line) && line.contains("\"Packages\"")) {
                return new ObjectMapper().readValue(line, OssRealtimeResults.class);
            }
        } catch (IOException ignored) {
        }
        return null;
    }

    private static boolean isValidJSON(String json) {
        try {
            new ObjectMapper().readTree(json);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}

