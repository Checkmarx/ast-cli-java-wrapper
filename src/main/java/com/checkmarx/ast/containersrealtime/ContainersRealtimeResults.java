package com.checkmarx.ast.containersrealtime;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

@Value
@JsonDeserialize
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ContainersRealtimeResults {
    private static final Logger log = LoggerFactory.getLogger(ContainersRealtimeResults.class);

    @JsonProperty("Images") List<ContainersRealtimeImage> images;

    @JsonCreator
    public ContainersRealtimeResults(@JsonProperty("Images") List<ContainersRealtimeImage> images) {
        this.images = images;
    }

    public static ContainersRealtimeResults fromLine(String line) {
        if (StringUtils.isBlank(line)) {
            return null;
        }
        try {
            if (line.contains("\"Images\"") && isValidJSON(line)) {
                return new ObjectMapper().readValue(line, ContainersRealtimeResults.class);
            }
        } catch (IOException e) {
            log.debug("Failed to parse containers realtime line: {}", line, e);
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
