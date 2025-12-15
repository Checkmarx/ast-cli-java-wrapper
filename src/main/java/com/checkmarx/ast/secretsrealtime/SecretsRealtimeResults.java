package com.checkmarx.ast.secretsrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
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
import java.util.Collections;
import java.util.List;

@Value
@JsonDeserialize
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecretsRealtimeResults {
    private static final Logger log = LoggerFactory.getLogger(SecretsRealtimeResults.class);

    @JsonProperty("Secrets") List<Secret> secrets;

    @JsonCreator
    public SecretsRealtimeResults(@JsonProperty("Secrets") List<Secret> secrets) {
        this.secrets = secrets == null ? Collections.emptyList() : secrets;
    }

    @Value
    @JsonDeserialize
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Secret {
        @JsonProperty("Title") String title;
        @JsonProperty("Description") String description;
        @JsonProperty("SecretValue") String secretValue;
        @JsonProperty("FilePath") String filePath;
        @JsonProperty("Severity") String severity;
        @JsonProperty("Locations") List<RealtimeLocation> locations;

        @JsonCreator
        public Secret(@JsonProperty("Title") String title,
                      @JsonProperty("Description") String description,
                      @JsonProperty("SecretValue") String secretValue,
                      @JsonProperty("FilePath") String filePath,
                      @JsonProperty("Severity") String severity,
                      @JsonProperty("Locations") List<RealtimeLocation> locations) {
            this.title = title;
            this.description = description;
            this.secretValue = secretValue;
            this.filePath = filePath;
            this.severity = severity;
            this.locations = locations == null ? Collections.emptyList() : locations;
        }
    }

    public static SecretsRealtimeResults fromLine(String line) {
        if (StringUtils.isBlank(line)) {
            return null;
        }
        try {
            if (!isValidJSON(line)) {
                return null;
            }
            ObjectMapper mapper = new ObjectMapper();
            String trimmed = line.trim();
            if (trimmed.startsWith("[")) {
                List<Secret> list = mapper.readValue(trimmed, mapper.getTypeFactory().constructCollectionType(List.class, Secret.class));
                return new SecretsRealtimeResults(list);
            }
            if (trimmed.startsWith("{")) {
                Secret single = mapper.readValue(trimmed, Secret.class);
                return new SecretsRealtimeResults(Collections.singletonList(single));
            }
        } catch (IOException e) {
            log.debug("Failed to parse secrets realtime JSON line: {}", line, e);
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

