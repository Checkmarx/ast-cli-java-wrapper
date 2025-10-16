package com.checkmarx.ast.iacrealtime;

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
public class IacRealtimeResults {
    private static final Logger log = LoggerFactory.getLogger(IacRealtimeResults.class);
    @JsonProperty("Results") List<Issue> results; // Normalized list (array or single object)

    @JsonCreator
    public IacRealtimeResults(@JsonProperty("Results") List<Issue> results) {
        this.results = results == null ? Collections.emptyList() : results;
    }

    @Value
    @JsonDeserialize
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Issue {
        @JsonProperty("Title") String title;
        @JsonProperty("Description") String description;
        @JsonProperty("SimilarityID") String similarityId;
        @JsonProperty("FilePath") String filePath;
        @JsonProperty("Severity") String severity;
        @JsonProperty("ExpectedValue") String expectedValue;
        @JsonProperty("ActualValue") String actualValue;
        @JsonProperty("Locations") List<RealtimeLocation> locations;

        @JsonCreator
        public Issue(@JsonProperty("Title") String title,
                     @JsonProperty("Description") String description,
                     @JsonProperty("SimilarityID") String similarityId,
                     @JsonProperty("FilePath") String filePath,
                     @JsonProperty("Severity") String severity,
                     @JsonProperty("ExpectedValue") String expectedValue,
                     @JsonProperty("ActualValue") String actualValue,
                     @JsonProperty("Locations") List<RealtimeLocation> locations) {
            this.title = title;
            this.description = description;
            this.similarityId = similarityId;
            this.filePath = filePath;
            this.severity = severity;
            this.expectedValue = expectedValue;
            this.actualValue = actualValue;
            this.locations = locations == null ? Collections.emptyList() : locations;
        }
    }

    public static IacRealtimeResults fromLine(String line) {
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
                List<Issue> list = mapper.readValue(trimmed, mapper.getTypeFactory().constructCollectionType(List.class, Issue.class));
                return new IacRealtimeResults(list == null ? Collections.emptyList() : list);
            }
            if (trimmed.startsWith("{")) {
                Issue single = mapper.readValue(trimmed, Issue.class);
                return new IacRealtimeResults(Collections.singletonList(single));
            }
        } catch (IOException e) {
            log.debug("Failed to parse iac realtime JSON line: {}", line, e);
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