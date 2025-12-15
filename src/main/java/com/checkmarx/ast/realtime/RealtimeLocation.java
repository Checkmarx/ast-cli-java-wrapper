package com.checkmarx.ast.realtime;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Value;

@Value
@JsonDeserialize
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RealtimeLocation {
    @JsonProperty("Line") int line;
    @JsonProperty("StartIndex") int startIndex;
    @JsonProperty("EndIndex") int endIndex;

    @JsonCreator
    public RealtimeLocation(@JsonProperty("Line") int line,
                             @JsonProperty("StartIndex") int startIndex,
                             @JsonProperty("EndIndex") int endIndex) {
        this.line = line;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
    }
}

