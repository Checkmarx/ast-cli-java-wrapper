package com.checkmarx.ast.containersrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Value;

import java.util.Collections;
import java.util.List;

@Value
@JsonDeserialize
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ContainersRealtimeImage {
    @JsonProperty("ImageName") String imageName;
    @JsonProperty("ImageTag") String imageTag;
    @JsonProperty("FilePath") String filePath;
    @JsonProperty("Locations") List<RealtimeLocation> locations;
    @JsonProperty("Status") String status;
    @JsonProperty("Vulnerabilities") List<ContainersRealtimeVulnerability> vulnerabilities;

    @JsonCreator
    public ContainersRealtimeImage(@JsonProperty("ImageName") String imageName,
                                   @JsonProperty("ImageTag") String imageTag,
                                   @JsonProperty("FilePath") String filePath,
                                   @JsonProperty("Locations") List<RealtimeLocation> locations,
                                   @JsonProperty("Status") String status,
                                   @JsonProperty("Vulnerabilities") List<ContainersRealtimeVulnerability> vulnerabilities) {
        this.imageName = imageName;
        this.imageTag = imageTag;
        this.filePath = filePath;
        this.locations = locations == null ? Collections.emptyList() : locations;
        this.status = status;
        this.vulnerabilities = vulnerabilities == null ? Collections.emptyList() : vulnerabilities;
    }
}