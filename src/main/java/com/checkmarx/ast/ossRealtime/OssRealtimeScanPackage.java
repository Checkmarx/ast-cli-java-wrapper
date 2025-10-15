package com.checkmarx.ast.ossRealtime;

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
public class OssRealtimeScanPackage {
    @JsonProperty("PackageManager")
    String packageManager;
    @JsonProperty("PackageName")
    String packageName;
    @JsonProperty("PackageVersion")
    String packageVersion;
    @JsonProperty("FilePath")
    String filePath;
    @JsonProperty("Locations")
    List<RealtimeLocation> locations;
    @JsonProperty("Status")
    String status;
    @JsonProperty("Vulnerabilities")
    List<OssRealtimeVulnerability> vulnerabilities;

    @JsonCreator
    public OssRealtimeScanPackage(@JsonProperty("PackageManager") String packageManager,
                                  @JsonProperty("PackageName") String packageName,
                                  @JsonProperty("PackageVersion") String packageVersion,
                                  @JsonProperty("FilePath") String filePath,
                                  @JsonProperty("Locations") List<RealtimeLocation> locations,
                                  @JsonProperty("Status") String status,
                                  @JsonProperty("Vulnerabilities") List<OssRealtimeVulnerability> vulnerabilities) {
        this.packageManager = packageManager;
        this.packageName = packageName;
        this.packageVersion = packageVersion;
        this.filePath = filePath;
        this.locations = locations == null ? Collections.emptyList() : locations;
        this.status = status;
        this.vulnerabilities = vulnerabilities == null ? Collections.emptyList() : vulnerabilities;
    }
}
