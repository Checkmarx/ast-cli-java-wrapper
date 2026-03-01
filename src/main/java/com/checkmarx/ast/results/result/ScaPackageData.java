package com.checkmarx.ast.results.result;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Value;

import java.util.List;

@Value
@JsonDeserialize()
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScaPackageData {

    String Id;
    String fixLink;
    List<List<DependencyPath>> dependencyPaths;
    boolean outdated;
    boolean supportsQuickFix;
    String typeOfDependency;
    boolean isDevelopmentDependency;
    boolean isTestDependency;


    public ScaPackageData(@JsonProperty("Id") String id,
                          @JsonProperty("fixLink") String fixLink,
                          @JsonProperty("dependencyPaths") List<List<DependencyPath>> dependencyPaths,
                          @JsonProperty("outdated") boolean outdated,
                          @JsonProperty("supportsQuickFix") boolean supportsQuickFix,
                          @JsonProperty("typeOfDependency") String typeOfDependency,
                          @JsonProperty("isDevelopmentDependency") boolean isDevelopmentDependency,
                          @JsonProperty("isTestDependency") boolean isTestDependency) {

        Id = id;
        this.fixLink = fixLink;
        this.dependencyPaths = dependencyPaths;
        this.outdated = outdated;
        this.supportsQuickFix = supportsQuickFix;
        this.typeOfDependency = typeOfDependency;
        this.isDevelopmentDependency = isDevelopmentDependency;
        this.isTestDependency = isTestDependency;
    }
}
