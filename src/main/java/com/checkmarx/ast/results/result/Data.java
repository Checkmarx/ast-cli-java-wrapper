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
public class Data {

    String queryId;
    String queryName;
    String group;
    String resultHash;
    String languageName;
    String platform;
    String issueType;
    String expectedValue;
    String value;
    String fileName;
    String packageIdentifier;
    String recommendedVersion;
    int line;
    List<Node> nodes;
    List<PackageData> packageData;
    ScaPackageData scaPackageData;
    // Secret Detection specific fields
    String ruleName;
    String ruleDescription;
    String remediation;

    public Data(@JsonProperty("queryId") String queryId,
                @JsonProperty("queryName") String queryName,
                @JsonProperty("group") String group,
                @JsonProperty("resultHash") String resultHash,
                @JsonProperty("languageName") String languageName,
                @JsonProperty("platform") String platform,
                @JsonProperty("issueType") String issueType,
                @JsonProperty("expectedValue") String expectedValue,
                @JsonProperty("value") String value,
                @JsonProperty("filename") String fileName,
                @JsonProperty("packageIdentifier") String packageIdentifier,
                @JsonProperty("recommendedVersion") String recommendedVersion,
                @JsonProperty("line") int line,
                @JsonProperty("nodes") List<Node> nodes,
                @JsonProperty("packageData") List<PackageData> packageData,
                @JsonProperty("scaPackageData") ScaPackageData scaPackageData,
                @JsonProperty("ruleName") String ruleName,
                @JsonProperty("ruleDescription") String ruleDescription,
                @JsonProperty("remediation") String remediation) {
        this.queryId = queryId;
        this.queryName = queryName;
        this.group = group;
        this.resultHash = resultHash;
        this.languageName = languageName;
        this.platform = platform;
        this.issueType = issueType;
        this.expectedValue = expectedValue;
        this.value = value;
        this.fileName = fileName;
        this.packageIdentifier = packageIdentifier;
        this.recommendedVersion = recommendedVersion;
        this.line = line;
        this.nodes = nodes;
        this.packageData = packageData;
        this.scaPackageData = scaPackageData;
        this.ruleName = ruleName;
        this.ruleDescription = ruleDescription;
        this.remediation = remediation;
    }
}
