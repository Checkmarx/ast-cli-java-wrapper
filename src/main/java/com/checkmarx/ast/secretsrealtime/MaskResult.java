package com.checkmarx.ast.secretsrealtime;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents the result of a mask secrets command operation.
 * Contains masked secrets and the masked file content.
 * This is separate from realtime scanning results.
 */
@Value
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MaskResult {
    private static final Logger log = LoggerFactory.getLogger(MaskResult.class);

    /**
     * List of masked secrets found in the file
     */
    @JsonProperty("maskedSecrets")
    List<MaskedSecret> maskedSecrets;

    /**
     * The masked file content with secrets redacted
     */
    @JsonProperty("maskedFile")
    String maskedFile;

    @JsonCreator
    public MaskResult(@JsonProperty("maskedSecrets") List<MaskedSecret> maskedSecrets,
                     @JsonProperty("maskedFile") String maskedFile) {
        this.maskedSecrets = maskedSecrets == null ? Collections.emptyList() : maskedSecrets;
        this.maskedFile = maskedFile;
    }

    /**
     * Parses mask command output from JSON response
     * @param root JsonNode containing the mask command response
     * @return MaskResult object with parsed data
     */
    public static MaskResult parse(JsonNode root) {
        if (root == null) {
            return new MaskResult(Collections.emptyList(), "");
        }

        List<MaskedSecret> secrets = new ArrayList<>();
        JsonNode maskedSecretsNode = root.get("maskedSecrets");

        if (maskedSecretsNode != null && maskedSecretsNode.isArray()) {
            for (JsonNode secretNode : maskedSecretsNode) {
                String masked = secretNode.has("masked") ? secretNode.get("masked").asText() : "";
                String secret = secretNode.has("secret") ? secretNode.get("secret").asText() : "";
                int line = secretNode.has("line") ? secretNode.get("line").asInt() : 0;

                secrets.add(new MaskedSecret(masked, secret, line));
            }
        }

        String maskedFile = root.has("maskedFile") ? root.get("maskedFile").asText() : "";

        return new MaskResult(secrets, maskedFile);
    }

    /**
     * Parses mask command output from JSON string
     * @param jsonString JSON string containing the mask command response
     * @return MaskResult object with parsed data, or null if parsing fails
     */
    public static MaskResult fromJsonString(String jsonString) {
        if (StringUtils.isBlank(jsonString)) {
            return null;
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(jsonString.trim());
            return parse(root);
        } catch (IOException e) {
            log.debug("Failed to parse mask result JSON: {}", jsonString, e);
            return null;
        }
    }
}
