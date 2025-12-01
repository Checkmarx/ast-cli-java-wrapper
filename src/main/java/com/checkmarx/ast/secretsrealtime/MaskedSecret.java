package com.checkmarx.ast.secretsrealtime;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Value;

/**
 * Represents a single masked secret from the mask command output.
 * This is used for the separate mask functionality (not realtime scan results).
 */
@Value
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MaskedSecret {

    /**
     * The masked/redacted version of the secret
     */
    @JsonProperty("masked")
    String masked;

    /**
     * The original secret value (may be empty for security reasons)
     */
    @JsonProperty("secret")
    String secret;

    /**
     * Line number where the secret was found
     */
    @JsonProperty("line")
    int line;

    @JsonCreator
    public MaskedSecret(@JsonProperty("masked") String masked,
                       @JsonProperty("secret") String secret,
                       @JsonProperty("line") int line) {
        this.masked = masked;
        this.secret = secret;
        this.line = line;
    }
}
