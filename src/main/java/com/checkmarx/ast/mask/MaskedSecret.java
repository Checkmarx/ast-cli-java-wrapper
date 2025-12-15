package com.checkmarx.ast.mask;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.Value;

@Value
@EqualsAndHashCode()
@JsonDeserialize()
@ToString(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MaskedSecret {

    String masked;
    String secret;
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
