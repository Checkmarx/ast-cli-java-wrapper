package com.checkmarx.ast.mask;

import com.checkmarx.ast.utils.JsonParser;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.type.TypeFactory;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.Value;

import java.util.List;

@Value
@EqualsAndHashCode()
@JsonDeserialize()
@ToString(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class MaskResult {

    List<MaskedSecret> maskedSecrets;
    String maskedFile;

    @JsonCreator
    public MaskResult(@JsonProperty("maskedSecrets") List<MaskedSecret> maskedSecrets,
                     @JsonProperty("maskedFile") String maskedFile) {
        this.maskedSecrets = maskedSecrets;
        this.maskedFile = maskedFile;
    }

    public static MaskResult fromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructType(MaskResult.class));
    }
}
