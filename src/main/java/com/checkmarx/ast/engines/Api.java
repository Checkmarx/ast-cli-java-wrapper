package com.checkmarx.ast.engines;

import com.checkmarx.ast.utils.JsonParser;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.type.TypeFactory;

import java.util.List;

public class Api {
    String apiName;
     String description;
    String apiUrl;

    public Api(
            @JsonProperty("api_name") String apiName,
            @JsonProperty("description") String description,
            @JsonProperty("api_url") String apiUrl
    ){
    this.apiName=apiName;
    this.description=description;
    this.apiUrl=apiUrl;
    }

    public static <T> T fromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructType(Api.class));
    }

    public static <T> List<T> listFromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructCollectionType(List.class, Api.class));
    }

    @Override
    public String toString() {
        return "Api{" +
                "apiName='" + apiName + '\'' +
                ", description='" + description + '\'' +
                ", apiUrl='" + apiUrl + '\'' +
                '}';
    }
}
