package com.checkmarx.ast.engines;

import com.checkmarx.ast.utils.JsonParser;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.type.TypeFactory;

import java.util.Arrays;
import java.util.List;

public class Engine {
    String engineName;
    String engineId;
    Api[] apis;

    public Engine(
            @JsonProperty("engine_name") String engineName,
            @JsonProperty("engine_id") String engineId,
            @JsonProperty("apis") Api[] apis
    ){
        this.engineId=engineId;
        this.engineName=engineName;
        this.apis=apis;
    }

    public static <T> T fromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructType(Engine.class));
    }

    public static <T> List<T> listFromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructCollectionType(List.class, Engine.class));
    }

    @Override
    public String toString() {
        return "Engine{" +
                "engineName='" + engineName + '\'' +
                ", engineId='" + engineId + '\'' +
                ", apis=" + Arrays.toString(apis) +
                '}';
    }
}
