package com.checkmarx.ast.engines;

import com.checkmarx.ast.utils.JsonParser;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.type.TypeFactory;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;

@Getter
public class Engines {
    Engine[] enginesList;
    public Engines(
            @JsonProperty("engines") Engine[] enginesList
    ){
        this.enginesList =enginesList;
    }

    public static <T> T fromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructType(Engines.class));
    }

    public static <T> List<T> listFromLine(String line) {
        return JsonParser.parse(line, TypeFactory.defaultInstance().constructCollectionType(List.class, Engines.class));
    }

    @Override
    public String toString() {
        return "Engines{" +
                "enginesList=" + Arrays.toString(enginesList) +
                '}';
    }
}
