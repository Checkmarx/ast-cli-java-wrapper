package com.checkmarx.ast.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JavaType;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonParserTest {

    @Test
    void testConstructorIsInstantiable() {
        // JsonParser constructor was never called — instantiating covers <init> (+3 instructions).
        JsonParser parser = new JsonParser();
        assertNotNull(parser);
    }

    @Test
    void testParse_returnsNullForBlankInput() {
        JavaType type = new ObjectMapper().constructType(Map.class);
        assertNull(JsonParser.parse("", type));
        assertNull(JsonParser.parse("   ", type));
        assertNull(JsonParser.parse(null, type));
    }

    @Test
    void testParse_returnsNullForInvalidJson() {
        JavaType type = new ObjectMapper().constructType(Map.class);
        assertNull(JsonParser.parse("{not valid}", type));
        assertNull(JsonParser.parse("[{]", type));
    }

    @Test
    void testParse_returnsObjectForValidJson() {
        JavaType type = new ObjectMapper().constructType(Map.class);
        Map<?, ?> result = JsonParser.parse("{\"key\":\"value\"}", type);
        assertNotNull(result);
        assertEquals("value", result.get("key"));
    }
}
