package com.checkmarx.ast.predicate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Predicate Unit Tests")
class PredicateUnitTest {

    private static final String TEST_ID = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
    private static final String TEST_SIMILARITY_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    private static final String TEST_PROJECT_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    @Test
    @DisplayName("fromLine with valid JSON returns Predicate")
    void testFromLine_WithValidJson_ReturnsPredicate() {
        String json = "{\"ID\":\"" + TEST_ID + "\",\"SimilarityID\":\"" + TEST_SIMILARITY_ID + "\",\"ProjectID\":\"" + TEST_PROJECT_ID + "\",\"State\":\"TO_VERIFY\",\"Severity\":\"HIGH\"}";
        Predicate result = Predicate.fromLine(json);

        assertNotNull(result);
        assertEquals(TEST_ID, result.getId());
        assertEquals(TEST_SIMILARITY_ID, result.getSimilarityId());
        assertEquals(TEST_PROJECT_ID, result.getProjectId());
        assertEquals("TO_VERIFY", result.getState());
        assertEquals("HIGH", result.getSeverity());
    }

    @Test
    @DisplayName("fromLine with null input returns null")
    void testFromLine_WithNullInput_ReturnsNull() {
        Predicate result = Predicate.fromLine(null);
        assertNull(result);
    }

    @ParameterizedTest
    @DisplayName("fromLine with blank input returns null")
    @ValueSource(strings = {"", "   ", "\t"})
    void testFromLine_WithBlankInput_ReturnsNull(String input) {
        Predicate result = Predicate.fromLine(input);
        assertNull(result);
    }

    @ParameterizedTest
    @DisplayName("fromLine with invalid JSON returns null")
    @ValueSource(strings = {"{not valid}", "[{]", "not json"})
    void testFromLine_WithInvalidJson_ReturnsNull(String invalidJson) {
        Predicate result = Predicate.fromLine(invalidJson);
        assertNull(result);
    }

    @Test
    @DisplayName("listFromLine with valid JSON array returns list of Predicates")
    void testListFromLine_WithValidJsonArray_ReturnsList() {
        String json = "[{\"ID\":\"" + TEST_ID + "\",\"SimilarityID\":\"id1\",\"ProjectID\":\"proj1\",\"State\":\"OPEN\",\"Severity\":\"MEDIUM\"}," +
                      "{\"ID\":\"id2\",\"SimilarityID\":\"id2\",\"ProjectID\":\"proj2\",\"State\":\"CONFIRMED\",\"Severity\":\"HIGH\"}]";
        List<Predicate> result = Predicate.listFromLine(json);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(TEST_ID, result.get(0).getId());
        assertEquals("id2", result.get(1).getId());
    }

    @Test
    @DisplayName("listFromLine with empty array returns empty list")
    void testListFromLine_WithEmptyArray_ReturnsEmptyList() {
        List<Predicate> result = Predicate.listFromLine("[]");

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("listFromLine with null input returns null")
    void testListFromLine_WithNullInput_ReturnsNull() {
        List<Predicate> result = Predicate.listFromLine(null);
        assertNull(result);
    }

    @ParameterizedTest
    @DisplayName("listFromLine with blank input returns null")
    @ValueSource(strings = {"", "   "})
    void testListFromLine_WithBlankInput_ReturnsNull(String input) {
        List<Predicate> result = Predicate.listFromLine(input);
        assertNull(result);
    }

    @Test
    @DisplayName("listFromLine with invalid JSON returns null")
    void testListFromLine_WithInvalidJson_ReturnsNull() {
        List<Predicate> result = Predicate.listFromLine("[{invalid}]");
        assertNull(result);
    }


    @Test
    @DisplayName("fromLine with JSON containing extra fields ignores them")
    void testFromLine_WithExtraFields_IgnoresUnknownFields() {
        String json = "{\"ID\":\"" + TEST_ID + "\",\"SimilarityID\":\"id1\",\"ProjectID\":\"proj1\",\"State\":\"OPEN\",\"Severity\":\"HIGH\",\"ExtraField\":\"value\"}";
        Predicate result = Predicate.fromLine(json);

        assertNotNull(result);
        assertEquals(TEST_ID, result.getId());
    }

    @Test
    @DisplayName("listFromLine with JSON containing whitespace handles correctly")
    void testListFromLine_WithWhitespace_ParsesCorrectly() {
        String json = "  [  {\"ID\":\"" + TEST_ID + "\",\"SimilarityID\":\"id1\",\"ProjectID\":\"proj1\",\"State\":\"OPEN\",\"Severity\":\"HIGH\"}  ]  ";
        List<Predicate> result = Predicate.listFromLine(json);

        assertNotNull(result);
        assertEquals(1, result.size());
    }

    @Test
    @DisplayName("fromLine preserves all field values correctly")
    void testFromLine_PreservesAllFields() {
        String json = "{\"ID\":\"id123\",\"SimilarityID\":\"sim456\",\"ProjectID\":\"proj789\",\"State\":\"REVIEWED\",\"Severity\":\"LOW\",\"Comment\":\"Test comment\",\"CreatedBy\":\"user1\",\"CreatedAt\":\"2026-01-01T00:00:00Z\",\"UpdatedAt\":\"2026-06-14T00:00:00Z\",\"StateId\":5}";
        Predicate result = Predicate.fromLine(json);

        assertNotNull(result);
        assertEquals("id123", result.getId());
        assertEquals("sim456", result.getSimilarityId());
        assertEquals("proj789", result.getProjectId());
        assertEquals("REVIEWED", result.getState());
        assertEquals("LOW", result.getSeverity());
        assertEquals("Test comment", result.getComment());
        assertEquals("user1", result.getCreatedBy());
        assertEquals("2026-01-01T00:00:00Z", result.getCreatedAt());
        assertEquals("2026-06-14T00:00:00Z", result.getUpdatedAt());
        assertEquals(5, result.getStateId());
    }

    @Test
    @DisplayName("fromLine returns null for malformed JSON")
    void testFromLine_WithMalformedJson_ReturnsNull() {
        String json = "{\"ID\":\"id1\",\"SimilarityID\":";
        Predicate result = Predicate.fromLine(json);
        assertNull(result);
    }

    @Test
    @DisplayName("listFromLine returns null for malformed JSON array")
    void testListFromLine_WithMalformedJsonArray_ReturnsNull() {
        String json = "[{\"ID\":\"id1\"},";
        List<Predicate> result = Predicate.listFromLine(json);
        assertNull(result);
    }
}
