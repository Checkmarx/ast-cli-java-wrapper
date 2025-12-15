package com.checkmarx.ast;

import com.checkmarx.ast.iacrealtime.IacRealtimeResults;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class IacRealtimeResultsTest {

    @Test
    void testFromLineWithValidJsonArray() {
        String json = "[" +
                "  {" +
                "    \"Title\": \"My Issue\"," +
                "    \"Severity\": \"High\"" +
                "  }" +
                "]";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getResults().size());
        IacRealtimeResults.Issue issue = results.getResults().get(0);
        assertEquals("My Issue", issue.getTitle());
        assertEquals("High", issue.getSeverity());
    }

    @Test
    void testFromLineWithValidJsonObject() {
        String json = "{" +
                "  \"Title\": \"My Single Issue\"," +
                "  \"Severity\": \"Medium\"" +
                "}";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getResults().size());
        IacRealtimeResults.Issue issue = results.getResults().get(0);
        assertEquals("My Single Issue", issue.getTitle());
        assertEquals("Medium", issue.getSeverity());
    }

    @Test
    void testFromLineWithEmptyJsonArray() {
        String json = "[]";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertTrue(results.getResults().isEmpty());
    }

    @Test
    void testFromLineWithBlankLine() {
        assertNull(IacRealtimeResults.fromLine(""));
        assertNull(IacRealtimeResults.fromLine("  "));
        assertNull(IacRealtimeResults.fromLine(null));
    }

    @Test
    void testFromLineWithInvalidJson() {
        String json = "[{]";
        assertNull(IacRealtimeResults.fromLine(json));
    }
}

