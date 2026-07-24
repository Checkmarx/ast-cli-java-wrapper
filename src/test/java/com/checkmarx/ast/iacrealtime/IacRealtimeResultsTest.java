package com.checkmarx.ast.iacrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("IacRealtimeResults Tests")
class IacRealtimeResultsTest {

    // ===== IacRealtimeResults (Container) Tests =====

    @Test
    @DisplayName("Constructor with null results initializes empty list")
    void testConstructor_NullResults() {
        IacRealtimeResults results = new IacRealtimeResults(null);
        assertNotNull(results.getResults());
        assertTrue(results.getResults().isEmpty());
    }

    @Test
    @DisplayName("Constructor with empty list initializes correctly")
    void testConstructor_EmptyList() {
        List<IacRealtimeResults.Issue> emptyList = new ArrayList<>();
        IacRealtimeResults results = new IacRealtimeResults(emptyList);
        assertNotNull(results.getResults());
        assertTrue(results.getResults().isEmpty());
    }

    @Test
    @DisplayName("Constructor with issues preserves list")
    void testConstructor_WithIssues() {
        List<IacRealtimeResults.Issue> issues = createIssues(2);
        IacRealtimeResults results = new IacRealtimeResults(issues);
        assertEquals(2, results.getResults().size());
        assertEquals("Issue 1", results.getResults().get(0).getTitle());
    }

    @Test
    @DisplayName("fromLine with valid JSON array")
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
    @DisplayName("fromLine with valid JSON object")
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
    @DisplayName("fromLine with empty JSON array")
    void testFromLineWithEmptyJsonArray() {
        String json = "[]";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertTrue(results.getResults().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\n", "\t"})
    @DisplayName("fromLine with blank inputs returns null")
    void testFromLineWithBlankInputs(String blankInput) {
        assertNull(IacRealtimeResults.fromLine(blankInput));
    }

    @Test
    @DisplayName("fromLine with null returns null")
    void testFromLineWithNull() {
        assertNull(IacRealtimeResults.fromLine(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"[{]", "{invalid", "not json", "{\"unclosed\": "})
    @DisplayName("fromLine with invalid JSON returns null")
    void testFromLineWithInvalidJson(String invalidJson) {
        assertNull(IacRealtimeResults.fromLine(invalidJson));
    }

    @Test
    @DisplayName("fromLine with multiple issues in array")
    void testFromLineWithMultipleIssues() {
        String json = "[" +
                "{\"Title\":\"Issue1\",\"Severity\":\"High\"}," +
                "{\"Title\":\"Issue2\",\"Severity\":\"Medium\"}," +
                "{\"Title\":\"Issue3\",\"Severity\":\"Low\"}" +
                "]";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertEquals(3, results.getResults().size());
        assertEquals("Issue1", results.getResults().get(0).getTitle());
        assertEquals("Issue2", results.getResults().get(1).getTitle());
        assertEquals("Issue3", results.getResults().get(2).getTitle());
    }

    // ===== Issue Inner Class Tests =====

    @Test
    @DisplayName("Issue constructor with all fields")
    void testIssueConstructor_AllFields() {
        List<RealtimeLocation> locations = createLocations(1);
        IacRealtimeResults.Issue issue = new IacRealtimeResults.Issue(
                "Test Title",
                "Test Description",
                "SIM123",
                "/path/to/file",
                "High",
                "expected",
                "actual",
                locations
        );
        assertEquals("Test Title", issue.getTitle());
        assertEquals("Test Description", issue.getDescription());
        assertEquals("SIM123", issue.getSimilarityId());
        assertEquals("/path/to/file", issue.getFilePath());
        assertEquals("High", issue.getSeverity());
        assertEquals("expected", issue.getExpectedValue());
        assertEquals("actual", issue.getActualValue());
        assertEquals(1, issue.getLocations().size());
    }

    @Test
    @DisplayName("Issue constructor with null locations initializes empty list")
    void testIssueConstructor_NullLocations() {
        IacRealtimeResults.Issue issue = new IacRealtimeResults.Issue(
                "Title", "Description", "SIM", "path", "High", "exp", "act", null
        );
        assertNotNull(issue.getLocations());
        assertTrue(issue.getLocations().isEmpty());
    }

    @Test
    @DisplayName("Issue getters return correct values")
    void testIssueGetters() {
        IacRealtimeResults.Issue issue = new IacRealtimeResults.Issue(
                "Title123", "Desc456", "SIMID", "/file.tf", "Critical", "true", "false", null
        );
        assertEquals("Title123", issue.getTitle());
        assertEquals("Desc456", issue.getDescription());
        assertEquals("SIMID", issue.getSimilarityId());
        assertEquals("/file.tf", issue.getFilePath());
        assertEquals("Critical", issue.getSeverity());
        assertEquals("true", issue.getExpectedValue());
        assertEquals("false", issue.getActualValue());
    }

    @Test
    @DisplayName("Issue with null fields")
    void testIssueWithNullFields() {
        IacRealtimeResults.Issue issue = new IacRealtimeResults.Issue(
                null, null, null, null, null, null, null, null
        );
        assertNull(issue.getTitle());
        assertNull(issue.getDescription());
        assertNull(issue.getSimilarityId());
        assertNull(issue.getFilePath());
        assertNull(issue.getSeverity());
        assertNull(issue.getExpectedValue());
        assertNull(issue.getActualValue());
        assertNotNull(issue.getLocations());
    }

    @Test
    @DisplayName("Issue equals comparison with identical objects")
    void testIssueEquals_SameValues() {
        IacRealtimeResults.Issue issue1 = createIssue("Title", "Desc", "SIM");
        IacRealtimeResults.Issue issue2 = createIssue("Title", "Desc", "SIM");
        assertEquals(issue1, issue2);
    }

    @Test
    @DisplayName("Issue equals comparison with different values")
    void testIssueEquals_DifferentValues() {
        IacRealtimeResults.Issue issue1 = createIssue("Title1", "Desc", "SIM");
        IacRealtimeResults.Issue issue2 = createIssue("Title2", "Desc", "SIM");
        assertNotEquals(issue1, issue2);
    }

    @Test
    @DisplayName("Issue hashCode consistency")
    void testIssueHashCode_Consistency() {
        IacRealtimeResults.Issue issue1 = createIssue("Title", "Desc", "SIM");
        IacRealtimeResults.Issue issue2 = createIssue("Title", "Desc", "SIM");
        assertEquals(issue1.hashCode(), issue2.hashCode());
    }

    @ParameterizedTest
    @CsvSource({
        "Low, Medium, false",
        "High, High, true",
        "Critical, Medium, false"
    })
    @DisplayName("Issue severity comparison")
    void testIssueSeverity(String sev1, String sev2, boolean shouldBeEqual) {
        IacRealtimeResults.Issue issue1 = createIssueWithSeverity(sev1);
        IacRealtimeResults.Issue issue2 = createIssueWithSeverity(sev2);
        if (shouldBeEqual) {
            assertEquals(issue1, issue2);
        } else {
            assertNotEquals(issue1, issue2);
        }
    }

    @Test
    @DisplayName("Issue with multiple locations")
    void testIssueWithMultipleLocations() {
        List<RealtimeLocation> locations = createLocations(3);
        IacRealtimeResults.Issue issue = new IacRealtimeResults.Issue(
                "Title", null, null, "/file", "High", null, null, locations
        );
        assertEquals(3, issue.getLocations().size());
    }

    @Test
    @DisplayName("fromLine with issue containing all fields")
    void testFromLineWithCompleteIssue() {
        String json = "{" +
                "\"Title\":\"Terraform Security Issue\"," +
                "\"Description\":\"S3 bucket not encrypted\"," +
                "\"SimilarityID\":\"SIM001\"," +
                "\"FilePath\":\"/terraform/main.tf\"," +
                "\"Severity\":\"High\"," +
                "\"ExpectedValue\":\"encryption_enabled=true\"," +
                "\"ActualValue\":\"encryption_enabled=false\"," +
                "\"Locations\":[{\"Line\":10,\"StartIndex\":5,\"EndIndex\":20}]" +
                "}";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        IacRealtimeResults.Issue issue = results.getResults().get(0);
        assertEquals("Terraform Security Issue", issue.getTitle());
        assertEquals("S3 bucket not encrypted", issue.getDescription());
        assertEquals("SIM001", issue.getSimilarityId());
        assertEquals("/terraform/main.tf", issue.getFilePath());
        assertEquals("High", issue.getSeverity());
        assertEquals("encryption_enabled=true", issue.getExpectedValue());
        assertEquals("encryption_enabled=false", issue.getActualValue());
        assertEquals(1, issue.getLocations().size());
    }

    @Test
    @DisplayName("fromLine preserves empty values in JSON")
    void testFromLineWithEmptyFields() {
        String json = "{\"Title\":\"\",\"FilePath\":\"\"}";
        IacRealtimeResults results = IacRealtimeResults.fromLine(json);
        assertNotNull(results);
        IacRealtimeResults.Issue issue = results.getResults().get(0);
        assertEquals("", issue.getTitle());
        assertEquals("", issue.getFilePath());
    }

    // ===== Helper Methods =====

    private List<IacRealtimeResults.Issue> createIssues(int count) {
        List<IacRealtimeResults.Issue> issues = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            issues.add(createIssue("Issue " + i, "Description " + i, "SIM" + i));
        }
        return issues;
    }

    private IacRealtimeResults.Issue createIssue(String title, String desc, String simId) {
        return new IacRealtimeResults.Issue(title, desc, simId, "/file", "High", null, null, null);
    }

    private IacRealtimeResults.Issue createIssueWithSeverity(String severity) {
        return new IacRealtimeResults.Issue("Title", null, "SIM", "/file", severity, null, null, null);
    }

    private List<RealtimeLocation> createLocations(int count) {
        List<RealtimeLocation> locations = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            locations.add(new RealtimeLocation(i, i * 5, i * 10));
        }
        return locations;
    }
}

