package com.checkmarx.ast.containersrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class ContainersRealtimeParsingUnitTest {

    // --- ContainersRealtimeResults.fromLine ---

    @Test
    void testFromLineWithValidImagesJson() {
        String json = "{\"Images\": [{" +
                "  \"ImageName\": \"nginx\"," +
                "  \"ImageTag\": \"1.21\"," +
                "  \"FilePath\": \"/Dockerfile\"," +
                "  \"Status\": \"vulnerable\"" +
                "}]}";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertNotNull(results.getImages());
        assertEquals(1, results.getImages().size());
        ContainersRealtimeImage img = results.getImages().get(0);
        assertEquals("nginx", img.getImageName());
        assertEquals("1.21", img.getImageTag());
        assertEquals("/Dockerfile", img.getFilePath());
        assertEquals("vulnerable", img.getStatus());
    }

    @Test
    void testFromLineWithJsonWithoutImagesKey() {
        // Valid JSON but no "Images" key — contains check fails → null
        assertNull(ContainersRealtimeResults.fromLine("{\"Other\": []}"));
        assertNull(ContainersRealtimeResults.fromLine("[{\"ImageName\": \"x\"}]"));
    }

    @Test
    void testFromLineWithBlankAndNull() {
        assertNull(ContainersRealtimeResults.fromLine(""));
        assertNull(ContainersRealtimeResults.fromLine("   "));
        assertNull(ContainersRealtimeResults.fromLine(null));
    }

    @Test
    void testFromLineWithInvalidJson() {
        assertNull(ContainersRealtimeResults.fromLine("{bad"));
        assertNull(ContainersRealtimeResults.fromLine("[{]"));
    }

    @Test
    void testFromLineWithImagesKeyButMalformedJson() {
        // Contains "Images" (with quotes) so isValidJSON is called, but JSON is malformed →
        // isValidJSON catches IOException and returns false → fromLine returns null.
        // This covers the isValidJSON catch block (+3 instructions).
        assertNull(ContainersRealtimeResults.fromLine("{\"Images\": not valid json}"));
    }

    @Test
    void testFromLineWithEmptyImagesArray() {
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine("{\"Images\": []}");
        assertNotNull(results);
        assertNotNull(results.getImages());
        assertTrue(results.getImages().isEmpty());
    }

    @Test
    void testFromLineWithMultipleImages() {
        String json = "{\"Images\": [" +
                "  {\"ImageName\": \"img-a\", \"ImageTag\": \"1.0\"}," +
                "  {\"ImageName\": \"img-b\", \"ImageTag\": \"2.0\"}" +
                "]}";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(2, results.getImages().size());
        assertEquals("img-a", results.getImages().get(0).getImageName());
        assertEquals("img-b", results.getImages().get(1).getImageName());
    }

    // --- ContainersRealtimeImage constructor ---

    @Test
    void testImageConstructorWithNullCollections() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
                "ubuntu", "20.04", "/Dockerfile", null, "ok", null);
        assertEquals("ubuntu", img.getImageName());
        assertEquals("20.04", img.getImageTag());
        assertEquals("/Dockerfile", img.getFilePath());
        assertEquals("ok", img.getStatus());
        assertTrue(img.getLocations().isEmpty());
        assertTrue(img.getVulnerabilities().isEmpty());
    }

    @Test
    void testImageConstructorWithNonNullCollections() {
        RealtimeLocation loc = new RealtimeLocation(1, 0, 5);
        ContainersRealtimeVulnerability vuln = new ContainersRealtimeVulnerability(
                "CVE-2023-1234", "High");
        ContainersRealtimeImage img = new ContainersRealtimeImage(
                "alpine", "3.14", "/Dockerfile",
                Collections.singletonList(loc),
                "vulnerable",
                Collections.singletonList(vuln));
        assertEquals(1, img.getLocations().size());
        assertEquals(1, img.getLocations().get(0).getLine());
        assertEquals(1, img.getVulnerabilities().size());
        assertEquals("CVE-2023-1234", img.getVulnerabilities().get(0).getCve());
    }

    // --- ContainersRealtimeVulnerability constructor ---

    @Test
    void testVulnerabilityConstructorStoresAllFields() {
        ContainersRealtimeVulnerability vuln = new ContainersRealtimeVulnerability(
                "CVE-2022-5678", "Critical");
        assertEquals("CVE-2022-5678", vuln.getCve());
        assertEquals("Critical", vuln.getSeverity());
    }

    @Test
    void testFromLineWithVulnerabilitiesInImage() {
        String json = "{\"Images\": [{" +
                "  \"ImageName\": \"vuln-img\"," +
                "  \"ImageTag\": \"latest\"," +
                "  \"Vulnerabilities\": [{" +
                "    \"CVE\": \"CVE-2021-9876\"," +
                "    \"Severity\": \"Medium\"" +
                "  }]" +
                "}]}";
        ContainersRealtimeResults results = ContainersRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getImages().size());
        assertEquals(1, results.getImages().get(0).getVulnerabilities().size());
        ContainersRealtimeVulnerability vuln = results.getImages().get(0).getVulnerabilities().get(0);
        assertEquals("CVE-2021-9876", vuln.getCve());
        assertEquals("Medium", vuln.getSeverity());
    }
}
