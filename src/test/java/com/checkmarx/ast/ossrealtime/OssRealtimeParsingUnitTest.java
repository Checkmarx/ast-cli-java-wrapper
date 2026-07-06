package com.checkmarx.ast.ossrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class OssRealtimeParsingUnitTest {

    // --- OssRealtimeResults.fromLine ---

    @Test
    void testFromLineWithValidPackagesJson() {
        String json = "{\"Packages\": [{" +
                "  \"PackageManager\": \"npm\"," +
                "  \"PackageName\": \"lodash\"," +
                "  \"PackageVersion\": \"4.17.15\"," +
                "  \"FilePath\": \"/package.json\"," +
                "  \"Status\": \"vulnerable\"" +
                "}]}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getPackages().size());
        OssRealtimeScanPackage pkg = results.getPackages().get(0);
        assertEquals("npm", pkg.getPackageManager());
        assertEquals("lodash", pkg.getPackageName());
        assertEquals("4.17.15", pkg.getPackageVersion());
        assertEquals("/package.json", pkg.getFilePath());
        assertEquals("vulnerable", pkg.getStatus());
    }

    @Test
    void testFromLineWithJsonWithoutPackagesKey() {
        // Valid JSON but no "Packages" key — isValidJSON passes but contains check fails → null
        assertNull(OssRealtimeResults.fromLine("{\"Other\": []}"));
        assertNull(OssRealtimeResults.fromLine("[{\"PackageName\": \"x\"}]"));
    }

    @Test
    void testFromLineWithBlankAndNull() {
        assertNull(OssRealtimeResults.fromLine(""));
        assertNull(OssRealtimeResults.fromLine("   "));
        assertNull(OssRealtimeResults.fromLine(null));
    }

    @Test
    void testFromLineWithInvalidJson() {
        assertNull(OssRealtimeResults.fromLine("{bad json"));
        assertNull(OssRealtimeResults.fromLine("[{]"));
    }

    @Test
    void testFromLineWithEmptyPackagesArray() {
        OssRealtimeResults results = OssRealtimeResults.fromLine("{\"Packages\": []}");
        assertNotNull(results);
        assertTrue(results.getPackages().isEmpty());
    }

    @Test
    void testConstructorWithNullPackages() {
        OssRealtimeResults results = new OssRealtimeResults(null);
        assertNotNull(results);
        assertTrue(results.getPackages().isEmpty());
    }

    // --- OssRealtimeScanPackage constructor ---

    @Test
    void testScanPackageConstructorWithNullCollections() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
                "maven", "spring-core", "5.3.0", "/pom.xml", null, "ok", null);
        assertTrue(pkg.getLocations().isEmpty());
        assertTrue(pkg.getVulnerabilities().isEmpty());
        assertEquals("maven", pkg.getPackageManager());
        assertEquals("spring-core", pkg.getPackageName());
        assertEquals("5.3.0", pkg.getPackageVersion());
        assertEquals("/pom.xml", pkg.getFilePath());
        assertEquals("ok", pkg.getStatus());
    }

    @Test
    void testScanPackageConstructorWithNonNullCollections() {
        RealtimeLocation loc = new RealtimeLocation(3, 0, 5);
        OssRealtimeVulnerability vuln = new OssRealtimeVulnerability(
                "CVE-2021-1234", "High", "desc", "5.3.1");
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
                "npm", "axios", "0.21.0", "/package.json",
                Collections.singletonList(loc), "vulnerable",
                Collections.singletonList(vuln));
        assertEquals(1, pkg.getLocations().size());
        assertEquals(3, pkg.getLocations().get(0).getLine());
        assertEquals(1, pkg.getVulnerabilities().size());
        assertEquals("CVE-2021-1234", pkg.getVulnerabilities().get(0).getCve());
    }

    // --- OssRealtimeVulnerability constructor ---

    @Test
    void testVulnerabilityConstructorStoresAllFields() {
        OssRealtimeVulnerability vuln = new OssRealtimeVulnerability(
                "CVE-2023-9999", "Critical", "Remote code execution", "1.2.3");
        assertEquals("CVE-2023-9999", vuln.getCve());
        assertEquals("Critical", vuln.getSeverity());
        assertEquals("Remote code execution", vuln.getDescription());
        assertEquals("1.2.3", vuln.getFixVersion());
    }

    // --- RealtimeLocation constructor ---

    @Test
    void testRealtimeLocationConstructorStoresAllFields() {
        RealtimeLocation loc = new RealtimeLocation(10, 5, 20);
        assertEquals(10, loc.getLine());
        assertEquals(5, loc.getStartIndex());
        assertEquals(20, loc.getEndIndex());
    }

    @Test
    void testFromLineWithMultiplePackages() {
        String json = "{\"Packages\": [" +
                "  {\"PackageName\": \"pkg-a\", \"PackageVersion\": \"1.0\"}," +
                "  {\"PackageName\": \"pkg-b\", \"PackageVersion\": \"2.0\"}" +
                "]}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(2, results.getPackages().size());
        assertEquals("pkg-a", results.getPackages().get(0).getPackageName());
        assertEquals("pkg-b", results.getPackages().get(1).getPackageName());
    }

    @Test
    void testFromLineWithVulnerabilitiesInPackage() {
        String json = "{\"Packages\": [{" +
                "  \"PackageName\": \"vuln-pkg\"," +
                "  \"Vulnerabilities\": [{" +
                "    \"CVE\": \"CVE-2022-0001\"," +
                "    \"Severity\": \"High\"," +
                "    \"Description\": \"Heap overflow\"," +
                "    \"FixVersion\": \"3.0.0\"" +
                "  }]" +
                "}]}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        assertNotNull(results);
        assertEquals(1, results.getPackages().size());
        assertEquals(1, results.getPackages().get(0).getVulnerabilities().size());
        OssRealtimeVulnerability vuln = results.getPackages().get(0).getVulnerabilities().get(0);
        assertEquals("CVE-2022-0001", vuln.getCve());
        assertEquals("High", vuln.getSeverity());
    }
}
