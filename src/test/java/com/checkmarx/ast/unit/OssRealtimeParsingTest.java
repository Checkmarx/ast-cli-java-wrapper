package com.checkmarx.ast.unit;

import com.checkmarx.ast.ossrealtime.OssRealtimeResults;
import com.checkmarx.ast.ossrealtime.OssRealtimeScanPackage;
import com.checkmarx.ast.ossrealtime.OssRealtimeVulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

/**
 * Unit tests for OssRealtimeResults JSON parsing and object construction.
 * Focus: JSON parsing branches, constructor defaults, null/empty handling.
 */
class OssRealtimeParsingTest {

    /** Packages value is a string -> parser should fail and return null. */
    @Test
    void fromLine_PackagesStringType_ReturnsNull() {
        String json = "{\"Packages\":\"oops\"}";
        Assertions.assertNull(OssRealtimeResults.fromLine(json));
    }

    /** Packages array contains non-object entries -> parsing should fail and return null. */
    @Test
    void fromLine_PackagesArrayWithNonObjectEntries_ReturnsNull() {
        String json = "{\"Packages\":[123,\"abc\"]}";
        Assertions.assertNull(OssRealtimeResults.fromLine(json));
    }

    /** Packages key absent entirely -> fromLine returns null. */
    @Test
    void fromLine_LineDoesNotContainPackagesKey_ReturnsNull() {
        String jsonLine = "{\"PackageManager\":\"npm\"}"; // No top-level "Packages" key
        Assertions.assertNull(OssRealtimeResults.fromLine(jsonLine));
    }

    /** Truncated JSON containing Packages key -> parse exception caught, returns null. */
    @Test
    void fromLine_TruncatedJsonWithPackagesKey_CatchesAndReturnsNull() {
        String truncated = "{\"Packages\":[{"; // contains "Packages" but invalid JSON
        Assertions.assertNull(OssRealtimeResults.fromLine(truncated));
    }

    /** Packages key present but explicitly null -> results object with empty list. */
    @Test
    void fromLine_PackagesNull_YieldsEmptyList() {
        String json = "{\"Packages\":null}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        Assertions.assertTrue(results.getPackages().isEmpty());
    }

    /** Empty Packages array -> empty list returned. */
    @Test
    void fromLine_EmptyPackagesArray() {
        String json = "{\"Packages\":[]}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        Assertions.assertTrue(results.getPackages().isEmpty());
    }

    /** Package missing optional fields: packageManager & packageVersion should map to null. */
    @Test
    void parsePackageMissingFields_AllowsNulls() {
        String json = "{ \"Packages\": [{ \"PackageName\": \"only-name\", \"FilePath\": \"package.json\", \"Status\": \"OK\" }] }";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        Assertions.assertEquals(1, results.getPackages().size());
        OssRealtimeScanPackage pkg = results.getPackages().get(0);
        Assertions.assertNull(pkg.getPackageManager());
        Assertions.assertEquals("only-name", pkg.getPackageName());
        Assertions.assertNull(pkg.getPackageVersion());
    }

    /** Unicode characters preserved in Description field. */
    @Test
    void parseUnicodeInDescription() {
        String json = "{ \"Packages\": [{ \"PackageManager\": \"npm\", \"PackageName\": \"u\", \"PackageVersion\": \"1\", \"FilePath\": \"p.json\", \"Status\": \"OK\", \"Vulnerabilities\": [{ \"Id\": \"CVE-u\", \"Severity\": \"Low\", \"Description\": \"Unicode snow ☃ and emoji 🚀\" }] }] }";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        Assertions.assertEquals(1, results.getPackages().size());
        OssRealtimeVulnerability vul = results.getPackages().get(0).getVulnerabilities().get(0);
        Assertions.assertEquals("Unicode snow ☃ and emoji 🚀", vul.getDescription());
        Assertions.assertEquals("CVE-u", vul.getId());
    }

    /** Multiple vulnerabilities: one without fixVersion, one with fixVersion. */
    @Test
    void parseMultipleVulnerabilities() {
        String json = "{\n" +
                "  \"Packages\": [{\n" +
                "    \"PackageManager\": \"npm\",\n" +
                "    \"PackageName\": \"dep\",\n" +
                "    \"PackageVersion\": \"1.0.0\",\n" +
                "    \"FilePath\": \"/a/package.json\",\n" +
                "    \"Status\": \"OK\",\n" +
                "    \"Vulnerabilities\": [\n" +
                "      { \"Id\": \"CVE-1\", \"Severity\": \"Low\", \"Description\": \"d1\" },\n" +
                "      { \"Id\": \"CVE-2\", \"Severity\": \"Critical\", \"Description\": \"d2\", \"FixVersion\": \"2.0.0\" }\n" +
                "    ]\n" +
                "  }]\n" +
                "}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        OssRealtimeScanPackage pkg = results.getPackages().get(0);
        List<OssRealtimeVulnerability> vulns = pkg.getVulnerabilities();
        Assertions.assertEquals(2, vulns.size());
        Assertions.assertEquals("CVE-1", vulns.get(0).getId());
        Assertions.assertNull(vulns.get(0).getFixVersion());
        Assertions.assertEquals("CVE-2", vulns.get(1).getId());
        Assertions.assertEquals("2.0.0", vulns.get(1).getFixVersion());
    }

    /** Explicit null lists should be normalized to empty lists by constructor. */
    @Test
    void constructor_DefaultsEmptyListsWhenNull() throws IOException {
        String json = "{\n" +
                "  \"Packages\": [{\n" +
                "    \"PackageManager\": \"pip\",\n" +
                "    \"PackageName\": \"requests\",\n" +
                "    \"PackageVersion\": \"2.0.0\",\n" +
                "    \"FilePath\": \"requirements.txt\",\n" +
                "    \"Status\": \"Unknown\",\n" +
                "    \"Locations\": null,\n" +
                "    \"Vulnerabilities\": null\n" +
                "  }]\n" +
                "}";
        OssRealtimeResults results = new ObjectMapper().readValue(json, OssRealtimeResults.class);
        Assertions.assertNotNull(results);
        Assertions.assertEquals(1, results.getPackages().size());
        OssRealtimeScanPackage pkg = results.getPackages().get(0);
        Assertions.assertTrue(pkg.getLocations().isEmpty());
        Assertions.assertTrue(pkg.getVulnerabilities().isEmpty());
    }

    /** All vulnerability fields mapped including fixVersion. */
    @Test
    void vulnerability_AllFieldsMapped() {
        String json = "{\n" +
                "  \"Packages\": [{\n" +
                "    \"PackageManager\": \"npm\",\n" +
                "    \"PackageName\": \"chalk\",\n" +
                "    \"PackageVersion\": \"5.0.0\",\n" +
                "    \"FilePath\": \"/w/package.json\",\n" +
                "    \"Status\": \"OK\",\n" +
                "    \"Vulnerabilities\": [{\n" +
                "       \"Id\": \"CVE-2025-9999\",\n" +
                "       \"Severity\": \"Medium\",\n" +
                "       \"Description\": \"Some issue\",\n" +
                "       \"FixVersion\": \"5.0.1\"\n" +
                "    }]\n" +
                "  }]\n" +
                "}";
        OssRealtimeResults results = OssRealtimeResults.fromLine(json);
        Assertions.assertNotNull(results);
        OssRealtimeVulnerability vul = results.getPackages().get(0).getVulnerabilities().get(0);
        Assertions.assertEquals("CVE-2025-9999", vul.getId());
        Assertions.assertEquals("Medium", vul.getSeverity());
        Assertions.assertEquals("Some issue", vul.getDescription());
        Assertions.assertEquals("5.0.1", vul.getFixVersion());
    }
}
