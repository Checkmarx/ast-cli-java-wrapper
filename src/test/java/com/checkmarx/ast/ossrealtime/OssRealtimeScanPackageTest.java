package com.checkmarx.ast.ossrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("OssRealtimeScanPackage")
class OssRealtimeScanPackageTest {

    @Test
    @DisplayName("OssRealtimeScanPackage is a POJO with Lombok @Value")
    void testOssRealtimeScanPackageExists() {
        // OssRealtimeScanPackage uses @Value with complex constructor
        // Test class existence and basic contract
        assertNotNull(OssRealtimeScanPackage.class);
        assertTrue(OssRealtimeScanPackage.class.getSimpleName().contains("OssRealtimeScanPackage"));
    }

    @Test
    @DisplayName("Constructor with all parameters creates valid instance")
    void testConstructor_WithAllParameters() {
        List<RealtimeLocation> locations = Arrays.asList(new RealtimeLocation(1, 0, 10));
        List<OssRealtimeVulnerability> vulns = Arrays.asList(
            new OssRealtimeVulnerability("CVE-2021-1", "high", "desc", "1.0.1")
        );

        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", locations, "VULNERABLE", vulns
        );

        assertNotNull(pkg);
        assertEquals("npm", pkg.getPackageManager());
        assertEquals("lodash", pkg.getPackageName());
        assertEquals("4.17.20", pkg.getPackageVersion());
        assertEquals("package.json", pkg.getFilePath());
        assertEquals("VULNERABLE", pkg.getStatus());
        assertEquals(1, pkg.getLocations().size());
        assertEquals(1, pkg.getVulnerabilities().size());
    }

    @Test
    @DisplayName("Constructor with null locations converts to empty list")
    void testConstructor_NullLocations_CreatesEmptyList() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "maven", "log4j", "2.14.0", "pom.xml", null, "VULNERABLE", new ArrayList<>()
        );

        assertNotNull(pkg.getLocations());
        assertEquals(0, pkg.getLocations().size());
    }

    @Test
    @DisplayName("Constructor with null vulnerabilities converts to empty list")
    void testConstructor_NullVulnerabilities_CreatesEmptyList() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "pip", "requests", "2.25.1", "requirements.txt", new ArrayList<>(), "SAFE", null
        );

        assertNotNull(pkg.getVulnerabilities());
        assertEquals(0, pkg.getVulnerabilities().size());
    }

    @Test
    @DisplayName("Constructor with both null collections")
    void testConstructor_BothNull_CreatesEmptyCollections() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "gradle", "junit", "4.13.2", "build.gradle", null, "SAFE", null
        );

        assertEquals(0, pkg.getLocations().size());
        assertEquals(0, pkg.getVulnerabilities().size());
    }

    @Test
    @DisplayName("equals returns true for identical packages")
    void testEquals_IdenticalPackages_ReturnsTrue() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );

        assertEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when packageManager differs")
    void testEquals_DifferentManager_ReturnsFalse() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "yarn", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when packageName differs")
    void testEquals_DifferentName_ReturnsFalse() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "underscore", "4.17.20", "package.json", null, "VULNERABLE", null
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when packageVersion differs")
    void testEquals_DifferentVersion_ReturnsFalse() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.21", "package.json", null, "VULNERABLE", null
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when filePath differs")
    void testEquals_DifferentFilePath_ReturnsFalse() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "yarn.lock", null, "VULNERABLE", null
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when status differs")
    void testEquals_DifferentStatus_ReturnsFalse() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "SAFE", null
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("hashCode is consistent for equal packages")
    void testHashCode_EqualPackages_SameHash() {
        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );

        assertEquals(pkg1.hashCode(), pkg2.hashCode());
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNull() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );

        assertNotNull(pkg.toString());
        assertFalse(pkg.toString().isEmpty());
    }

    @Test
    @DisplayName("equals with null returns false")
    void testEquals_WithNull_ReturnsFalse() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );

        assertFalse(pkg.equals(null));
    }

    @Test
    @DisplayName("equals with different type returns false")
    void testEquals_DifferentType_ReturnsFalse() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", null, "VULNERABLE", null
        );

        assertFalse(pkg.equals("not a package"));
    }

    // ===== Augmentation tests for additional edge cases =====

    @Test
    @DisplayName("equals returns false when vulnerabilities differ")
    void testEquals_DifferentVulnerabilities_ReturnsFalse() {
        List<OssRealtimeVulnerability> vulns1 = new ArrayList<>();
        List<OssRealtimeVulnerability> vulns2 = new ArrayList<>();
        vulns2.add(new OssRealtimeVulnerability("CVE-2021-1", "high", "desc", "1.0.0"));

        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", vulns1
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", vulns2
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("equals returns false when locations differ")
    void testEquals_DifferentLocations_ReturnsFalse() {
        List<RealtimeLocation> locs1 = new ArrayList<>();
        List<RealtimeLocation> locs2 = new ArrayList<>();
        locs2.add(new RealtimeLocation(1, 2, 3));

        OssRealtimeScanPackage pkg1 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", locs1, "VULNERABLE", new ArrayList<>()
        );
        OssRealtimeScanPackage pkg2 = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", locs2, "VULNERABLE", new ArrayList<>()
        );

        assertNotEquals(pkg1, pkg2);
    }

    @Test
    @DisplayName("Constructor with multiple vulnerabilities")
    void testConstructor_WithMultipleVulnerabilities() {
        List<OssRealtimeVulnerability> vulns = Arrays.asList(
            new OssRealtimeVulnerability("CVE-2021-1", "high", "desc1", "1.0.1"),
            new OssRealtimeVulnerability("CVE-2021-2", "medium", "desc2", "1.0.2"),
            new OssRealtimeVulnerability("CVE-2021-3", "low", "desc3", "1.0.3")
        );

        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", vulns
        );

        assertEquals(3, pkg.getVulnerabilities().size());
    }

    @Test
    @DisplayName("Constructor with multiple locations")
    void testConstructor_WithMultipleLocations() {
        List<RealtimeLocation> locations = Arrays.asList(
            new RealtimeLocation(1, 10, 20),
            new RealtimeLocation(2, 30, 40),
            new RealtimeLocation(3, 50, 60)
        );

        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", locations, "VULNERABLE", new ArrayList<>()
        );

        assertEquals(3, pkg.getLocations().size());
    }

    @Test
    @DisplayName("getters return correct values from constructor")
    void testGetters_ReturnConstructorValues() {
        List<RealtimeLocation> locs = Arrays.asList(new RealtimeLocation(1, 0, 10));
        List<OssRealtimeVulnerability> vulns = Arrays.asList(
            new OssRealtimeVulnerability("CVE-2021-1", "high", "desc", "1.0.1")
        );

        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "maven", "commons-lang", "3.9", "pom.xml", locs, "SAFE", vulns
        );

        assertEquals("maven", pkg.getPackageManager());
        assertEquals("commons-lang", pkg.getPackageName());
        assertEquals("3.9", pkg.getPackageVersion());
        assertEquals("pom.xml", pkg.getFilePath());
        assertEquals("SAFE", pkg.getStatus());
    }

    @Test
    @DisplayName("status values variations")
    void testStatus_Variations() {
        String[] statuses = {"VULNERABLE", "SAFE", "UNKNOWN", "PENDING"};
        for (String status : statuses) {
            OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
                "npm", "pkg", "1.0", "file", null, status, null
            );
            assertEquals(status, pkg.getStatus());
        }
    }

    @Test
    @DisplayName("equals same object returns true")
    void testEquals_SameObject_ReturnsTrue() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );
        assertTrue(pkg.equals(pkg));
    }

    @Test
    @DisplayName("package with null name and manager")
    void testConstructor_WithNullNameAndManager() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            null, null, "1.0", "file.txt", new ArrayList<>(), "SAFE", new ArrayList<>()
        );

        assertNull(pkg.getPackageManager());
        assertNull(pkg.getPackageName());
        assertEquals("1.0", pkg.getPackageVersion());
    }

    @Test
    @DisplayName("package with empty string fields")
    void testConstructor_WithEmptyStrings() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "", "", "", "", new ArrayList<>(), "", new ArrayList<>()
        );

        assertEquals("", pkg.getPackageManager());
        assertEquals("", pkg.getPackageName());
        assertEquals("", pkg.getPackageVersion());
        assertEquals("", pkg.getFilePath());
        assertEquals("", pkg.getStatus());
    }

    @Test
    @DisplayName("hashCode consistent across multiple calls")
    void testHashCode_Consistent() {
        OssRealtimeScanPackage pkg = new OssRealtimeScanPackage(
            "npm", "lodash", "4.17.20", "package.json", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );

        int hash1 = pkg.hashCode();
        int hash2 = pkg.hashCode();
        int hash3 = pkg.hashCode();

        assertEquals(hash1, hash2);
        assertEquals(hash2, hash3);
    }

}
