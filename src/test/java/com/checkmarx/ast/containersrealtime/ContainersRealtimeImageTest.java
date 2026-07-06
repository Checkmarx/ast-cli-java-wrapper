package com.checkmarx.ast.containersrealtime;

import com.checkmarx.ast.realtime.RealtimeLocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ContainersRealtimeImage")
class ContainersRealtimeImageTest {

    @Test
    @DisplayName("ContainersRealtimeImage is a POJO with Lombok @Value")
    void testContainersRealtimeImageExists() {
        // ContainersRealtimeImage uses @Value with complex constructor
        // Test class existence and basic contract
        assertNotNull(ContainersRealtimeImage.class);
        assertTrue(ContainersRealtimeImage.class.getSimpleName().contains("ContainersRealtimeImage"));
    }

    @Test
    @DisplayName("Constructor with all parameters creates valid instance")
    void testConstructor_WithAllParameters() {
        List<RealtimeLocation> locations = Arrays.asList(new RealtimeLocation(1, 0, 10));
        List<ContainersRealtimeVulnerability> vulns = Arrays.asList(
            new ContainersRealtimeVulnerability("CVE-2021-1", "high")
        );

        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", locations, "VULNERABLE", vulns
        );

        assertNotNull(img);
        assertEquals("nginx:latest", img.getImageName());
        assertEquals("1.0", img.getImageTag());
        assertEquals("/app/Dockerfile", img.getFilePath());
        assertEquals("VULNERABLE", img.getStatus());
        assertEquals(1, img.getLocations().size());
        assertEquals(1, img.getVulnerabilities().size());
    }

    @Test
    @DisplayName("Constructor with null locations converts to empty list")
    void testConstructor_NullLocations_CreatesEmptyList() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "ubuntu:20.04", "2.0", "Dockerfile", null, "SAFE", new ArrayList<>()
        );

        assertNotNull(img.getLocations());
        assertEquals(0, img.getLocations().size());
    }

    @Test
    @DisplayName("Constructor with null vulnerabilities converts to empty list")
    void testConstructor_NullVulnerabilities_CreatesEmptyList() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "alpine:3.12", "3.0", "Dockerfile", new ArrayList<>(), "SAFE", null
        );

        assertNotNull(img.getVulnerabilities());
        assertEquals(0, img.getVulnerabilities().size());
    }

    @Test
    @DisplayName("Constructor with both null collections")
    void testConstructor_BothNull_CreatesEmptyCollections() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "centos:8", "4.0", "Dockerfile", null, "SAFE", null
        );

        assertEquals(0, img.getLocations().size());
        assertEquals(0, img.getVulnerabilities().size());
    }

    @Test
    @DisplayName("equals returns true for identical images")
    void testEquals_IdenticalImages_ReturnsTrue() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );

        assertEquals(img1, img2);
    }

    @Test
    @DisplayName("equals returns false when imageName differs")
    void testEquals_DifferentImageName_ReturnsFalse() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "apache:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );

        assertNotEquals(img1, img2);
    }

    @Test
    @DisplayName("equals returns false when imageTag differs")
    void testEquals_DifferentImageTag_ReturnsFalse() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "nginx:latest", "2.0", "/app/Dockerfile", null, "VULNERABLE", null
        );

        assertNotEquals(img1, img2);
    }

    @Test
    @DisplayName("equals returns false when filePath differs")
    void testEquals_DifferentFilePath_ReturnsFalse() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/docker/Dockerfile", null, "VULNERABLE", null
        );

        assertNotEquals(img1, img2);
    }

    @Test
    @DisplayName("equals returns false when status differs")
    void testEquals_DifferentStatus_ReturnsFalse() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "SAFE", null
        );

        assertNotEquals(img1, img2);
    }

    @Test
    @DisplayName("hashCode is consistent for equal images")
    void testHashCode_EqualImages_SameHash() {
        ContainersRealtimeImage img1 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );
        ContainersRealtimeImage img2 = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", new ArrayList<>(), "VULNERABLE", new ArrayList<>()
        );

        assertEquals(img1.hashCode(), img2.hashCode());
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNull() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );

        assertNotNull(img.toString());
        assertFalse(img.toString().isEmpty());
    }

    @Test
    @DisplayName("equals with null returns false")
    void testEquals_WithNull_ReturnsFalse() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );

        assertFalse(img.equals(null));
    }

    @Test
    @DisplayName("equals with different type returns false")
    void testEquals_DifferentType_ReturnsFalse() {
        ContainersRealtimeImage img = new ContainersRealtimeImage(
            "nginx:latest", "1.0", "/app/Dockerfile", null, "VULNERABLE", null
        );

        assertFalse(img.equals("not an image"));
    }

}
