package com.checkmarx.ast.ossrealtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("OssRealtimeResults")
class OssRealtimeResultsTest {

    @Test
    @DisplayName("Constructor with null packages converts to empty list")
    void testConstructor_WithNullPackages_ConvertsToEmptyList() {
        OssRealtimeResults result = new OssRealtimeResults(null);
        assertNotNull(result.getPackages());
        assertTrue(result.getPackages().isEmpty());
    }

    @Test
    @DisplayName("Constructor with non-null packages preserves list")
    void testConstructor_WithNonNullPackages_PreservesList() {
        List<OssRealtimeScanPackage> packages = new ArrayList<>();
        OssRealtimeResults result = new OssRealtimeResults(packages);
        assertNotNull(result.getPackages());
        assertEquals(packages, result.getPackages());
    }

    @Test
    @DisplayName("getPackages returns non-null list")
    void testGetPackages_ReturnsNonNull() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        assertNotNull(result.getPackages());
    }

    @Test
    @DisplayName("equals returns true for same object")
    void testEquals_WithSameObject_ReturnsTrue() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        assertTrue(result.equals(result));
    }

    @Test
    @DisplayName("equals returns true for equal objects")
    void testEquals_WithEqualObjects_ReturnsTrue() {
        OssRealtimeResults result1 = new OssRealtimeResults(new ArrayList<>());
        OssRealtimeResults result2 = new OssRealtimeResults(new ArrayList<>());
        assertEquals(result1, result2);
    }

    @Test
    @DisplayName("equals returns false when compared to null")
    void testEquals_WithNull_ReturnsFalse() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        assertFalse(result.equals(null));
    }

    @Test
    @DisplayName("equals returns false when compared to different type")
    void testEquals_WithDifferentType_ReturnsFalse() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        assertFalse(result.equals("not a result"));
    }

    @Test
    @DisplayName("hashCode is consistent for equal objects")
    void testHashCode_ForEqualObjects_IsSame() {
        OssRealtimeResults result1 = new OssRealtimeResults(new ArrayList<>());
        OssRealtimeResults result2 = new OssRealtimeResults(new ArrayList<>());
        assertEquals(result1.hashCode(), result2.hashCode());
    }

    @Test
    @DisplayName("hashCode is consistent across multiple calls")
    void testHashCode_IsConsistent() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        int hash1 = result.hashCode();
        int hash2 = result.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNullString() {
        OssRealtimeResults result = new OssRealtimeResults(new ArrayList<>());
        assertNotNull(result.toString());
        assertFalse(result.toString().isEmpty());
    }
}
