package com.checkmarx.ast.realtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RealtimeLocation")
class RealtimeLocationTest {

    @Test
    @DisplayName("Constructor creates valid instance with three int parameters")
    void testConstructor_CreatesValidInstance() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        assertNotNull(location);
    }

    @Test
    @DisplayName("getLine returns correct value")
    void testGetLine_ReturnsCorrectValue() {
        RealtimeLocation location = new RealtimeLocation(25, 10, 30);
        assertEquals(25, location.getLine());
    }

    @Test
    @DisplayName("getStartIndex returns correct value")
    void testGetStartIndex_ReturnsCorrectValue() {
        RealtimeLocation location = new RealtimeLocation(25, 10, 30);
        assertEquals(10, location.getStartIndex());
    }

    @Test
    @DisplayName("getEndIndex returns correct value")
    void testGetEndIndex_ReturnsCorrectValue() {
        RealtimeLocation location = new RealtimeLocation(25, 10, 30);
        assertEquals(30, location.getEndIndex());
    }

    @Test
    @DisplayName("equals returns true for same object")
    void testEquals_WithSameObject_ReturnsTrue() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        assertTrue(location.equals(location));
    }

    @Test
    @DisplayName("equals returns true for equal objects")
    void testEquals_WithEqualObjects_ReturnsTrue() {
        RealtimeLocation loc1 = new RealtimeLocation(10, 5, 15);
        RealtimeLocation loc2 = new RealtimeLocation(10, 5, 15);
        assertEquals(loc1, loc2);
    }

    @ParameterizedTest(name = "Line {0} vs {1}")
    @CsvSource({
        "10, 20",
        "5, 10",
        "100, 101"
    })
    @DisplayName("equals returns false when line differs")
    void testEquals_DifferentLine_ReturnsFalse(int line1, int line2) {
        RealtimeLocation loc1 = new RealtimeLocation(line1, 5, 15);
        RealtimeLocation loc2 = new RealtimeLocation(line2, 5, 15);
        assertFalse(loc1.equals(loc2));
    }

    @Test
    @DisplayName("equals returns false when startIndex differs")
    void testEquals_DifferentStartIndex_ReturnsFalse() {
        RealtimeLocation loc1 = new RealtimeLocation(10, 5, 15);
        RealtimeLocation loc2 = new RealtimeLocation(10, 8, 15);
        assertFalse(loc1.equals(loc2));
    }

    @Test
    @DisplayName("equals returns false when endIndex differs")
    void testEquals_DifferentEndIndex_ReturnsFalse() {
        RealtimeLocation loc1 = new RealtimeLocation(10, 5, 15);
        RealtimeLocation loc2 = new RealtimeLocation(10, 5, 20);
        assertFalse(loc1.equals(loc2));
    }

    @Test
    @DisplayName("equals returns false when compared to null")
    void testEquals_WithNull_ReturnsFalse() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        assertFalse(location.equals(null));
    }

    @Test
    @DisplayName("equals returns false when compared to different type")
    void testEquals_WithDifferentType_ReturnsFalse() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        assertFalse(location.equals("not a location"));
    }

    @Test
    @DisplayName("hashCode is consistent for equal objects")
    void testHashCode_ForEqualObjects_IsSame() {
        RealtimeLocation loc1 = new RealtimeLocation(10, 5, 15);
        RealtimeLocation loc2 = new RealtimeLocation(10, 5, 15);
        assertEquals(loc1.hashCode(), loc2.hashCode());
    }

    @Test
    @DisplayName("hashCode is consistent across multiple calls")
    void testHashCode_IsConsistent() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        int hash1 = location.hashCode();
        int hash2 = location.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNullString() {
        RealtimeLocation location = new RealtimeLocation(10, 5, 15);
        assertNotNull(location.toString());
        assertFalse(location.toString().isEmpty());
    }

    @Test
    @DisplayName("Constructor with zero values creates valid instance")
    void testConstructor_WithZeroValues() {
        RealtimeLocation location = new RealtimeLocation(0, 0, 0);
        assertNotNull(location);
        assertEquals(0, location.getLine());
        assertEquals(0, location.getStartIndex());
        assertEquals(0, location.getEndIndex());
    }

    @Test
    @DisplayName("Constructor with large values creates valid instance")
    void testConstructor_WithLargeValues() {
        RealtimeLocation location = new RealtimeLocation(999999, 500000, 999999);
        assertEquals(999999, location.getLine());
        assertEquals(500000, location.getStartIndex());
        assertEquals(999999, location.getEndIndex());
    }
}
