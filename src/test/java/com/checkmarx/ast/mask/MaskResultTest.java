package com.checkmarx.ast.mask;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("MaskResult")
class MaskResultTest {

    @Test
    @DisplayName("Constructor creates valid instance with masked secrets")
    void testConstructor_CreatesValidInstance() {
        List<MaskedSecret> secrets = new ArrayList<>();
        MaskResult result = new MaskResult(secrets, "maskedFile.txt");
        assertNotNull(result);
    }

    @Test
    @DisplayName("Getters return correct values")
    void testGetters_ReturnCorrectValues() {
        List<MaskedSecret> secrets = Arrays.asList(
            new MaskedSecret("***", "password123", 1)
        );
        MaskResult result = new MaskResult(secrets, "app.log");
        assertEquals(secrets, result.getMaskedSecrets());
        assertEquals("app.log", result.getMaskedFile());
    }

    @Test
    @DisplayName("equals returns true for same object")
    void testEquals_WithSameObject_ReturnsTrue() {
        MaskResult result = new MaskResult(new ArrayList<>(), "file.txt");
        assertTrue(result.equals(result));
    }

    @Test
    @DisplayName("equals returns true for equal objects")
    void testEquals_WithEqualObjects_ReturnsTrue() {
        List<MaskedSecret> secrets = new ArrayList<>();
        MaskResult result1 = new MaskResult(secrets, "file.txt");
        MaskResult result2 = new MaskResult(secrets, "file.txt");
        assertEquals(result1, result2);
    }

    @Test
    @DisplayName("equals returns false when maskedFile differs")
    void testEquals_DifferentFile_ReturnsFalse() {
        List<MaskedSecret> secrets = new ArrayList<>();
        MaskResult result1 = new MaskResult(secrets, "file1.txt");
        MaskResult result2 = new MaskResult(secrets, "file2.txt");
        assertFalse(result1.equals(result2));
    }

    @Test
    @DisplayName("equals returns false when null")
    void testEquals_WithNull_ReturnsFalse() {
        MaskResult result = new MaskResult(new ArrayList<>(), "file.txt");
        assertFalse(result.equals(null));
    }

    @Test
    @DisplayName("equals returns false when compared to different type")
    void testEquals_WithDifferentType_ReturnsFalse() {
        MaskResult result = new MaskResult(new ArrayList<>(), "file.txt");
        assertFalse(result.equals("not a result"));
    }

    @Test
    @DisplayName("hashCode is consistent for equal objects")
    void testHashCode_ForEqualObjects_IsSame() {
        List<MaskedSecret> secrets = new ArrayList<>();
        MaskResult result1 = new MaskResult(secrets, "file.txt");
        MaskResult result2 = new MaskResult(secrets, "file.txt");
        assertEquals(result1.hashCode(), result2.hashCode());
    }

    @Test
    @DisplayName("hashCode is consistent across multiple calls")
    void testHashCode_IsConsistent() {
        MaskResult result = new MaskResult(new ArrayList<>(), "file.txt");
        int hash1 = result.hashCode();
        int hash2 = result.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNullString() {
        MaskResult result = new MaskResult(new ArrayList<>(), "file.txt");
        assertNotNull(result.toString());
        assertFalse(result.toString().isEmpty());
    }
}
