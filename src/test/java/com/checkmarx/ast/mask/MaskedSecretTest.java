package com.checkmarx.ast.mask;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("MaskedSecret")
class MaskedSecretTest {

    @Test
    @DisplayName("Constructor creates valid instance")
    void testConstructor_CreatesValidInstance() {
        MaskedSecret secret = new MaskedSecret("***password***", "password123", 10);
        assertNotNull(secret);
    }

    @Test
    @DisplayName("Getters return correct values")
    void testGetters_ReturnCorrectValues() {
        MaskedSecret secret = new MaskedSecret("***", "secret123", 5);
        assertEquals("***", secret.getMasked());
        assertEquals("secret123", secret.getSecret());
        assertEquals(5, secret.getLine());
    }

    @Test
    @DisplayName("equals returns true for same object")
    void testEquals_WithSameObject_ReturnsTrue() {
        MaskedSecret secret = new MaskedSecret("***", "pass", 1);
        assertTrue(secret.equals(secret));
    }

    @Test
    @DisplayName("equals returns true for equal objects")
    void testEquals_WithEqualObjects_ReturnsTrue() {
        MaskedSecret secret1 = new MaskedSecret("***", "pass", 1);
        MaskedSecret secret2 = new MaskedSecret("***", "pass", 1);
        assertEquals(secret1, secret2);
    }

    @Test
    @DisplayName("equals returns false when masked differs")
    void testEquals_DifferentMasked_ReturnsFalse() {
        MaskedSecret secret1 = new MaskedSecret("***", "pass", 1);
        MaskedSecret secret2 = new MaskedSecret("****", "pass", 1);
        assertFalse(secret1.equals(secret2));
    }

    @Test
    @DisplayName("equals returns false when secret differs")
    void testEquals_DifferentSecret_ReturnsFalse() {
        MaskedSecret secret1 = new MaskedSecret("***", "pass1", 1);
        MaskedSecret secret2 = new MaskedSecret("***", "pass2", 1);
        assertFalse(secret1.equals(secret2));
    }

    @Test
    @DisplayName("equals returns false when line differs")
    void testEquals_DifferentLine_ReturnsFalse() {
        MaskedSecret secret1 = new MaskedSecret("***", "pass", 1);
        MaskedSecret secret2 = new MaskedSecret("***", "pass", 2);
        assertFalse(secret1.equals(secret2));
    }

    @Test
    @DisplayName("equals returns false when null")
    void testEquals_WithNull_ReturnsFalse() {
        MaskedSecret secret = new MaskedSecret("***", "pass", 1);
        assertFalse(secret.equals(null));
    }

    @Test
    @DisplayName("equals returns false when compared to different type")
    void testEquals_WithDifferentType_ReturnsFalse() {
        MaskedSecret secret = new MaskedSecret("***", "pass", 1);
        assertFalse(secret.equals("not a secret"));
    }

    @Test
    @DisplayName("hashCode is consistent for equal objects")
    void testHashCode_ForEqualObjects_IsSame() {
        MaskedSecret secret1 = new MaskedSecret("***", "pass", 1);
        MaskedSecret secret2 = new MaskedSecret("***", "pass", 1);
        assertEquals(secret1.hashCode(), secret2.hashCode());
    }

    @Test
    @DisplayName("hashCode is consistent across multiple calls")
    void testHashCode_IsConsistent() {
        MaskedSecret secret = new MaskedSecret("***", "pass", 1);
        int hash1 = secret.hashCode();
        int hash2 = secret.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("toString produces non-null string")
    void testToString_ProducesNonNullString() {
        MaskedSecret secret = new MaskedSecret("***", "pass", 1);
        assertNotNull(secret.toString());
        assertFalse(secret.toString().isEmpty());
    }
}
