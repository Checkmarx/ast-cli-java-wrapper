package com.checkmarx.ast.mask;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MaskResultParsingTest {

    // --- MaskResult.fromLine (delegates to JsonParser.parse) ---

    @Test
    void testFromLineWithNull() {
        assertNull(MaskResult.fromLine(null));
    }

    @Test
    void testFromLineWithBlank() {
        assertNull(MaskResult.fromLine(""));
        assertNull(MaskResult.fromLine("   "));
    }

    @Test
    void testFromLineWithInvalidJson() {
        assertNull(MaskResult.fromLine("{invalid}"));
        assertNull(MaskResult.fromLine("{"));
    }

    @Test
    void testFromLineWithValidJson() {
        String json = "{" +
                "  \"maskedFile\": \"/path/to/file.txt\"," +
                "  \"maskedSecrets\": [" +
                "    {\"masked\": \"***\", \"secret\": \"actual-secret\", \"line\": 42}" +
                "  ]" +
                "}";
        MaskResult result = MaskResult.fromLine(json);
        assertNotNull(result);
        assertEquals("/path/to/file.txt", result.getMaskedFile());
        assertNotNull(result.getMaskedSecrets());
        assertEquals(1, result.getMaskedSecrets().size());
        MaskedSecret secret = result.getMaskedSecrets().get(0);
        assertEquals("***", secret.getMasked());
        assertEquals("actual-secret", secret.getSecret());
        assertEquals(42, secret.getLine());
    }

    @Test
    void testFromLineWithEmptySecretsArray() {
        String json = "{\"maskedFile\": \"file.txt\", \"maskedSecrets\": []}";
        MaskResult result = MaskResult.fromLine(json);
        assertNotNull(result);
        assertEquals("file.txt", result.getMaskedFile());
        assertNotNull(result.getMaskedSecrets());
        assertTrue(result.getMaskedSecrets().isEmpty());
    }

    @Test
    void testFromLineWithMultipleSecrets() {
        String json = "{" +
                "  \"maskedFile\": \"config.env\"," +
                "  \"maskedSecrets\": [" +
                "    {\"masked\": \"***1\", \"secret\": \"tok-a\", \"line\": 1}," +
                "    {\"masked\": \"***2\", \"secret\": \"tok-b\", \"line\": 5}" +
                "  ]" +
                "}";
        MaskResult result = MaskResult.fromLine(json);
        assertNotNull(result);
        assertEquals(2, result.getMaskedSecrets().size());
        assertEquals(1, result.getMaskedSecrets().get(0).getLine());
        assertEquals(5, result.getMaskedSecrets().get(1).getLine());
    }

    // --- MaskedSecret constructor ---

    @Test
    void testMaskedSecretConstructorStoresAllFields() {
        MaskedSecret secret = new MaskedSecret("***masked***", "real-token", 7);
        assertEquals("***masked***", secret.getMasked());
        assertEquals("real-token", secret.getSecret());
        assertEquals(7, secret.getLine());
    }

    // --- MaskResult constructor ---

    @Test
    void testMaskResultConstructorStoresAllFields() {
        MaskedSecret s = new MaskedSecret("m", "s", 1);
        MaskResult result = new MaskResult(Collections.singletonList(s), "/masked/file.txt");
        assertEquals("/masked/file.txt", result.getMaskedFile());
        assertEquals(1, result.getMaskedSecrets().size());
    }
}
