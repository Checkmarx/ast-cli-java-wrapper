package com.checkmarx.ast;

import com.checkmarx.ast.mask.MaskResult;
import com.checkmarx.ast.mask.MaskedSecret;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class MaskTest extends BaseTest {

    private static final String RESULTS_FILE = "target/test-classes/results.json";
    private static final String SECRETS_REALTIME_FILE = "target/test-classes/Secrets-realtime.json";

    @Test
    void testMaskSecretsWithFileContainingSecrets() throws Exception {
        // Tests CLI execution with file containing actual secrets and validates masking behavior
        MaskResult result = wrapper.maskSecrets(SECRETS_REALTIME_FILE);

        Assertions.assertNotNull(result);
        Assertions.assertNotNull(result.getMaskedFile());
        Assertions.assertNotNull(result.getMaskedSecrets());
        Assertions.assertFalse(result.getMaskedSecrets().isEmpty());

        MaskedSecret secret = result.getMaskedSecrets().get(0);
        Assertions.assertNotNull(secret.getMasked());
        Assertions.assertNotNull(secret.getSecret());
        Assertions.assertEquals(5, secret.getLine());
        Assertions.assertTrue(secret.getMasked().contains("<masked>") || secret.getMasked().contains("\\u003cmasked\\u003e"));
        Assertions.assertTrue(secret.getSecret().contains("-----BEGIN RSA PRIVATE KEY-----"));
        Assertions.assertTrue(secret.getSecret().length() > secret.getMasked().length());
    }

    @Test
    void testMaskSecretsWithFileContainingNoSecrets() throws Exception {
        // Tests CLI execution with file containing no secrets
        MaskResult result = wrapper.maskSecrets(RESULTS_FILE);

        Assertions.assertNotNull(result);
        Assertions.assertNotNull(result.getMaskedFile());
        Assertions.assertFalse(result.getMaskedFile().isEmpty());
    }

    @Test
    void testMaskSecretsErrorHandling() {
        // Tests CLI error handling for invalid inputs
        Assertions.assertThrows(Exception.class, () -> wrapper.maskSecrets(null));
        Assertions.assertThrows(Exception.class, () -> wrapper.maskSecrets("non-existent-file.json"));
        Assertions.assertDoesNotThrow(() -> wrapper.maskSecrets(RESULTS_FILE));
    }

    @Test
    void testMaskSecretsResponseParsing() throws Exception {
        // Tests CLI response structure and JSON parsing functionality
        MaskResult result = wrapper.maskSecrets(SECRETS_REALTIME_FILE);

        Assertions.assertNotNull(result);
        Assertions.assertNotNull(result.getMaskedSecrets());
        Assertions.assertFalse(result.getMaskedSecrets().isEmpty());

        MaskedSecret secret = result.getMaskedSecrets().get(0);
        Assertions.assertNotNull(secret.getMasked());
        Assertions.assertNotNull(secret.getSecret());
        Assertions.assertTrue(secret.getLine() >= 0);

        Assertions.assertNull(MaskResult.fromLine(""));
        Assertions.assertNull(MaskResult.fromLine("{invalid json}"));
        Assertions.assertNull(MaskResult.fromLine(null));
    }

    @Test
    void testMaskSecretsObjectBehavior() throws Exception {
        // Tests object equality, serialization and consistency with CLI responses
        MaskResult result1 = wrapper.maskSecrets(SECRETS_REALTIME_FILE);
        MaskResult result2 = wrapper.maskSecrets(SECRETS_REALTIME_FILE);

        Assertions.assertEquals(result1.getMaskedFile(), result2.getMaskedFile());
        Assertions.assertNotNull(result1.toString());
        Assertions.assertTrue(result1.toString().contains("MaskResult"));

        if (result1.getMaskedSecrets() != null && !result1.getMaskedSecrets().isEmpty()) {
            MaskedSecret secret1 = result1.getMaskedSecrets().get(0);
            MaskedSecret secret2 = result2.getMaskedSecrets().get(0);

            Assertions.assertEquals(secret1.getMasked(), secret2.getMasked());
            Assertions.assertEquals(secret1.getSecret(), secret2.getSecret());
            Assertions.assertEquals(secret1.getLine(), secret2.getLine());
            Assertions.assertEquals(secret1.hashCode(), secret2.hashCode());
            Assertions.assertEquals(secret1, secret1);
            Assertions.assertNotEquals(secret1, null);

            String toString = secret1.toString();
            Assertions.assertNotNull(toString);
            Assertions.assertTrue(toString.contains("MaskedSecret"));
        }

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(result1);
        MaskResult deserialized = mapper.readValue(json, MaskResult.class);

        Assertions.assertEquals(result1.getMaskedFile(), deserialized.getMaskedFile());
        if (result1.getMaskedSecrets() != null) {
            Assertions.assertEquals(result1.getMaskedSecrets().size(), deserialized.getMaskedSecrets().size());
        }
    }
}
