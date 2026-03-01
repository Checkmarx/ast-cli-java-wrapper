package com.checkmarx.ast;

import com.checkmarx.ast.tenant.TenantSetting;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class TenantTest extends BaseTest {

    @Test
    void testTenantSettings() throws Exception {
        List<TenantSetting> tenantSettings = wrapper.tenantSettings();
        Assertions.assertFalse(tenantSettings.isEmpty());
    }

    @Test
    void testIdeScansEnabled() {
        Assertions.assertDoesNotThrow(() -> wrapper.ideScansEnabled());
    }

    @Test
    void testAiMcpServerEnabled() throws Exception {
        boolean enabled = Assertions.assertDoesNotThrow(() -> wrapper.aiMcpServerEnabled());
        Assertions.assertTrue(enabled, "AI MCP Server flag expected to be true");
    }

    @Test
    void testDevAssistEnabled() {
        Assertions.assertDoesNotThrow(() -> wrapper.devAssistEnabled());
    }

    @Test
    void testOneAssistEnabled() {
        Assertions.assertDoesNotThrow(() -> wrapper.oneAssistEnabled());
    }
}
