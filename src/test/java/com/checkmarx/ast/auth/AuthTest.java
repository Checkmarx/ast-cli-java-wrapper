package com.checkmarx.ast.auth;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.wrapper.CxConfig;
import com.checkmarx.ast.wrapper.CxException;
import com.checkmarx.ast.wrapper.CxWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class AuthTest extends BaseTest {
    @Test
    void testAuthValidate() throws CxException, IOException, InterruptedException {
        try {
            Assertions.assertNotNull(wrapper.authValidate());
        } catch (CxException e) {
            if (e.getMessage().contains("400") || e.getMessage().contains("Provided credentials are invalid")) {
                Assumptions.abort("Invalid or expired credentials: " + e.getMessage());
            }
            throw e;
        }
    }
//
    @Test
    void testAuthFailure() {
        CxConfig cxConfig = getConfig();
        cxConfig.setBaseAuthUri("wrongAuth");
        cxConfig.setApiKey("InvalidApiKey");
        Assertions.assertThrows(CxException.class, () -> new CxWrapper(cxConfig, getLogger()).authValidate());
    }
}
