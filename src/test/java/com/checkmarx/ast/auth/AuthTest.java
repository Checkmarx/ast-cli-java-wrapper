package com.checkmarx.ast.auth;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.wrapper.CxConfig;
import com.checkmarx.ast.wrapper.CxConstants;
import com.checkmarx.ast.wrapper.CxException;
import com.checkmarx.ast.wrapper.CxWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Map;

class AuthTest extends BaseTest {
    @Test
    void testAuthValidate() throws CxException, IOException, InterruptedException {
        Assertions.assertNotNull(wrapper.authValidate());
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
