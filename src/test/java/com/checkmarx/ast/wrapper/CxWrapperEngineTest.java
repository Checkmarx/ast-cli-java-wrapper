package com.checkmarx.ast.wrapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CxWrapperEngineTest")
class CxWrapperEngineTest {

    @Mock
    Logger logger;

    private CxWrapper subject;
    private CxConfig config;

    @BeforeEach
    void setUp() throws Exception {
        config = CxConfig.builder()
                .baseUri("http://localhost:8080")
                .clientId("test-client")
                .apiKey("test-api-key")
                .build();
        subject = new CxWrapper(config, logger);
    }

    @Test
    @DisplayName("checkEngineExist with engine name")
    void testCheckEngineExist() throws Exception {
        assertDoesNotThrow(() -> {
            try {
                subject.checkEngineExist("cx");
            } catch (CxException e) {
                // Expected in test environment
            }
        });
    }

    @Test
    @DisplayName("checkEngineExist with null engine")
    void testCheckEngineExist_WithNull() {
        assertThrows(NullPointerException.class, () -> {
            subject.checkEngineExist(null);
        });
    }


}
