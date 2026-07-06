package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.containersrealtime.ContainersRealtimeResults;
import com.checkmarx.ast.iacrealtime.IacRealtimeResults;
import com.checkmarx.ast.kicsRealtimeResults.KicsRealtimeResults;
import com.checkmarx.ast.ossrealtime.OssRealtimeResults;
import com.checkmarx.ast.secretsrealtime.SecretsRealtimeResults;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
@DisplayName("CxWrapperRealtimeScanTest")
class CxWrapperRealtimeScanTest {

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

    // ===== KICS Realtime Scanning Tests =====

    @Test
    @DisplayName("kicsRealtimeScan with valid source path throws IOException on error")
    void testKicsRealtimeScan_ValidSourcePath() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("KICS execution failed"));

            assertThrows(IOException.class, () -> subject.kicsRealtimeScan("/app/terraform", "terraform", null));
        }
    }

    @Test
    @DisplayName("kicsRealtimeScan throws IOException on network error")
    void testKicsRealtimeScan_NetworkError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Network timeout"));

            assertThrows(IOException.class, () -> subject.kicsRealtimeScan("/app", null, null));
        }
    }

    @Test
    @DisplayName("kicsRealtimeScan throws CxException on execution error")
    void testKicsRealtimeScan_ExecutionError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(500, "Internal server error"));

            assertThrows(CxException.class, () -> subject.kicsRealtimeScan("/app", null, null));
        }
    }

    @Test
    @DisplayName("kicsRealtimeScan with null source path throws NullPointerException")
    void testKicsRealtimeScan_NullSourcePath() {
        assertThrows(NullPointerException.class, () -> {
            subject.kicsRealtimeScan(null, null, null);
        });
    }

    @Test
    @DisplayName("kicsRealtimeScan with engine parameter throws CxException on error")
    void testKicsRealtimeScan_WithEngine() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(400, "Invalid engine type"));

            assertThrows(CxException.class, () -> subject.kicsRealtimeScan("/app", "terraform", null));
        }
    }

    @Test
    @DisplayName("kicsRealtimeScan with additional parameters throws IOException")
    void testKicsRealtimeScan_WithAdditionalParams() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("CLI execution failed"));

            assertThrows(IOException.class, () -> subject.kicsRealtimeScan("/app", "terraform", "--profile strict"));
        }
    }

    // ===== OSS Realtime Scanning Tests =====

    @Test
    @DisplayName("ossRealtimeScan with valid source path throws CxException on error")
    void testOssRealtimeScan_ValidSourcePath() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(400, "Invalid package data"));

            assertThrows(CxException.class, () -> subject.ossRealtimeScan("/app/src", null));
        }
    }

    @Test
    @DisplayName("ossRealtimeScan throws IOException on network failure")
    void testOssRealtimeScan_NetworkFailure() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Connection refused"));

            assertThrows(IOException.class, () -> subject.ossRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("ossRealtimeScan throws CxException on API error")
    void testOssRealtimeScan_ApiError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(400, "Invalid source path"));

            assertThrows(CxException.class, () -> subject.ossRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("ossRealtimeScan throws NullPointerException when source is null")
    void testOssRealtimeScan_NullSource() {
        assertThrows(NullPointerException.class, () -> {
            subject.ossRealtimeScan(null, null);
        });
    }

    @Test
    @DisplayName("ossRealtimeScan with ignoredFiles parameter throws CxException on error")
    void testOssRealtimeScan_WithIgnoredFiles() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(400, "Invalid ignored file"));

            assertThrows(CxException.class, () -> subject.ossRealtimeScan("/app", ".gitignore"));
        }
    }

    // ===== IAC Realtime Scanning Tests =====

    @Test
    @DisplayName("iacRealtimeScan with valid source path throws IOException on error")
    void testIacRealtimeScan_ValidSourcePath() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("IAC scan failed"));

            assertThrows(IOException.class, () -> subject.iacRealtimeScan("/app/terraform", null, null));
        }
    }

    @Test
    @DisplayName("iacRealtimeScan throws IOException on execution failure")
    void testIacRealtimeScan_ExecutionFailure() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("CLI execution failed"));

            assertThrows(IOException.class, () -> subject.iacRealtimeScan("/app", null, null));
        }
    }

    @Test
    @DisplayName("iacRealtimeScan throws CxException on error")
    void testIacRealtimeScan_CxException() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(500, "Server error"));

            assertThrows(CxException.class, () -> subject.iacRealtimeScan("/app", null, null));
        }
    }

    @Test
    @DisplayName("iacRealtimeScan throws NullPointerException when source is null")
    void testIacRealtimeScan_NullSource() {
        assertThrows(NullPointerException.class, () -> {
            subject.iacRealtimeScan(null, null, null);
        });
    }

    @Test
    @DisplayName("iacRealtimeScan with containerTool parameter throws CxException on error")
    void testIacRealtimeScan_WithContainerTool() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(500, "Container tool error"));

            assertThrows(CxException.class, () -> subject.iacRealtimeScan("/app", "docker", null));
        }
    }

    // ===== Secrets Realtime Scanning Tests =====

    @Test
    @DisplayName("secretsRealtimeScan with valid source path throws CxException on error")
    void testSecretsRealtimeScan_ValidSourcePath() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(401, "Authentication failed"));

            assertThrows(CxException.class, () -> subject.secretsRealtimeScan("/app/src", null));
        }
    }

    @Test
    @DisplayName("secretsRealtimeScan throws IOException on network error")
    void testSecretsRealtimeScan_NetworkError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Network timeout"));

            assertThrows(IOException.class, () -> subject.secretsRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("secretsRealtimeScan throws NullPointerException when source is null")
    void testSecretsRealtimeScan_NullSource() {
        assertThrows(NullPointerException.class, () -> {
            subject.secretsRealtimeScan(null, null);
        });
    }

    @Test
    @DisplayName("secretsRealtimeScan with ignoredFiles parameter throws IOException")
    void testSecretsRealtimeScan_WithIgnoredFiles() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("File not found"));

            assertThrows(IOException.class, () -> subject.secretsRealtimeScan("/app", ".secretsignore"));
        }
    }

    // ===== Containers Realtime Scanning Tests =====

    @Test
    @DisplayName("containersRealtimeScan with valid source path throws IOException on error")
    void testContainersRealtimeScan_ValidSourcePath() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Container runtime not available"));

            assertThrows(IOException.class, () -> subject.containersRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("containersRealtimeScan throws IOException on CLI error")
    void testContainersRealtimeScan_CliError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("CLI not found"));

            assertThrows(IOException.class, () -> subject.containersRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("containersRealtimeScan throws CxException on error")
    void testContainersRealtimeScan_Error() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(403, "Access denied"));

            assertThrows(CxException.class, () -> subject.containersRealtimeScan("/app", null));
        }
    }

    @Test
    @DisplayName("containersRealtimeScan throws NullPointerException when source is null")
    void testContainersRealtimeScan_NullSource() {
        assertThrows(NullPointerException.class, () -> {
            subject.containersRealtimeScan(null, null);
        });
    }

    @Test
    @DisplayName("containersRealtimeScan with ignoredFiles parameter throws CxException")
    void testContainersRealtimeScan_WithIgnoredFiles() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(400, "Invalid Docker ignore file"));

            assertThrows(CxException.class, () -> subject.containersRealtimeScan("/app", ".dockerignore"));
        }
    }

    // ===== Results and Results Summary Tests =====

    @Test
    @DisplayName("results with valid scan ID throws IOException when Execution fails")
    void testResults_ValidScanId() throws Exception {
        String testScanId = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Failed to retrieve results"));

            assertThrows(IOException.class, () ->
                subject.results(java.util.UUID.fromString(testScanId)));
        }
    }

    @Test
    @DisplayName("results throws IOException on network error")
    void testResults_NetworkError() throws Exception {
        String testScanId = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Connection lost"));

            assertThrows(IOException.class, () ->
                subject.results(java.util.UUID.fromString(testScanId)));
        }
    }

    @Test
    @DisplayName("results with agent parameter throws IOException on error")
    void testResults_WithAgent() throws Exception {
        String testScanId = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(500, "Server error"));

            assertThrows(CxException.class, () ->
                subject.results(java.util.UUID.fromString(testScanId), "Jenkins"));
        }
    }

    @Test
    @DisplayName("resultsSummary with valid scan ID throws IOException on failure")
    void testResultsSummary_ValidScanId() throws Exception {
        String testScanId = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new IOException("Failed to retrieve results summary"));

            assertThrows(IOException.class, () ->
                subject.resultsSummary(java.util.UUID.fromString(testScanId)));
        }
    }

    @Test
    @DisplayName("resultsSummary throws CxException on API error")
    void testResultsSummary_Error() throws Exception {
        String testScanId = "3f6a5b2c-1d4e-4f8a-9c0b-7e2d1a3f5c8e";
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(any(), any(), any()))
                .thenThrow(new CxException(503, "Service unavailable"));

            assertThrows(CxException.class, () ->
                subject.resultsSummary(java.util.UUID.fromString(testScanId)));
        }
    }
}
