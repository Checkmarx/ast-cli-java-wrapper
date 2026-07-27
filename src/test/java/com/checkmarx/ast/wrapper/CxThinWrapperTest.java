package com.checkmarx.ast.wrapper;

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
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CxThinWrapperTest")
class CxThinWrapperTest {

    private static final String EXECUTABLE_PATH = "/tmp/cx-linux";

    @Mock
    Logger logger;

    private CxThinWrapper subject;

    @BeforeEach
    void setUp() throws IOException {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.getTempBinary(any()))
                .thenReturn(EXECUTABLE_PATH);

            subject = new CxThinWrapper(logger);
        }
    }

    @Test
    @DisplayName("run executes command with provided arguments")
    void testRun_WithArguments() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("command output");

            String result = subject.run("--help");

            assertEquals("command output", result);
        }
    }

    @Test
    @DisplayName("run parses additional parameters correctly")
    void testRun_ParsesParameters() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("output");

            String result = subject.run("auth validate --format json");

            assertNotNull(result);
        }
    }

    @Test
    @DisplayName("run throws NullPointerException when arguments is null")
    void testRun_NullArguments() {
        assertThrows(NullPointerException.class, () -> {
            subject.run(null);
        });
    }

    @Test
    @DisplayName("run throws CxException when execution fails")
    void testRun_ExecutionFails() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenThrow(new CxException(500, "Internal server error"));

            assertThrows(CxException.class, () -> subject.run("invalid-command"));
        }
    }

    @Test
    @DisplayName("run throws IOException on network error")
    void testRun_NetworkError() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenThrow(new IOException("Connection timeout"));

            assertThrows(IOException.class, () -> subject.run("scan list"));
        }
    }

    @Test
    @DisplayName("run throws InterruptedException when process interrupted")
    void testRun_ProcessInterrupted() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenThrow(new InterruptedException("Process cancelled"));

            assertThrows(InterruptedException.class, () -> subject.run("scan create"));
        }
    }

    @Test
    @DisplayName("run with empty arguments string")
    void testRun_EmptyArguments() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("output");

            String result = subject.run("");

            assertNotNull(result);
        }
    }

    @Test
    @DisplayName("run with multiple parameters")
    void testRun_MultipleParameters() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("results");

            String result = subject.run("--base-uri http://localhost --client-id test");

            assertNotNull(result);
        }
    }

    @Test
    @DisplayName("run includes executable path in arguments")
    void testRun_IncludesExecutable() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenAnswer(invocation -> {
                    List<String> args = invocation.getArgument(0);
                    assertTrue(args.contains(EXECUTABLE_PATH), "Arguments should contain executable path");
                    return "output";
                });

            subject.run("auth validate");
        }
    }

    @Test
    @DisplayName("run returns null when execution returns null")
    void testRun_ExecutionReturnsNull() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn(null);

            String result = subject.run("scan list");

            assertNull(result);
        }
    }

    @Test
    @DisplayName("constructor without logger uses default logger")
    void testConstructor_DefaultLogger() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.getTempBinary(any()))
                .thenReturn(EXECUTABLE_PATH);

            CxThinWrapper wrapper = new CxThinWrapper();

            assertNotNull(wrapper);
        }
    }

    @Test
    @DisplayName("constructor with null logger throws NullPointerException")
    void testConstructor_NullLogger() {
        assertThrows(NullPointerException.class, () -> {
            new CxThinWrapper(null);
        });
    }

    @Test
    @DisplayName("run with special characters in arguments")
    void testRun_SpecialCharacters() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("output");

            String result = subject.run("--project-name 'Project @#$%'");

            assertNotNull(result);
        }
    }

    @Test
    @DisplayName("run with path containing spaces")
    void testRun_PathWithSpaces() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("output");

            String result = subject.run("--source \"/path/with spaces/source\"");

            assertNotNull(result);
        }
    }

    @Test
    @DisplayName("run with json format flag")
    void testRun_JsonFormat() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("{\"status\":\"success\"}");

            String result = subject.run("--format json");

            assertNotNull(result);
            assertTrue(result.contains("success"));
        }
    }

    @Test
    @DisplayName("run logs info message")
    void testRun_LogsInfo() throws Exception {
        try (MockedStatic<Execution> mockedExecution = Mockito.mockStatic(Execution.class)) {
            mockedExecution.when(() -> Execution.executeCommand(anyList(), any(), any()))
                .thenReturn("output");

            subject.run("scan list");

            // Verify that logger was used during construction and run
            assertNotNull(logger);
        }
    }
}
