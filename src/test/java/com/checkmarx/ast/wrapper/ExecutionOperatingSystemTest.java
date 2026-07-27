package com.checkmarx.ast.wrapper;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExecutionOperatingSystemTest {

    // Branch inventory for getOperatingSystemType(String osName):
    //   Branch 1: osName.contains("linux")  → "linux"
    //   Branch 2: osName.contains("windows") → "windows"
    //   Branch 3: OS_MAC_NAMES.stream().anyMatch(osName::contains) → "mac"
    //             (mac os x, darwin, osx)
    //   Branch 4: none of the above → "UNKNOWN"

    @Test
    void testGetOperatingSystemType_linux() {
        assertEquals("linux", Execution.getOperatingSystemType("linux"));
    }

    @Test
    void testGetOperatingSystemType_linuxWithVersion() {
        assertEquals("linux", Execution.getOperatingSystemType("ubuntu linux 22.04"));
    }

    @Test
    void testGetOperatingSystemType_windows() {
        assertEquals("windows", Execution.getOperatingSystemType("windows 10"));
    }

    @Test
    void testGetOperatingSystemType_windowsServer() {
        assertEquals("windows", Execution.getOperatingSystemType("windows server 2019"));
    }

    @Test
    void testGetOperatingSystemType_macOsX() {
        assertEquals("mac", Execution.getOperatingSystemType("mac os x"));
    }

    @Test
    void testGetOperatingSystemType_darwin() {
        assertEquals("mac", Execution.getOperatingSystemType("darwin"));
    }

    @Test
    void testGetOperatingSystemType_osx() {
        assertEquals("mac", Execution.getOperatingSystemType("osx"));
    }

    @Test
    void testGetOperatingSystemType_unknown() {
        assertEquals("UNKNOWN", Execution.getOperatingSystemType("freebsd"));
    }

    @Test
    void testGetOperatingSystemType_unknownSolaris() {
        assertEquals("UNKNOWN", Execution.getOperatingSystemType("sunos"));
    }
}
