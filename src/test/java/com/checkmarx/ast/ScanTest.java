package com.checkmarx.ast;

import com.checkmarx.ast.asca.ScanDetail;
import com.checkmarx.ast.asca.ScanResult;
import com.checkmarx.ast.kicsRealtimeResults.KicsRealtimeResults;
import com.checkmarx.ast.ossrealtime.OssRealtimeResults;
import com.checkmarx.ast.scan.Scan;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

class ScanTest extends BaseTest {

    @Test
    void testScanShow() throws Exception {
        List<Scan> scanList = wrapper.scanList();
        Assertions.assertTrue(scanList.size() > 0);
        Scan scan = wrapper.scanShow(UUID.fromString(scanList.get(0).getId()));
        Assertions.assertEquals(scanList.get(0).getId(), scan.getId());
    }

    @Test
    void testScanAsca_WhenFileWithVulnerabilitiesIsSentWithAgent_ReturnSuccessfulResponseWithCorrectValues() throws Exception {
        ScanResult scanResult = wrapper.ScanAsca("src/test/resources/python-vul-file.py", true, "vscode");

        // Assertions for the scan result
        Assertions.assertNotNull(scanResult.getRequestId(), "Request ID should not be null");
        Assertions.assertTrue(scanResult.isStatus(), "Status should be true");
        Assertions.assertNull(scanResult.getError(), "Error should be null");

        // Ensure scan details are not null and contains at least one entry
        Assertions.assertNotNull(scanResult.getScanDetails(), "Scan details should not be null");
        Assertions.assertFalse(scanResult.getScanDetails().isEmpty(), "Scan details should contain at least one entry");

        // Iterate over all scan details and validate each one
        for (ScanDetail scanDetail : scanResult.getScanDetails()) {
            Assertions.assertNotNull(scanDetail.getRemediationAdvise(), "Remediation advise should not be null");
            Assertions.assertNotNull(scanDetail.getDescription(), "Description should not be null");
        }
    }


    @Test
    void testScanAsca_WhenFileWithoutVulnerabilitiesIsSent_ReturnSuccessfulResponseWithCorrectValues() throws Exception {
        ScanResult scanResult = wrapper.ScanAsca("src/test/resources/csharp-no-vul.cs", true, null);
        Assertions.assertNotNull(scanResult.getRequestId());
        Assertions.assertTrue(scanResult.isStatus());
        Assertions.assertNull(scanResult.getError());
        Assertions.assertNull(scanResult.getScanDetails()); // When no vulnerabilities are found, scan details is null
    }

    @Test
    void testScanAsca_WhenMissingFileExtension_ReturnFileExtensionIsRequiredFailure() throws Exception {
        ScanResult scanResult = wrapper.ScanAsca("CODEOWNERS", true, null);
        Assertions.assertNotNull(scanResult.getRequestId());
        Assertions.assertNotNull(scanResult.getError());
        Assertions.assertEquals("The file name must have an extension.", scanResult.getError().getDescription());
    }

    @Test
    void testScanList() throws Exception {
        List<Scan> cxOutput = wrapper.scanList("limit=10");
        Assertions.assertTrue(cxOutput.size() <= 10);
    }

    @Test
    void testScanCreate() throws Exception {
        Map<String, String> params = commonParams();
        Scan scan = wrapper.scanCreate(params);
        Assertions.assertEquals("Completed", wrapper.scanShow(UUID.fromString(scan.getId())).getStatus());
    }

    @Test
    void testScanCreateWithAsyncAndDebugFlag_ShouldParseScanResponseSuccessfully() throws Exception {
        Map<String, String> params = commonParams();
        Scan scan = wrapper.scanCreate(params, "--debug --async");
        Assertions.assertNotNull(scan);
    }

    @Test
    void testScanCancel() throws Exception {
        Map<String, String> params = commonParams();
        Scan scan = wrapper.scanCreate(params, "--async --sast-incremental");
        Assertions.assertDoesNotThrow(() -> wrapper.scanCancel(scan.getId()));
    }

    @Test
    void testKicsRealtimeScan() throws Exception {
        KicsRealtimeResults scan = wrapper.kicsRealtimeScan("target/test-classes/Dockerfile","","v");
        Assertions.assertTrue(scan.getResults().size() >= 1);
    }

    @Test
    void testOssRealtimeScanWithIgnoredFile() throws Exception {
        Assumptions.assumeTrue(getConfig().getPathToExecutable() != null && !getConfig().getPathToExecutable().isEmpty(), "PATH_TO_EXECUTABLE not set");

        String source = "pom.xml";
        String ignoreFile = "src/test/resources/ignored-packages.json";

        OssRealtimeResults results = wrapper.ossRealtimeScan(source, ignoreFile);

        Assertions.assertNotNull(results);
        Assertions.assertNotNull(results.getPackages());
    }

}
