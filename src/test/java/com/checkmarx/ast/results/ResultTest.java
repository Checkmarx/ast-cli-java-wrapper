package com.checkmarx.ast.results;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.codebashing.CodeBashing;
import com.checkmarx.ast.results.ReportFormat;
import com.checkmarx.ast.results.Results;
import com.checkmarx.ast.results.ResultsSummary;
import com.checkmarx.ast.results.result.Data;
import com.checkmarx.ast.results.result.Node;
import com.checkmarx.ast.results.result.Result;
import com.checkmarx.ast.scan.Scan;
import com.checkmarx.ast.wrapper.CxConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

class ResultTest extends BaseTest {
    private static String CWE_ID = "79";
    private static String LANGUAGE = "PHP";
    private static String QUERY_NAME = "Reflected XSS All Clients";

    @Test
    void testResultsHTML() throws Exception {
        List<Scan> scanList = wrapper.scanList("statuses=Completed");
        Assertions.assertTrue(scanList.size() > 0);
        String scanId = scanList.get(0).getId();
        String results = wrapper.results(UUID.fromString(scanId), ReportFormat.summaryHTML);
        Assertions.assertTrue(results.length() > 0);
    }

    @Test
    void testResultsJSON() throws Exception {
        List<Scan> scanList = wrapper.scanList("statuses=Completed");
        Assertions.assertTrue(scanList.size() > 0);
        String scanId = scanList.get(0).getId();
        String results = wrapper.results(UUID.fromString(scanId), ReportFormat.json, "java-wrapper");
        Assertions.assertTrue(results.length() > 0);
    }

    @Test
    void testResultsSummaryJSON() throws Exception {
        List<Scan> scanList = wrapper.scanList("statuses=Completed");
        Assertions.assertTrue(scanList.size() > 0);
        String scanId = scanList.get(0).getId();
        ResultsSummary results = wrapper.resultsSummary(UUID.fromString(scanId));
        Assertions.assertNotNull(results.getScanId());
    }

    @Test()
    void testResultsStructure() throws Exception {
        List<Scan> scanList = wrapper.scanList("statuses=Completed");
        Assertions.assertTrue(scanList.size() > 0);
        for (Scan scan : scanList) {
            Results results = wrapper.results(UUID.fromString(scan.getId()));
            if (results != null && results.getResults() != null) {
                Assertions.assertEquals(results.getTotalCount(), results.getResults().size());
                return;
            }
        }
        Assertions.assertTrue(false, "No results found");
    }

    @Test()
    void testResultsCodeBashing() throws Exception {
        List<CodeBashing> codeBashingList = wrapper.codeBashingList(CWE_ID, LANGUAGE, QUERY_NAME);
        Assertions.assertTrue(codeBashingList.size() > 0);
        String path = codeBashingList.get(0).getPath();
        Assertions.assertTrue(path.length() > 0);
    }

    @Test
    void testResultsBflJSON() throws Exception {
        Map<String, String> params = commonParams();
        Scan scan = wrapper.scanCreate(params);
        UUID scanId = UUID.fromString(scan.getId());

        Assertions.assertEquals("Completed", wrapper.scanShow(scanId).getStatus());

        Results results = wrapper.results(scanId);
        Result result = results.getResults().stream().filter(res -> res.getType().equalsIgnoreCase(CxConstants.SAST)).findFirst().get();
        Data data = result.getData();
        String queryId = data.getQueryId();
        int bflNodeIndex = wrapper.getResultsBfl(scanId, queryId, data.getNodes());
        Assertions.assertTrue(bflNodeIndex == -1 || bflNodeIndex >= 0);

        String queryIdInvalid = "0000";
        int bflNodeIndexInvalid = wrapper.getResultsBfl(scanId, queryIdInvalid, new ArrayList<Node>());
        Assertions.assertEquals(-1, bflNodeIndexInvalid);
    }
}
