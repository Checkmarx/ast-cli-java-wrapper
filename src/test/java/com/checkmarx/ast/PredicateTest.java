package com.checkmarx.ast;

import com.checkmarx.ast.predicate.CustomState;
import com.checkmarx.ast.predicate.Predicate;
import com.checkmarx.ast.results.Results;
import com.checkmarx.ast.results.result.Result;
import com.checkmarx.ast.scan.Scan;
import com.checkmarx.ast.wrapper.CxConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

class PredicateTest extends BaseTest {

    public static final String TO_VERIFY = "TO_VERIFY";
    public static final String HIGH = "HIGH";

    @Test
    void testTriage() throws Exception {
        Map<String, String> params = commonParams();
        Scan scan = wrapper.scanCreate(params);
        UUID scanId = UUID.fromString(scan.getId());

        Assertions.assertEquals("Completed", wrapper.scanShow(scanId).getStatus());

        Results results = wrapper.results(scanId);
        Result result = results.getResults().stream().filter(res -> res.getType().equalsIgnoreCase(CxConstants.SAST)).findFirst().get();

        List<Predicate> predicates = wrapper.triageShow(UUID.fromString(scan.getProjectId()), result.getSimilarityId(), result.getType());

        Assertions.assertNotNull(predicates);

        try {
            wrapper.triageUpdate(UUID.fromString(scan.getProjectId()), result.getSimilarityId(), result.getType(), TO_VERIFY, "Edited via Java Wrapper", HIGH);
        } catch (Exception e) {
            Assertions.fail("Triage update failed. Should not throw exception");
        }

        try {
            wrapper.triageUpdate(UUID.fromString(scan.getProjectId()), result.getSimilarityId(), result.getType(), result.getState(), "Edited back to normal", result.getSeverity());
        } catch (Exception e) {
            Assertions.fail("Triage update failed. Should not throw exception");
        }
    }

    @Test
    void testGetStates() throws Exception {
        List<CustomState> states = wrapper.triageGetStates(false);
        Assertions.assertNotNull(states);
    }

    @Test
    void testScaTriage() throws Exception {
        // Automatically find a completed scan that has SCA results
        List<Scan> scans = wrapper.scanList("statuses=Completed");

        Scan scaScan = null;
        Result scaResult = null;

        for (Scan scan : scans) {
            Results results = wrapper.results(UUID.fromString(scan.getId()));
            scaResult = results.getResults().stream()
                    .filter(res -> res.getType().equalsIgnoreCase("sca"))
                    .findFirst()
                    .orElse(null);
            if (scaResult != null) {
                scaScan = scan;
                break;
            }
        }

        Assumptions.assumeTrue(scaScan != null, "Skipping: no completed scan with SCA results found");

        String packageIdentifier = scaResult.getData().getPackageIdentifier();
        int firstDash = packageIdentifier.indexOf('-');
        int lastDash = packageIdentifier.lastIndexOf('-');
        String vulnerabilities = String.format("packagename=%s,packageversion=%s,vulnerabilityId=%s,packagemanager=%s",
                packageIdentifier.substring(firstDash + 1, lastDash),
                packageIdentifier.substring(lastDash + 1),
                scaResult.getVulnerabilityDetails().getCveName(),
                packageIdentifier.substring(0, firstDash).toLowerCase());

        List<Predicate> predicates = wrapper.triageScaShow(UUID.fromString(scaScan.getProjectId()), vulnerabilities, scaResult.getType());
        Assertions.assertNotNull(predicates);

        try {
            wrapper.triageScaUpdate(UUID.fromString(scaScan.getProjectId()), TO_VERIFY, "Edited via Java Wrapper", vulnerabilities, scaResult.getType());
        } catch (Exception e) {
            Assertions.fail("SCA triage update failed. Should not throw exception");
        }
    }
}
