package com.checkmarx.ast.remediation;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.remediation.KicsRemediation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.nio.file.Paths;

class RemediationTest extends BaseTest {
    private static String RESULTS_FILE = "target/test-classes/results.json";

    private static Path path = Paths.get("target/test-classes/");
    private static String KICS_FILE = path.toAbsolutePath().toString();
    private static String QUERY_ID = "9574288c118e8c87eea31b6f0b011295a39ec5e70d83fb70e839b8db4a99eba8";
    private static String ENGINE = "docker";

    @Test
    void testKicsRemediation() throws Exception {
        KicsRemediation remediation = wrapper.kicsRemediate(RESULTS_FILE,KICS_FILE,"","");
        Assertions.assertTrue(remediation.getAppliedRemediation() != "");
        Assertions.assertTrue(remediation.getAvailableRemediation() != "");
    }

    @Test
    void testKicsRemediationSimilarityFilter() throws Exception {
        KicsRemediation remediation = wrapper.kicsRemediate(RESULTS_FILE,KICS_FILE,ENGINE,QUERY_ID);
        Assertions.assertTrue(remediation.getAppliedRemediation() != "");
        Assertions.assertTrue(remediation.getAvailableRemediation() != "");
    }

}
