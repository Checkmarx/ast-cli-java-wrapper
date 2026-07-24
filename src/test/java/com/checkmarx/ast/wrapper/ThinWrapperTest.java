package com.checkmarx.ast.wrapper;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.scan.Scan;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class ThinWrapperTest extends BaseTest {

    @SneakyThrows
    @Test
    public void testThinWrapper() {
        CxThinWrapper wrapper = new CxThinWrapper(getLogger());
        String result = wrapper.run("scan list --format json --filter limit=10");
        List<Scan> scanList = Scan.listFromLine(result);
        Assumptions.assumeTrue(scanList != null, "Scan list unavailable");
        Assertions.assertTrue(scanList.size() <= 10);
    }

    @SneakyThrows
    @Test
    public void testThinWrapperFail() {
        CxThinWrapper wrapper = new CxThinWrapper(getLogger());
        String arguments = "scan create -s . --project-name thin-wrapper-test --sast-preset invalid-preset";
        CxException e = Assertions.assertThrows(CxException.class, () -> wrapper.run(arguments));
        Assertions.assertTrue(e.getMessage().contains("--sast-preset"));
    }
}
