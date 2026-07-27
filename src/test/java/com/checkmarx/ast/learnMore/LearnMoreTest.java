package com.checkmarx.ast.learnMore;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.learnMore.LearnMore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.List;

class LearnMoreTest extends BaseTest {
    private static String QUERY_ID = "16772998409937314312";

    @Test
    void testLearnMore() throws Exception {
        List<LearnMore> learnMore = wrapper.learnMore(QUERY_ID);
        Assertions.assertTrue(learnMore.size()>0);
    }

}
