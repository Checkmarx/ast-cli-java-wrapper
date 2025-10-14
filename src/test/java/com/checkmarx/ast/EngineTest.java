package com.checkmarx.ast;

import com.checkmarx.ast.engines.Engines;
import com.checkmarx.ast.wrapper.CxException;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EngineTest extends BaseTest{

    private static final Logger logger = LoggerFactory.getLogger(EngineTest.class);
    @Test
    void testApiList1() throws Exception {
        Engines enginesList = wrapper.listApi("");
        logger.info(enginesList.toString());
        Assertions.assertTrue(enginesList.getEnginesList().length>0);
    }

    @Test
    void testApiList2() throws Exception {
        Engines enginesList = wrapper.listApi("SAST");
        logger.info(enginesList.toString());
        Assertions.assertTrue(enginesList.getEnginesList().length>0);
    }

    @Test
    void testApiList3() throws Exception {
        Engines enginesList = wrapper.listApi("SCA");
        logger.info(enginesList.toString());
        Assertions.assertTrue(enginesList.getEnginesList().length>0);
    }
    @Test
    void testApiList4() throws Exception {
        Engines enginesList = wrapper.listApi("Iac");
        logger.info(enginesList.toString());
        Assertions.assertTrue(enginesList.getEnginesList().length>0);
    }
    @SneakyThrows
    @Test
    void testApiList5() throws Exception {
        Engines enginesList = wrapper.listApi("xyz");
Assertions.assertEquals(null,enginesList);
    }
}
