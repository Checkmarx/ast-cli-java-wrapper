package com.checkmarx.ast;

import com.checkmarx.ast.project.Project;
import com.checkmarx.ast.wrapper.CxConfig;
import com.checkmarx.ast.wrapper.CxConstants;
import com.checkmarx.ast.wrapper.CxWrapper;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class BaseTest {

    private static final String CX_BASE_URI = getEnvOrNull("CX_BASE_URI");
    private static final String CX_BASE_AUTH_URI = getEnvOrNull("CX_BASE_AUTH_URI");
    private static final String CX_TENANT = getEnvOrNull("CX_TENANT");
    private static final String CX_APIKEY = getEnvOrNull("CX_APIKEY");
    private static final String CX_CLIENT_ID = getEnvOrNull("CX_CLIENT_ID");
    private static final String CX_CLIENT_SECRET = getEnvOrNull("CX_CLIENT_SECRET");
    private static final String CX_ADDITIONAL_PARAMETERS = getEnvOrNull("CX_ADDITIONAL_PARAMETERS");
    private static final String PATH_TO_EXECUTABLE = getEnvOrNull("PATH_TO_EXECUTABLE");
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    protected CxWrapper wrapper;
    private String projectId;

    protected static CxConfig getConfig() {
        return CxConfig.builder()
                .baseUri(CX_BASE_URI)
                .baseAuthUri(CX_BASE_AUTH_URI)
                .tenant(CX_TENANT)
                .apiKey(CX_APIKEY)
                .clientId(CX_CLIENT_ID)
                .clientSecret(CX_CLIENT_SECRET)
                .additionalParameters(CX_ADDITIONAL_PARAMETERS)
                .pathToExecutable(PATH_TO_EXECUTABLE)
                .build();
    }

    private static String getEnvOrNull(String key) {
        return System.getenv().getOrDefault(key, null);
    }

    @BeforeEach
    public void init() throws Exception {
        wrapper = new CxWrapper(getConfig(), getLogger());
        cleanupTestProject();
    }

    protected void cleanupTestProject() {
        try {
            List<Project> projects = wrapper.projectList("limit=10000&name=cli-java-wrapper-tests");
            if (projects != null && !projects.isEmpty()) {
                logger.info("Found existing test project, cleaning up...");
                // Project cleanup is handled by platform retention policy
            }
        } catch (Exception e) {
            logger.debug("Cleanup check failed (non-critical): {}", e.getMessage());
        }
    }

    protected Logger getLogger() {
        return logger;
    }

    protected Map<String, String> commonParams() {
        Map<String, String> params = new HashMap<>();
        params.put(CxConstants.PROJECT_NAME, "cli-java-wrapper-tests");
        params.put(CxConstants.SOURCE, ".");
        params.put(CxConstants.FILE_FILTER, "!test");
        params.put(CxConstants.BRANCH, "main");
        params.put(CxConstants.SAST_PRESET_NAME, "Checkmarx Default");
        params.put(CxConstants.AGENT, "CLI-Java-Wrapper");
        return params;
    }
}
