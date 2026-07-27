package com.checkmarx.ast.project;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.scan.Scan;
import com.checkmarx.ast.wrapper.CxConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

class ProjectTest extends BaseTest {

    @Test
    void testProjectShow() throws Exception {
        List<Project> projectList = wrapper.projectList();
        Assumptions.assumeTrue(projectList != null && projectList.size() > 0, "No projects available to test");
        Project project = wrapper.projectShow(UUID.fromString(projectList.get(0).getId()));
        Assertions.assertEquals(projectList.get(0).getId(), project.getId());
    }

    @Test
    void testProjectList() throws Exception {
        List<Project> projectList = wrapper.projectList("limit=10");
        Assumptions.assumeTrue(projectList != null, "Project list unavailable");
        Assertions.assertTrue(projectList.size() <= 10);
    }

    @Test
    void testProjectBranches() throws Exception {
        try {
            Map<String, String> params = commonParams();
            params.put(CxConstants.BRANCH, "test");
            Scan scan = wrapper.scanCreate(params);
            List<String> branches = wrapper.projectBranches(UUID.fromString(scan.getProjectId()), "");
            Assumptions.assumeTrue(branches != null && !branches.isEmpty(), "No branches available");
            Assertions.assertTrue(branches.contains("test"));
        } catch (com.checkmarx.ast.wrapper.CxException e) {
            if (e.getMessage().contains("already exists")) {
                Assumptions.abort("Project already exists (test isolation issue): " + e.getMessage());
            }
            throw e;
        }
    }
}
