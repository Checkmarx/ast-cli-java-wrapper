package com.checkmarx.ast.project;

import com.checkmarx.ast.BaseTest;
import com.checkmarx.ast.project.Project;
import com.checkmarx.ast.scan.Scan;
import com.checkmarx.ast.wrapper.CxConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

class ProjectTest extends BaseTest {

    @Test
    void testProjectShow() throws Exception {
        List<Project> projectList = wrapper.projectList();
        Assertions.assertTrue(projectList.size() > 0);
        Project project = wrapper.projectShow(UUID.fromString(projectList.get(0).getId()));
        Assertions.assertEquals(projectList.get(0).getId(), project.getId());
    }

    @Test
    void testProjectList() throws Exception {
        List<Project> projectList = wrapper.projectList("limit=10");
        Assertions.assertTrue(projectList.size() <= 10);
    }

    @Test
    void testProjectBranches() throws Exception {
        Map<String, String> params = commonParams();
        params.put(CxConstants.BRANCH, "test");
        Scan scan = wrapper.scanCreate(params);
        List<String> branches = wrapper.projectBranches(UUID.fromString(scan.getProjectId()), "");
        Assertions.assertTrue(branches.size() >= 1);
        Assertions.assertTrue(branches.contains("test"));
    }
}
