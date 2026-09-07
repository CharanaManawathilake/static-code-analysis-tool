/*
 *  Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.scan.internal;

import io.ballerina.projects.Project;
import io.ballerina.projects.directory.ProjectLoader;
import io.ballerina.scan.BaseTest;
import io.ballerina.scan.Issue;
import io.ballerina.scan.Source;
import io.ballerina.scan.utils.ScanUtils;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.ballerinalang.compiler.diagnostic.BLangDiagnosticLocation;

import java.nio.file.Path;
import java.util.List;

/**
 * Tests verifying that optional rule metadata fields are included in, or omitted from, the
 * Ballerina JSON and SARIF output depending on whether the underlying rule's bundled metadata
 * specifies them.
 *
 * @since 0.1.0
 */
public class CoreRuleOutputTest extends BaseTest {
    private final Path balProject = testResources.resolve("test-resources")
            .resolve("bal-project-with-analyzer-configurations");

    // Location known to fall within bal-project-with-analyzer-configurations/main.bal.
    private final BLangDiagnosticLocation location = new BLangDiagnosticLocation("main.bal", 20, 20, 17, 39, 777, 22);

    @Test(description = "test that precision is omitted, cwe/owasp never appear, and securitySeverity is present "
            + "in the Ballerina JSON output")
    void testOptionalFieldsOmittedFromJsonOutput() {
        Issue issue = new IssueImpl(location, CoreRule.AVOID_CHECKPANIC.rule(), Source.BUILT_IN, "main.bal",
                balProject.resolve("main.bal").toString());
        String json = ScanUtils.convertIssuesToJsonString(List.of(issue));

        Assert.assertFalse(json.contains("\"precision\""),
                "precision should be omitted since rule 1's metadata does not specify one");
        Assert.assertTrue(json.contains("\"securitySeverity\": 5.3"),
                "securitySeverity should be present since every core rule now specifies one");
        Assert.assertFalse(json.contains("\"cwe\""),
                "cwe should never appear in the Ballerina JSON output (redundant with tags)");
        Assert.assertFalse(json.contains("\"owasp\""),
                "owasp should never appear in the Ballerina JSON output (redundant with tags)");
        Assert.assertTrue(json.contains("\"tags\""), "tags should still be present");
        Assert.assertTrue(json.contains("\"fullDescription\""), "fullDescription should still be present");
        Assert.assertTrue(json.contains("\"snippet\""), "snippet should be present for a resolvable location");
    }

    @Test(description = "test that securitySeverity is included in the Ballerina JSON output when specified")
    void testSecuritySeverityIncludedInJsonOutputWhenSpecified() {
        Issue issue = new IssueImpl(location, CoreRule.HARD_CODED_SECRET.rule(), Source.BUILT_IN, "main.bal",
                balProject.resolve("main.bal").toString());
        String json = ScanUtils.convertIssuesToJsonString(List.of(issue));

        Assert.assertTrue(json.contains("\"securitySeverity\": 8.6"),
                "securitySeverity should be present since rule 13's metadata specifies one");
        Assert.assertFalse(json.contains("\"precision\""),
                "precision should still be omitted since rule 13's metadata does not specify one");
    }

    @Test(description = "test that precision is omitted and security-severity is present in the SARIF output")
    void testOptionalFieldsOmittedFromSarifOutput() throws Exception {
        Project project = ProjectLoader.load(balProject).project();
        Issue issue = new IssueImpl(location, CoreRule.AVOID_CHECKPANIC.rule(), Source.BUILT_IN, "main.bal",
                balProject.resolve("main.bal").toString());
        String sarif = ScanUtils.convertIssuesToSarifString(List.of(issue), project);

        Assert.assertFalse(sarif.contains("\"precision\""),
                "SARIF properties should omit precision since rule 1's metadata does not specify one");
        Assert.assertTrue(sarif.contains("\"security-severity\": \"5.3\""),
                "SARIF properties should include security-severity since every core rule now specifies one");
        Assert.assertTrue(sarif.contains("\"tags\""), "SARIF properties should still include tags");
        Assert.assertTrue(sarif.contains("\"snippet\""), "SARIF region should include a source snippet");
    }

    @Test(description = "test that security-severity is included in the SARIF output when specified")
    void testSecuritySeverityIncludedInSarifOutputWhenSpecified() throws Exception {
        Project project = ProjectLoader.load(balProject).project();
        Issue issue = new IssueImpl(location, CoreRule.HARD_CODED_SECRET.rule(), Source.BUILT_IN, "main.bal",
                balProject.resolve("main.bal").toString());
        String sarif = ScanUtils.convertIssuesToSarifString(List.of(issue), project);

        Assert.assertTrue(sarif.contains("\"security-severity\": \"8.6\""),
                "SARIF properties should include security-severity since rule 13's metadata specifies one");
        Assert.assertFalse(sarif.contains("\"precision\""),
                "SARIF properties should still omit precision since rule 13's metadata does not specify one");
    }
}
