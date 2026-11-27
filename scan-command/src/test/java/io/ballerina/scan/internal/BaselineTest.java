/*
 *  Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.ballerina.projects.Project;
import io.ballerina.projects.directory.BuildProject;
import io.ballerina.projects.directory.ProjectLoader;
import io.ballerina.projects.directory.WorkspaceProject;
import io.ballerina.projects.util.ProjectUtils;
import io.ballerina.scan.BaseTest;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.ballerina.scan.TestConstants.LINUX_LINE_SEPARATOR;
import static io.ballerina.scan.TestConstants.WINDOWS_LINE_SEPARATOR;

/**
 * Tests for the finding fingerprints and the baseline of the scan command, run on packages written to a temporary
 * directory so that each test can edit them.
 *
 * @since 0.15.0
 */
public class BaselineTest extends BaseTest {
    private static final String BASELINE = "scan-baseline.json";
    private static final String BASELINE_SCAN_TOML = """
            [baseline]
            path = "scan-baseline.json"
            """;
    private static final String FUNCTIONS = """
            function getResult() returns int|error => 1;

            """;
    // One ballerina:13 issue, and two identical ballerina:1 issues
    private static final String MAIN = FUNCTIONS + """
            public function main() {
                string password = "admin123";
                _ = checkpanic getResult();
                _ = checkpanic getResult();
            }
            """;
    private static final String TEST_SOURCE = """
            function testHelper() {
                _ = checkpanic getResult();
            }
            """;
    private static final int MAIN_ISSUES = 3;
    private static final int ALL_ISSUES = MAIN_ISSUES + 1;
    private Path workDirectory;
    private int projectCount;

    @BeforeClass
    void createWorkDirectory() throws IOException {
        workDirectory = Files.createTempDirectory("scan-baseline-test");
    }

    @AfterClass(alwaysRun = true)
    void deleteWorkDirectory() {
        ProjectUtils.deleteDirectory(workDirectory);
    }

    @Test(description = "test --create-baseline records every unsuppressed issue, reports each as unchanged and "
            + "never trips the gate, and a later scan gates only new issues")
    void testCreateAndCheck() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        ScanRun create = scan(project, "--create-baseline", "--fail-on-severity=LOW");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(create.err().contains("0 new issue(s), " + ALL_ISSUES + " in baseline"), create.output());
        Assert.assertTrue(create.err().contains("Saved " + ALL_ISSUES + " entries to the baseline at:\n\t"
                + project.resolve(BASELINE).toUri()), create.output());
        Assert.assertEquals(JsonParser.parseString(create.out()).getAsJsonArray().size(), 0, create.output());
        JsonArray results = results(project);
        Assert.assertEquals(results.size(), ALL_ISSUES);
        for (JsonElement result : results) {
            Assert.assertEquals(result.getAsJsonObject().get("baselineState").getAsString(), "unchanged");
            Assert.assertTrue(fingerprint(result).matches("[0-9a-f]{32}:[1-9][0-9]*"), result.toString());
        }

        String baseline = Files.readString(project.resolve(BASELINE), StandardCharsets.UTF_8);
        JsonObject baselineJson = JsonParser.parseString(baseline).getAsJsonObject();
        Assert.assertEquals(baselineJson.get("version").getAsInt(), 1);
        Assert.assertEquals(baselineJson.get("fingerprint").getAsString(), "ballerinaScanHash/v1");
        JsonArray entries = baselineJson.getAsJsonArray("issues");
        Assert.assertEquals(entries.size(), ALL_ISSUES);
        Set<String> baselined = new HashSet<>();
        entries.forEach(entry -> baselined.add(entry.getAsJsonObject().get("fingerprint").getAsString()));
        Set<String> reported = new HashSet<>();
        results.forEach(result -> reported.add(fingerprint(result)));
        Assert.assertEquals(baselined, reported);
        // The secret is redacted in the committed file
        Assert.assertFalse(baseline.contains("admin123"), baseline);
        Assert.assertTrue(baseline.contains("string password = \\\"***\\\";"), baseline);
        Assert.assertTrue(baseline.contains("\"filePath\": \"tests/main_test.bal\""), baseline);

        // A rerun leaves the file as it is
        ScanRun rerun = scan(project, "--create-baseline");
        Assert.assertEquals(rerun.exitCode(), 0, rerun.output());
        Assert.assertTrue(rerun.err().contains("The baseline already holds these " + ALL_ISSUES + " entries:"),
                rerun.output());
        Assert.assertEquals(Files.readString(project.resolve(BASELINE), StandardCharsets.UTF_8), baseline);

        ScanRun check = scan(project, "--fail-on-severity=LOW");
        Assert.assertEquals(check.exitCode(), 0, check.output());
        Assert.assertTrue(check.err().contains("0 new issue(s), " + ALL_ISSUES + " in baseline"), check.output());
        Assert.assertFalse(check.err().contains("warning"), check.output());
        Assert.assertEquals(Files.readString(project.resolve(BASELINE), StandardCharsets.UTF_8), baseline);
    }

    @Test(description = "test a new issue is printed, counted as new and trips the gate, while the reports keep "
            + "every issue with its baselineState")
    void testNewIssueTripsGate() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        writeMain(project, MAIN.replace("    string password = \"admin123\";\n",
                "    string password = \"admin123\";\n    string dbPassword = \"s3cr3t\";\n"));

        ScanRun run = scan(project, "--fail-on-severity=HIGH");
        Assert.assertEquals(run.exitCode(), 1, run.output());
        Assert.assertEquals(run.errorReport(), "bal scan: error: 1 issue at or above HIGH, limit 1 (HIGH: 1)");
        Assert.assertTrue(run.err().contains("1 new issue(s), " + ALL_ISSUES + " in baseline"), run.output());
        JsonArray printed = JsonParser.parseString(run.out()).getAsJsonArray();
        Assert.assertEquals(printed.size(), 1, run.out());
        Assert.assertEquals(printed.get(0).getAsJsonObject().get("baselineState").getAsString(), "new");
        Assert.assertEquals(printed.get(0).getAsJsonObject().getAsJsonObject("location").get("snippet")
                .getAsString(), "\"s3cr3t\"");

        JsonArray results = results(project);
        Assert.assertEquals(results.size(), ALL_ISSUES + 1);
        Assert.assertEquals(countState(results, "new"), 1);
        Assert.assertEquals(countState(results, "unchanged"), ALL_ISSUES);

        // Only --create-baseline accepts it
        Assert.assertEquals(scan(project, "--create-baseline", "--fail-on-severity=HIGH").exitCode(), 0);
        Assert.assertEquals(scan(project, "--fail-on-severity=HIGH").exitCode(), 0);
    }

    @Test(description = "test edits that do not change the flagged lines leave every issue in the baseline")
    void testUnrelatedEdits() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        // Lines and a function added above, the code re-indented, a comment on a flagged line, and CRLF line endings
        writeMain(project, ("""
                // Orders service

                function helper() returns int {
                    return 1;
                }

                """ + MAIN.replace("    string password = \"admin123\";",
                "\t\tstring  password = \"admin123\"; // TODO: move to a configurable"))
                .replace("\n", "\r\n"));
        ScanRun run = scan(project, "--fail-on-severity=LOW");
        Assert.assertEquals(run.exitCode(), 0, run.output());
        Assert.assertTrue(run.err().contains("0 new issue(s), " + ALL_ISSUES + " in baseline"), run.output());
    }

    @Test(description = "test a fixed issue leaves a stale entry, which a scan warns about and --prune-baseline "
            + "removes without adding the new issues")
    void testStaleEntriesAndPrune() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        // One of the two identical issues fixed, and a new issue added
        writeMain(project, MAIN.replaceFirst(" {4}_ = checkpanic getResult\\(\\);\n", "")
                .replace("    string password = \"admin123\";\n",
                        "    string password = \"admin123\";\n    string dbPassword = \"s3cr3t\";\n"));

        ScanRun check = scan(project);
        Assert.assertEquals(check.exitCode(), 0, check.output());
        Assert.assertTrue(check.err().contains("bal scan: warning: 1 entry of the baseline scan-baseline.json "
                + "matches no issue; run 'bal scan --prune-baseline' to remove it"), check.output());
        Assert.assertTrue(check.err().contains("1 new issue(s), " + (ALL_ISSUES - 1) + " in baseline"),
                check.output());

        ScanRun prune = scan(project, "--prune-baseline", "--fail-on-severity=HIGH");
        Assert.assertEquals(prune.exitCode(), 1, prune.output());
        Assert.assertEquals(prune.errorReport(), "bal scan: error: 1 issue at or above HIGH, limit 1 (HIGH: 1)");
        Assert.assertTrue(prune.err().contains("Removed 1 stale entry from the baseline at:"), prune.output());
        Assert.assertFalse(prune.err().contains("bal scan: warning"), prune.output());
        String pruned = Files.readString(project.resolve(BASELINE), StandardCharsets.UTF_8);
        Assert.assertEquals(entries(project).size(), ALL_ISSUES - 1);
        Assert.assertFalse(pruned.contains("dbPassword"), pruned);

        ScanRun again = scan(project, "--prune-baseline");
        Assert.assertTrue(again.err().contains("The baseline has no entries to remove:"), again.output());
        Assert.assertEquals(Files.readString(project.resolve(BASELINE), StandardCharsets.UTF_8), pruned);
        ScanRun after = scan(project);
        Assert.assertFalse(after.err().contains("bal scan: warning"), after.output());
    }

    @Test(description = "test identical issues are matched by count, so an added one is new and the numbers of "
            + "the others do not matter")
    void testIdenticalIssues() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        String oneMore = MAIN.replace("    string password = \"admin123\";\n",
                "    _ = checkpanic getResult();\n    string password = \"admin123\";\n");
        writeMain(project, oneMore);
        ScanRun run = scan(project);
        Assert.assertTrue(run.err().contains("1 new issue(s), " + ALL_ISSUES + " in baseline"), run.output());
        JsonArray printed = JsonParser.parseString(run.out()).getAsJsonArray();
        Assert.assertEquals(printed.size(), 1, run.out());
        // The last identical issue in source order is the new one, whichever was added
        Assert.assertEquals(printed.get(0).getAsJsonObject().getAsJsonObject("location").get("startLine")
                .getAsInt(), 7, run.out());
        Assert.assertTrue(fingerprint(printed.get(0)).endsWith(":3"), run.out());
    }

    @Test(description = "test a suppressed issue is never in the baseline, and is new when suppressions are "
            + "disregarded")
    void testSuppressedIssues() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML, "import ballerina/scan;\n\n" + FUNCTIONS + """
                public function main() {
                    string password = "admin123";
                    @scan:Suppress {rules: ["ballerina:1"], reason: "Always succeeds"}
                    int suppressed = checkpanic getResult();
                    _ = suppressed;
                }
                """);
        ScanRun create = scan(project, "--create-baseline");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(create.err().contains("0 new issue(s), 2 in baseline, 1 suppressed"), create.output());
        Assert.assertEquals(entries(project).size(), 2);
        JsonArray results = results(project);
        Assert.assertEquals(countState(results, "new"), 1, results.toString());
        for (JsonElement result : results) {
            boolean suppressed = result.getAsJsonObject().has("suppressions");
            Assert.assertEquals(result.getAsJsonObject().get("baselineState").getAsString(),
                    suppressed ? "new" : "unchanged");
        }

        ScanRun ignoring = scan(project, "--ignore-suppressions", "--fail-on-severity=LOW");
        Assert.assertEquals(ignoring.exitCode(), 1, ignoring.output());
        Assert.assertTrue(ignoring.err().contains("1 new issue(s), 2 in baseline"), ignoring.output());
    }

    @Test(description = "test --ignore-baseline reports every issue without baselineState and never reads the file")
    void testIgnoreBaseline() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Files.writeString(project.resolve(BASELINE), "not json");
        ScanRun run = scan(project, "--ignore-baseline", "--format=sarif");
        Assert.assertEquals(run.exitCode(), 0, run.output());
        Assert.assertTrue(run.err().contains(ALL_ISSUES + " issue(s)"), run.output());
        JsonArray sarifResults = sarifResults(project);
        Assert.assertEquals(sarifResults.size(), ALL_ISSUES);
        for (JsonElement result : sarifResults) {
            Assert.assertFalse(result.getAsJsonObject().has("baselineState"), result.toString());
            Assert.assertTrue(fingerprint(result).matches("[0-9a-f]{32}:[1-9][0-9]*"), result.toString());
        }

        // A platform tracks new issues itself, so a platform-triggered scan ignores the baseline too
        Assert.assertEquals(scan(project, "--platform-triggered").exitCode(), 0);
        // Without a baseline, the scan reports as it did before baselines
        Path withoutBaseline = createPackage(null);
        ScanRun plain = scan(withoutBaseline);
        Assert.assertEquals(plain.exitCode(), 0, plain.output());
        Assert.assertTrue(plain.err().contains(ALL_ISSUES + " issue(s)"), plain.output());
        Assert.assertFalse(plain.err().contains("in baseline"), plain.output());
        results(withoutBaseline).forEach(result -> Assert.assertFalse(result.getAsJsonObject().has("baselineState")));
    }

    @Test(description = "test SARIF results carry the fingerprint in partialFingerprints, never fingerprints, and "
            + "baselineState on every result")
    void testSarifReport() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        writeMain(project, MAIN.replace("    string password = \"admin123\";\n",
                "    string password = \"admin123\";\n    string dbPassword = \"s3cr3t\";\n"));
        ScanRun run = scan(project, "--format=sarif");
        Assert.assertEquals(run.exitCode(), 0, run.output());
        JsonArray sarifResults = sarifResults(project);
        Assert.assertEquals(sarifResults.size(), ALL_ISSUES + 1);
        Set<String> values = new HashSet<>();
        for (JsonElement result : sarifResults) {
            JsonObject resultObject = result.getAsJsonObject();
            Assert.assertFalse(resultObject.has("fingerprints"), resultObject.toString());
            Assert.assertEquals(resultObject.getAsJsonObject("partialFingerprints").keySet(),
                    Set.of("ballerinaScanHash/v1"));
            Assert.assertTrue(resultObject.has("baselineState"), resultObject.toString());
            values.add(fingerprint(result));
        }
        Assert.assertEquals(values.size(), ALL_ISSUES + 1, "every fingerprint of a run is unique");
        Assert.assertEquals(countState(sarifResults, "new"), 1);

        // Two scans of the same code give identical reports
        String first = Files.readString(project.resolve("target").resolve("report").resolve("scan_results.sarif"));
        Assert.assertEquals(scan(project, "--format=sarif").exitCode(), 0);
        Assert.assertEquals(Files.readString(project.resolve("target").resolve("report")
                .resolve("scan_results.sarif")), first);
    }

    @Test(description = "test invalid combinations and missing files of the baseline options are reported with "
            + "their exit codes")
    void testBaselineErrors() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        assertUsageError(scan(project, "--create-baseline", "--prune-baseline"),
                "--create-baseline and --prune-baseline cannot be used together");
        assertUsageError(scan(project, "--create-baseline", "--prune-baseline", "--ignore-baseline"),
                "--create-baseline, --prune-baseline and --ignore-baseline cannot be used together");
        assertUsageError(scan(project, "--prune-baseline", "--ignore-baseline"),
                "--prune-baseline and --ignore-baseline cannot be used together");
        assertUsageError(scan(project, "--baseline-path=missing.json"),
                "baseline missing.json given to --baseline-path does not exist; add --create-baseline to create it");
        assertUsageError(scan(project, "--baseline-path="), "invalid value '' for --baseline-path; expected the "
                + "path of a baseline file");
        assertUsageError(scan(project, "--baseline-path=tests"),
                "baseline tests is a directory; set the path of a file");

        // A configured file that does not exist is an error, so that a typo does not turn the baseline off
        ScanRun missing = scan(project);
        Assert.assertEquals(missing.exitCode(), 1, missing.output());
        Assert.assertEquals(missing.errorReport(), "bal scan: error: baseline scan-baseline.json set in Scan.toml "
                + "does not exist; run 'bal scan --create-baseline' to create it");
        Assert.assertFalse(missing.output().contains("Running Scans"), missing.output());

        Files.writeString(project.resolve(BASELINE), "{\n  \"version\": 3,\n  \"issues\": []\n}\n");
        ScanRun invalid = scan(project);
        Assert.assertEquals(invalid.exitCode(), 1, invalid.output());
        Assert.assertEquals(invalid.errorReport(), """
                bal scan: error: scan-baseline.json has 1 error
                scan-baseline.json:2:14: error: unsupported baseline version 3; this version of the scan tool reads \
                version 1""");
        // --create-baseline keeps the entries it does not cover, so it cannot replace a file it cannot read
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 1);

        Path withoutBaseline = createPackage(null);
        assertUsageError(scan(withoutBaseline, "--create-baseline"), "--create-baseline needs a baseline file; set "
                + "'path' in the [baseline] table of Scan.toml, or use --baseline-path=<path>");
        assertUsageError(scan(withoutBaseline, "--prune-baseline"), "--prune-baseline needs a baseline file; set "
                + "'path' in the [baseline] table of Scan.toml, or use --baseline-path=<path>");
        // Without a mode that writes, a package without a baseline is scanned as usual
        Assert.assertEquals(scan(withoutBaseline, "--ignore-baseline").exitCode(), 0);
    }

    @Test(description = "test --create-baseline creates a missing file and its folders, and --baseline-path "
            + "replaces [baseline] path for one run")
    void testBaselinePaths() throws IOException {
        Path project = createPackage("""
                [baseline]
                path = "baselines/scan.json"
                """);
        ScanRun create = scan(project, "--create-baseline");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(Files.isRegularFile(project.resolve("baselines").resolve("scan.json")), create.output());

        ScanRun custom = scan(project, "--create-baseline", "--baseline-path=custom.json");
        Assert.assertEquals(custom.exitCode(), 0, custom.output());
        Assert.assertTrue(custom.err().contains("bal scan: warning: --baseline-path=custom.json overrides "
                + "[baseline] path = \"baselines/scan.json\" in Scan.toml"), custom.output());
        Assert.assertTrue(Files.isRegularFile(project.resolve("custom.json")), custom.output());
        Assert.assertEquals(scan(project, "--baseline-path=custom.json").exitCode(), 0);

        // An option given alone uses a file that Scan.toml does not set
        Path withoutBaseline = createPackage(null);
        Assert.assertEquals(scan(withoutBaseline, "--create-baseline", "--baseline-path=" + BASELINE).exitCode(),
                0);
        ScanRun check = scan(withoutBaseline, "--baseline-path=" + BASELINE, "--fail-on-severity=LOW");
        Assert.assertEquals(check.exitCode(), 0, check.output());
        Assert.assertTrue(check.err().contains("0 new issue(s), " + ALL_ISSUES + " in baseline"), check.output());
    }

    @Test(description = "test a scan filtered to some rules or without the tests changes only the entries it can see")
    void testScopeOfWrites() throws IOException {
        Path project = createPackage(BASELINE_SCAN_TOML);
        Assert.assertEquals(scan(project, "--create-baseline").exitCode(), 0);
        // The secret is fixed, and the ballerina:1 issues are left as they are
        writeMain(project, MAIN.replace("    string password = \"admin123\";\n", ""));

        ScanRun excluded = scan(project, "--prune-baseline", "--exclude-rules=ballerina:13");
        Assert.assertTrue(excluded.err().contains("The baseline has no entries to remove:"), excluded.output());
        Assert.assertEquals(entries(project).size(), ALL_ISSUES);

        ScanRun withoutTests = scan(project, "--exclude-tests");
        Assert.assertTrue(withoutTests.err().contains("1 entry of the baseline scan-baseline.json matches no issue"),
                withoutTests.output());
        Assert.assertTrue(withoutTests.err().contains("0 new issue(s), 2 in baseline"), withoutTests.output());

        ScanRun create = scan(project, "--create-baseline", "--include-rules=ballerina:13");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(create.err().contains("Saved 3 entries to the baseline at:"), create.output());
        List<String> ruleIds = new ArrayList<>();
        entries(project).forEach(entry -> ruleIds.add(entry.getAsJsonObject().get("ruleId").getAsString()));
        Assert.assertEquals(ruleIds, List.of("ballerina:1", "ballerina:1", "ballerina:1"));
    }

    @Test(description = "test a workspace baseline keeps each package's entries apart, gates each package on its own "
            + "new issues, and a package scanned alone writes only its own entries")
    void testWorkspaceBaseline() throws IOException {
        Path workspace = createWorkspace(BASELINE_SCAN_TOML, null);
        ScanRun create = scan(workspace, "--create-baseline");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(create.err().contains("0 new issue(s), 3 in baseline"), create.output());
        JsonArray entries = entries(workspace);
        Set<String> packages = new HashSet<>();
        Set<String> fingerprints = new HashSet<>();
        for (JsonElement entry : entries) {
            Assert.assertEquals(entry.getAsJsonObject().get("filePath").getAsString(), "main.bal");
            packages.add(entry.getAsJsonObject().get("package").getAsString());
            fingerprints.add(entry.getAsJsonObject().get("fingerprint").getAsString());
        }
        Assert.assertEquals(packages, Set.of("myorg/pkg_a", "myorg/pkg_b"));
        // The same file path and line in two packages are two issues
        Assert.assertEquals(fingerprints.size(), 3);

        // A package loaded alone, without its workspace, gets the same fingerprints as in the workspace
        ScanRun alone = scanAlone(workspace.resolve("pkg-a"), "--fail-on-severity=LOW");
        Assert.assertEquals(alone.exitCode(), 0, alone.output());
        Assert.assertTrue(alone.err().contains("0 new issue(s), 2 in baseline"), alone.output());

        // A package scanned alone keeps the entries of the other packages
        writeMain(workspace.resolve("pkg-a"), FUNCTIONS + "public function main() {\n}\n");
        ScanRun prune = scanAlone(workspace.resolve("pkg-a"), "--prune-baseline");
        Assert.assertTrue(prune.err().contains("Removed 2 stale entries from the baseline at:"), prune.output());
        Assert.assertEquals(entries(workspace).size(), 1);
        Assert.assertEquals(entries(workspace).get(0).getAsJsonObject().get("package").getAsString(), "myorg/pkg_b");

        // Each package is gated on its own new issues
        writeMain(workspace.resolve("pkg-b"), FUNCTIONS + """
                public function main() {
                    _ = checkpanic getResult();
                    string password = "admin123";
                }
                """);
        ScanRun gated = scan(workspace, "--fail-on-severity=HIGH");
        Assert.assertEquals(gated.exitCode(), 1, gated.output());
        Assert.assertTrue(gated.errorReport().startsWith("bal scan: error: 1 package failed the gate\n"
                + "pkg-b: error: 1 issue at or above HIGH"), gated.output());
    }

    @Test(description = "test --create-baseline in a workspace leaves out a package without a baseline, and fails "
            + "when no package has one")
    void testWorkspacePackageWithoutBaseline() throws IOException {
        // pkg-b has a Scan.toml of its own without a baseline, which replaces the workspace one as a whole
        Path workspace = createWorkspace(BASELINE_SCAN_TOML, "[gate]\nfailOnCount = 10\n");
        ScanRun create = scan(workspace, "--create-baseline");
        Assert.assertEquals(create.exitCode(), 0, create.output());
        Assert.assertTrue(create.err().contains("bal scan: warning: pkg-b sets no baseline and is left out of "
                + "--create-baseline"), create.output());
        Assert.assertTrue(create.err().contains("1 new issue(s), 2 in baseline"), create.output());
        Assert.assertEquals(entries(workspace).size(), 2);

        // The workspace report holds baselineState on every result, so the issues of pkg-b are new
        JsonArray workspaceResults = JsonParser.parseString(Files.readString(workspace.resolve("target")
                .resolve("report").resolve("scan_results.json"))).getAsJsonArray();
        Assert.assertEquals(countState(workspaceResults, "unchanged"), 2, workspaceResults.toString());
        Assert.assertEquals(countState(workspaceResults, "new"), 1, workspaceResults.toString());

        Path noBaselines = createWorkspace(null, null);
        assertUsageError(scan(noBaselines, "--create-baseline"), "--create-baseline needs a baseline file; set "
                + "'path' in the [baseline] table of Scan.toml, or use --baseline-path=<path>");
    }

    private static void assertUsageError(ScanRun run, String message) {
        Assert.assertEquals(run.exitCode(), 2, run.output());
        Assert.assertEquals(run.errorReport(), "bal scan: error: " + message + "\n"
                + UsageHintTestUtils.usageHint(), run.output());
    }

    private static int countState(JsonArray results, String state) {
        int count = 0;
        for (JsonElement result : results) {
            JsonElement baselineState = result.getAsJsonObject().get("baselineState");
            if (baselineState != null && baselineState.getAsString().equals(state)) {
                count++;
            }
        }
        return count;
    }

    private static String fingerprint(JsonElement result) {
        return result.getAsJsonObject().getAsJsonObject("partialFingerprints").get("ballerinaScanHash/v1")
                .getAsString();
    }

    private static JsonArray results(Path project) throws IOException {
        return JsonParser.parseString(Files.readString(project.resolve("target").resolve("report")
                .resolve("scan_results.json"), StandardCharsets.UTF_8)).getAsJsonArray();
    }

    private static JsonArray sarifResults(Path project) throws IOException {
        JsonObject sarif = JsonParser.parseString(Files.readString(project.resolve("target").resolve("report")
                .resolve("scan_results.sarif"), StandardCharsets.UTF_8)).getAsJsonObject();
        return sarif.getAsJsonArray("runs").get(0).getAsJsonObject().getAsJsonArray("results");
    }

    private static JsonArray entries(Path root) throws IOException {
        return JsonParser.parseString(Files.readString(root.resolve(BASELINE), StandardCharsets.UTF_8))
                .getAsJsonObject().getAsJsonArray("issues");
    }

    private static void writeMain(Path project, String source) throws IOException {
        Files.writeString(project.resolve("main.bal"), source, StandardCharsets.UTF_8);
    }

    /**
     * Writes a package with the main and test sources to a new directory, with its dependencies locked.
     */
    private Path createPackage(String scanToml) throws IOException {
        return createPackage(scanToml, MAIN);
    }

    private Path createPackage(String scanToml, String main) throws IOException {
        Path root = workDirectory.resolve("package-" + projectCount++);
        writePackage(root, "orders", main, scanToml);
        Files.createDirectories(root.resolve("tests"));
        Files.writeString(root.resolve("tests").resolve("main_test.bal"), TEST_SOURCE, StandardCharsets.UTF_8);
        lock(root);
        return root;
    }

    /**
     * Writes a workspace of two packages, each with its issues in a file named main.bal.
     */
    private Path createWorkspace(String workspaceScanToml, String packageBScanToml) throws IOException {
        Path root = workDirectory.resolve("workspace-" + projectCount++);
        Files.createDirectories(root);
        Files.writeString(root.resolve("Ballerina.toml"), "[workspace]\npackages = [\"pkg-a\", \"pkg-b\"]\n");
        if (workspaceScanToml != null) {
            Files.writeString(root.resolve("Scan.toml"), workspaceScanToml);
        }
        writePackage(root.resolve("pkg-a"), "pkg_a", MAIN.replace("    string password = \"admin123\";\n", ""),
                null);
        writePackage(root.resolve("pkg-b"), "pkg_b", FUNCTIONS + """
                public function main() {
                    _ = checkpanic getResult();
                }
                """, packageBScanToml);
        lock(root);
        return root;
    }

    private static void writePackage(Path root, String name, String main, String scanToml) throws IOException {
        Files.createDirectories(root);
        Files.writeString(root.resolve("Ballerina.toml"), """
                [package]
                org = "myorg"
                name = "{NAME}"
                version = "0.1.0"
                """.replace("{NAME}", name));
        Files.writeString(root.resolve("main.bal"), main, StandardCharsets.UTF_8);
        if (scanToml != null) {
            Files.writeString(root.resolve("Scan.toml"), scanToml);
        }
    }

    // A scan requires the dependencies to be locked, as `bal build` locks them
    private static void lock(Path root) {
        Project project = ProjectLoader.load(root).project();
        List<BuildProject> packages = project instanceof WorkspaceProject workspace
                ? List.copyOf(workspace.projects()) : List.of((BuildProject) project);
        for (BuildProject buildProject : packages) {
            buildProject.currentPackage().getResolution();
            buildProject.save();
        }
    }

    private static ScanRun scan(Path directory, String... args) {
        return scan(directory, null, args);
    }

    /**
     * Scans a workspace package loaded on its own, as the editor and test runners load it. Scanning from inside a
     * package on the command line loads its whole workspace.
     */
    private static ScanRun scanAlone(Path packageRoot, String... args) {
        return scan(packageRoot, BuildProject.load(packageRoot), args);
    }

    private static ScanRun scan(Path directory, Project project, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String userDirectory = System.getProperty("user.dir");
        System.setProperty("user.dir", directory.toString());
        try (PrintStream outStream = new PrintStream(out, true, StandardCharsets.UTF_8);
             PrintStream errStream = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            ScanCmd scanCmd = project == null ? new ScanCmd(outStream, errStream)
                    : new ScanCmd(outStream, errStream) {
                        @Override
                        protected Project getProject() {
                            return project;
                        }
                    };
            new CommandLine(scanCmd).parseArgs(args);
            scanCmd.execute();
            return new ScanRun(scanCmd.exitCode(), normalize(out), normalize(err));
        } finally {
            System.setProperty("user.dir", userDirectory);
        }
    }

    private static String normalize(ByteArrayOutputStream stream) {
        return stream.toString(StandardCharsets.UTF_8).replace(WINDOWS_LINE_SEPARATOR, LINUX_LINE_SEPARATOR);
    }

    private record ScanRun(int exitCode, String out, String err) {
        String output() {
            return "stdout:\n" + out + "\nstderr:\n" + err;
        }

        // The error report is the last thing written, so it runs from the last error line to the end
        String errorReport() {
            int start = err.lastIndexOf("bal scan: error: ");
            return start < 0 ? "" : err.substring(start).trim();
        }
    }
}
