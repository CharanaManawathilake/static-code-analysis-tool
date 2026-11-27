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

import io.ballerina.projects.util.ProjectUtils;
import io.ballerina.scan.internal.BaselineFile.Entry;
import io.ballerina.scan.utils.Constants;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Tests for reading, validating and writing a baseline file.
 *
 * @since 0.15.0
 */
public class BaselineFileTest {
    private static final String HASH = "9f2c51d0a4b87e13c6f0e2d9b1a47c58";
    private static final String OTHER_HASH = "4be1a7c3f09d2e8b5a6c1f7e3d9b0a24";
    private static final String DISPLAY_PATH = "scan-baseline.json";
    private static final Entry SECRET = new Entry(HASH + ":1", "ballerina:13", "myorg/orders",
            "modules/db/client.bal", "    string password = \"***\";");
    private static final Entry CHECKPANIC = new Entry("4be1a7c3f09d2e8b5a6c1f7e3d9b0a24:1", "ballerina:1",
            "myorg/orders", "main.bal", "    int value = checkpanic getResult();");
    private Path directory;
    private int fileCount;

    @BeforeClass
    void createDirectory() throws IOException {
        directory = Files.createTempDirectory("scan-baseline-file-test");
    }

    @AfterClass(alwaysRun = true)
    void deleteDirectory() {
        ProjectUtils.deleteDirectory(directory);
    }

    @Test(description = "test a valid baseline is read with its entries")
    void testReadValidBaseline() throws IOException {
        BaselineFile file = BaselineFile.read(write("""
                {
                  "version": 1,
                  "fingerprint": "ballerinaScanHash/v1",
                  "balScanVersion": "0.15.0",
                  "issues": [
                    {
                      "fingerprint": "9f2c51d0a4b87e13c6f0e2d9b1a47c58:1",
                      "ruleId": "ballerina:13",
                      "package": "myorg/orders",
                      "filePath": "modules/db/client.bal",
                      "snippet": "    string password = \\"***\\";"
                    }
                  ]
                }
                """), DISPLAY_PATH);
        Assert.assertTrue(file.exists());
        Assert.assertEquals(file.entries(), List.of(SECRET));
        Assert.assertEquals(file.entries().get(0).hash(), HASH);
        Assert.assertEquals(file.entries().get(0).occurrence(), 1);
    }

    @Test(description = "test a baseline written by hand, with a byte order mark, CRLF line endings, no "
            + "balScanVersion and no snippet, is read")
    void testReadMinimalBaseline() throws IOException {
        BaselineFile file = BaselineFile.read(write("﻿{\"version\": 1, \"fingerprint\": \"ballerinaScanHash/v1\","
                + "\r\n\"issues\": [{\"fingerprint\": \"" + HASH + ":12\", \"ruleId\": \"ballerina:1\", \"package\": "
                + "\"myorg/orders\", \"filePath\": \"main.bal\"}]}\r\n"), DISPLAY_PATH);
        Assert.assertEquals(file.entries(), List.of(new Entry(HASH + ":12", "ballerina:1", "myorg/orders",
                "main.bal", "")));
        Assert.assertEquals(file.entries().get(0).occurrence(), 12);
    }

    @DataProvider(name = "invalid-baselines")
    public Object[][] invalidBaselines() {
        return new Object[][]{
                {"", List.of("scan-baseline.json:1:1: error: invalid JSON: unexpected end of the file; expected a "
                        + "value")},
                {"{\n  \"version\": 1,\n  \"issues\": [\n}", List.of("scan-baseline.json:4:1: error: invalid JSON: "
                        + "unexpected character '}'; expected a value")},
                {"{\"version\": 1} extra", List.of("scan-baseline.json:1:16: error: invalid JSON: unexpected "
                        + "character 'e' after the end of the JSON value")},
                {"{\"version\": 1, \"issues\": [\"unterminated]}", List.of("scan-baseline.json:1:27: error: invalid "
                        + "JSON: unterminated string")},
                {"[]", List.of("scan-baseline.json:1:1: error: invalid baseline [...]; expected an object with "
                        + "'version', 'fingerprint' and 'issues'")},
                {"{\"version\": 2, \"fingerprint\": \"other\", \"issues\": 1}", List.of("scan-baseline.json:1:13: "
                        + "error: unsupported baseline version 2; this version of the scan tool reads version 1")},
                {"{\"version\": \"1\", \"fingerprint\": \"ballerinaScanHash/v1\", \"issues\": []}",
                        List.of("scan-baseline.json:1:13: error: invalid value \"1\" for 'version'; expected the "
                                + "version of the baseline format, such as 1")},
                {"{\"version\": 1, \"fingerprint\": \"ballerinaScanHash/v2\", \"issues\": []}",
                        List.of("scan-baseline.json:1:31: error: unsupported fingerprint version "
                                + "'ballerinaScanHash/v2'; expected 'ballerinaScanHash/v1'")},
                {"{\"version\": 1, \"issues\": []}", List.of("scan-baseline.json:1:1: error: missing field "
                        + "'fingerprint'")},
                {"""
                        {
                          "version": 1,
                          "fingerprint": "ballerinaScanHash/v1",
                          "created": "2026-11-27",
                          "issues": [
                            {"fingerprint": "{HASH}:1", "ruleId": "ballerina:1", "package": "myorg/orders",
                             "filePath": "main.bal", "line": 4},
                            {"fingerprint": "{HASH}", "ruleId": "", "package": "myorg/orders"},
                            {"fingerprint": "{OTHER}:1", "ruleId": "ballerina:1", "package": "myorg/orders",
                             "filePath": "main.bal", "filePath": "other.bal"},
                            "not an issue",
                            {"fingerprint": "{OTHER}:1", "ruleId": "ballerina:1", "package": "myorg/orders",
                             "filePath": "main.bal", "snippet": 1}
                          ]
                        }
                        """.replace("{HASH}", HASH).replace("{OTHER}", OTHER_HASH), List.of(
                        "scan-baseline.json:4:3: error: unknown field 'created'; expected 'version', 'fingerprint', "
                                + "'balScanVersion' or 'issues'",
                        "scan-baseline.json:7:30: error: unknown field 'line'; expected 'fingerprint', 'ruleId', "
                                + "'package', 'filePath' or 'snippet'",
                        "scan-baseline.json:8:5: error: missing field 'filePath'",
                        "scan-baseline.json:8:21: error: invalid value \"" + HASH + "\" for 'fingerprint'; expected a "
                                + "32-digit lowercase hexadecimal hash and an occurrence number, such as "
                                + "\"9f2c51d0a4b87e13c6f0e2d9b1a47c58:1\"",
                        "scan-baseline.json:8:67: error: invalid value \"\" for 'ruleId'; expected a rule ID, such "
                                + "as \"ballerina:1\"",
                        "scan-baseline.json:10:30: error: duplicate field 'filePath'",
                        "scan-baseline.json:11:5: error: invalid value \"not an issue\" for 'issues'; expected an "
                                + "array of issues, each an object",
                        "scan-baseline.json:13:41: error: invalid value 1 for 'snippet'; expected the flagged line as "
                                + "a string")},
                {"""
                        {"version": 1, "fingerprint": "ballerinaScanHash/v1", "issues": [
                          {"fingerprint": "{HASH}:1", "ruleId": "ballerina:1", "package": "a/b", "filePath": "a.bal"},
                          {"fingerprint": "{HASH}:1", "ruleId": "ballerina:1", "package": "a/b", "filePath": "a.bal"}
                        ]}
                        """.replace("{HASH}", HASH), List.of("scan-baseline.json:3:3: error: duplicate fingerprint '"
                        + HASH + ":1'")},
        };
    }

    @Test(description = "test every error of an invalid baseline is reported at its line and column, in order",
            dataProvider = "invalid-baselines")
    void testInvalidBaseline(String content, List<String> errors) throws IOException {
        Path path = write(content);
        try {
            BaselineFile.read(path, DISPLAY_PATH);
            Assert.fail("expected the baseline to be rejected");
        } catch (ScanFailure failure) {
            Assert.assertEquals(failure.exitCode(), ExitCode.RUNTIME_ERROR);
            Assert.assertEquals(failure.getMessage(), DISPLAY_PATH + " has " + errors.size()
                    + (errors.size() == 1 ? " error" : " errors"));
            Assert.assertEquals(failure.details(), errors);
        }
    }

    @Test(description = "test a baseline is written in a stable order with no line numbers or dates, and a rerun "
            + "with the same entries leaves the file untouched")
    void testWrite() throws IOException {
        Path path = directory.resolve("nested").resolve("folder").resolve("baseline-" + fileCount++ + ".json");
        BaselineFile absent = BaselineFile.absent(path, DISPLAY_PATH);
        Assert.assertFalse(absent.exists());
        Assert.assertTrue(absent.write(List.of(SECRET, CHECKPANIC)));
        String written = Files.readString(path, StandardCharsets.UTF_8);
        Assert.assertEquals(written, """
                {
                  "version": 1,
                  "fingerprint": "ballerinaScanHash/v1",
                  "balScanVersion": "{VERSION}",
                  "issues": [
                    {
                      "fingerprint": "4be1a7c3f09d2e8b5a6c1f7e3d9b0a24:1",
                      "ruleId": "ballerina:1",
                      "package": "myorg/orders",
                      "filePath": "main.bal",
                      "snippet": "    int value = checkpanic getResult();"
                    },
                    {
                      "fingerprint": "9f2c51d0a4b87e13c6f0e2d9b1a47c58:1",
                      "ruleId": "ballerina:13",
                      "package": "myorg/orders",
                      "filePath": "modules/db/client.bal",
                      "snippet": "    string password = \\"***\\";"
                    }
                  ]
                }
                """.replace("{VERSION}", Constants.SARIF_TOOL_VERSION));

        BaselineFile reread = BaselineFile.read(path, DISPLAY_PATH);
        Assert.assertFalse(reread.write(List.of(CHECKPANIC, SECRET)));
        Assert.assertEquals(Files.readString(path, StandardCharsets.UTF_8), written);
        Assert.assertTrue(reread.write(List.of(SECRET)));
        Assert.assertEquals(BaselineFile.read(path, DISPLAY_PATH).entries(), List.of(SECRET));
        try (var files = Files.list(path.getParent())) {
            Assert.assertEquals(files.count(), 1, "the temporary file is removed");
        }
    }

    @Test(description = "test entries are ordered by package, file path, rule ID, hash and occurrence number")
    void testEntryOrder() {
        Entry tenth = new Entry(HASH + ":10", "ballerina:1", "a/b", "main.bal", "");
        Entry ninth = new Entry(HASH + ":9", "ballerina:1", "a/b", "main.bal", "");
        Entry otherPackage = new Entry(HASH + ":1", "ballerina:1", "a/a", "z.bal", "");
        String rendered = BaselineFile.render(List.of(otherPackage, ninth, tenth).stream()
                .sorted(Entry.ORDER).toList());
        Assert.assertTrue(rendered.indexOf(HASH + ":1\"") < rendered.indexOf(HASH + ":9\""), rendered);
        Assert.assertTrue(rendered.indexOf(HASH + ":9\"") < rendered.indexOf(HASH + ":10\""), rendered);
    }

    @Test(description = "test a baseline that cannot be written is a runtime error naming the file")
    void testWriteFailure() throws IOException {
        Path blocker = write("not a directory");
        BaselineFile file = BaselineFile.absent(blocker.resolve("scan-baseline.json"), DISPLAY_PATH);
        try {
            file.write(List.of(SECRET));
            Assert.fail("expected the write to fail");
        } catch (ScanFailure failure) {
            Assert.assertEquals(failure.exitCode(), ExitCode.RUNTIME_ERROR);
            Assert.assertTrue(failure.getMessage().startsWith("failed to write the baseline scan-baseline.json: "),
                    failure.getMessage());
        }
    }

    private Path write(String content) throws IOException {
        Path path = directory.resolve("baseline-" + fileCount++ + ".json");
        Files.writeString(path, content, StandardCharsets.UTF_8);
        return path;
    }
}
