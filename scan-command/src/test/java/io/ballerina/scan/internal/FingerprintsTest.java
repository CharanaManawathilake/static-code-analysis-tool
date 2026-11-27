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

import io.ballerina.projects.Document;
import io.ballerina.projects.Module;
import io.ballerina.projects.Project;
import io.ballerina.projects.directory.ProjectLoader;
import io.ballerina.projects.util.ProjectUtils;
import io.ballerina.scan.Issue;
import io.ballerina.scan.Rule;
import io.ballerina.scan.RuleKind;
import io.ballerina.scan.Source;
import io.ballerina.scan.utils.ScanUtils;
import io.ballerina.tools.text.LinePosition;
import io.ballerina.tools.text.TextDocument;
import io.ballerina.tools.text.TextDocuments;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.ballerinalang.compiler.diagnostic.BLangDiagnosticLocation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tests for the {@code ballerinaScanHash/v1} fingerprint of an issue.
 *
 * @since 0.15.0
 */
public class FingerprintsTest {
    private static final Rule SECRET_RULE = RuleFactory.createRule(13, "rule 13", RuleKind.VULNERABILITY);
    private static final Rule CHECKPANIC_RULE = RuleFactory.createRule(1, "rule 1", RuleKind.CODE_SMELL);
    private static final String FLAGGED_LINE = "    string password = \"admin123\";";
    private Path temporaryDirectory;
    private int fileCount;

    @BeforeClass
    void createDirectory() throws IOException {
        temporaryDirectory = Files.createTempDirectory("scan-fingerprints-test");
    }

    @AfterClass(alwaysRun = true)
    void deleteDirectory() {
        ProjectUtils.deleteDirectory(temporaryDirectory);
    }

    @Test(description = "test the fingerprint hashes the rule, package, path and the tokens of the flagged line")
    void testHashInputs() throws IOException {
        Scanned scanned = scan(function(FLAGGED_LINE), "\"admin123\"");
        Finding finding = scanned.finding(0);
        Assert.assertEquals(finding.hash(), Fingerprints.hash("ballerina:13", scanned.packageName(),
                finding.filePath(), "string password = \"admin123\" ;"));
        Assert.assertEquals(finding.occurrence(), 1);
        Assert.assertEquals(finding.ruleId(), "ballerina:13");
        Assert.assertEquals(finding.filePath(), scanned.fileName());
        Assert.assertEquals(scanned.issues().get(0).partialFingerprints(),
                Map.of("ballerinaScanHash/v1", finding.hash() + ":1"));
    }

    @Test(description = "test the hash is the first 32 hexadecimal digits of the SHA-256 hash of the joined inputs")
    void testHashAlgorithm() throws NoSuchAlgorithmException {
        String input = String.join("\u001F", "1", "ballerina:13", "myorg/orders", "modules/db/client.bal",
                "string password = \"admin123\" ;");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        String expected = HexFormat.of().formatHex(digest).substring(0, 32);
        Assert.assertEquals(Fingerprints.hash("ballerina:13", "myorg/orders", "modules/db/client.bal",
                "string password = \"admin123\" ;"), expected);
        Assert.assertTrue(expected.matches("[0-9a-f]{32}"), expected);
    }

    @Test(description = "test changes the fingerprint ignores leave it unchanged")
    void testUnchangedFingerprint() throws IOException {
        String original = hash(function(FLAGGED_LINE), "\"admin123\"");
        // Lines added above the issue, and the enclosing function moved and renamed
        Assert.assertEquals(hash("""
                import ballerina/io;

                function other() {
                    io:println("other");
                }

                """ + function(FLAGGED_LINE).replace("function main", "function renamed"), "\"admin123\""),
                original);
        // Re-indented, with other spacing within the line
        Assert.assertEquals(hash(function("\t\tstring   password=\"admin123\"  ;"), "\"admin123\""), original);
        // A comment added at the end of the flagged line
        Assert.assertEquals(hash(function(FLAGGED_LINE + " // TODO: read it from a configurable"),
                "\"admin123\""), original);
        // A comment and an edit on the other lines
        Assert.assertEquals(hash(function("    // the password\n" + FLAGGED_LINE + "\n    int count = 10;"),
                "\"admin123\""), original);
        // A CRLF checkout
        Assert.assertEquals(hash(function(FLAGGED_LINE).replace("\n", "\r\n"), "\"admin123\""), original);
        // A byte order mark
        Assert.assertEquals(hash("﻿" + function(FLAGGED_LINE), "\"admin123\""), original);
    }

    @Test(description = "test changes to the flagged code change the fingerprint")
    void testChangedFingerprint() throws IOException {
        String original = hash(function(FLAGGED_LINE), "\"admin123\"");
        Assert.assertNotEquals(hash(function("    string password = \"admin1234\";"), "\"admin1234\""), original);
        // String contents keep their spaces
        Assert.assertNotEquals(hash(function("    string password = \"admin 123\";"), "\"admin 123\""), original);
        // The flagged line wrapped, which changes the tokens on it
        Assert.assertNotEquals(hash(function("    string password =\n        \"admin123\";"), "\"admin123\""),
                original);
        Assert.assertNotEquals(hash(function(FLAGGED_LINE), "\"admin123\"", CHECKPANIC_RULE), original);
        // The file renamed
        Assert.assertNotEquals(hash(function(FLAGGED_LINE), "\"admin123\"", SECRET_RULE, "renamed.bal"), original);
    }

    @Test(description = "test tokens are separated by one space, so that adjacent tokens are not joined")
    void testTokenBoundaries() throws IOException {
        Scanned separate = scan(function("    int x = check foo();"), "check foo()");
        Scanned joined = scan(function("    int x = checkfoo();"), "checkfoo()");
        Assert.assertEquals(separate.finding(0).hash(), Fingerprints.hash("ballerina:13", separate.packageName(),
                separate.fileName(), "int x = check foo ( ) ;"));
        Assert.assertNotEquals(separate.finding(0).hash(), joined.finding(0).hash());
    }

    @Test(description = "test every token of the line is used, whatever column the range starts at or its length")
    void testRangeWithinTheLine() throws IOException {
        String source = function(FLAGGED_LINE);
        String lineStart = hash(source, source.indexOf("string password"), 0);
        Assert.assertEquals(hash(source, source.indexOf("\"admin123\""), "\"admin123\"".length()), lineStart);
        Assert.assertEquals(hash(source, source.indexOf("password"), 3), lineStart);
        // A zero-length range uses the line that holds its offset
        Assert.assertEquals(hash(source, source.indexOf(";"), 0), lineStart);
    }

    @Test(description = "test a line with no token is hashed as the empty string")
    void testLineWithoutTokens() throws IOException {
        String source = function("    // only a comment\n\n" + FLAGGED_LINE);
        Scanned comment = scan(source, source.indexOf("// only"), 0);
        Assert.assertEquals(comment.finding(0).hash(), Fingerprints.hash("ballerina:13", comment.packageName(),
                comment.fileName(), ""));
        Scanned empty = scan(source, source.indexOf("\n\n") + 1, 0);
        Assert.assertEquals(empty.finding(0).hash(), comment.finding(0).hash());
    }

    @Test(description = "test a token over several lines is used in full, with LF line endings, on each of its lines")
    void testMultiLineToken() throws IOException {
        String source = function("    string message = string `first\n    second`;");
        Scanned firstLine = scan(source, "string `first");
        Assert.assertEquals(firstLine.finding(0).hash(), Fingerprints.hash("ballerina:13", firstLine.packageName(),
                firstLine.fileName(), "string message = string ` first\n    second"));
        Scanned crlf = scan(source.replace("\n", "\r\n"), "string `first");
        Assert.assertEquals(crlf.finding(0).hash(), firstLine.finding(0).hash());

        // On a continuation line, the token is included in full, with the tokens that follow it on that line
        Scanned continuation = scan(source, source.indexOf("second"), 6);
        Assert.assertEquals(continuation.finding(0).hash(), Fingerprints.hash("ballerina:13",
                continuation.packageName(), continuation.fileName(), "first\n    second ` ;"));
        Scanned crlfContinuation = scan(source.replace("\n", "\r\n"),
                source.replace("\n", "\r\n").indexOf("second"), 6);
        Assert.assertEquals(crlfContinuation.finding(0).hash(), continuation.finding(0).hash());
    }

    @Test(description = "test identical findings in a file are numbered in source order, and every value is unique")
    void testOccurrences() throws IOException {
        String source = """
                function first() returns error? {
                    int a = checkpanic getResult(); int b = checkpanic getResult();
                }

                function second() returns error? {
                    int a = checkpanic getResult(); int b = checkpanic getResult();
                }

                function getResult() returns int|error => 1;
                """;
        List<int[]> ranges = new ArrayList<>();
        int offset = source.indexOf("checkpanic");
        while (offset >= 0) {
            ranges.add(new int[]{offset, "checkpanic getResult()".length()});
            offset = source.indexOf("checkpanic", offset + 1);
        }
        // Reported out of order, as analyzers may report them
        ranges.add(0, ranges.remove(ranges.size() - 1));
        Scanned scanned = scan(source, CHECKPANIC_RULE, "main.bal", ranges);

        Set<String> values = new HashSet<>();
        Set<String> hashes = new HashSet<>();
        for (Issue issue : scanned.issues()) {
            values.add(issue.partialFingerprints().get(Fingerprints.KEY));
            hashes.add(((IssueImpl) issue).finding().hash());
        }
        Assert.assertEquals(values.size(), 4, values.toString());
        Assert.assertEquals(hashes.size(), 1, hashes.toString());
        // The last range, reported first, is the last in source order
        Assert.assertEquals(scanned.finding(0).occurrence(), 4);
        Assert.assertEquals(scanned.finding(1).occurrence(), 1);
        Assert.assertEquals(scanned.finding(2).occurrence(), 2);
        Assert.assertEquals(scanned.finding(3).occurrence(), 3);
    }

    @Test(description = "test the snippet keeps the line as written, with the content of every literal redacted")
    void testSnippetRedaction() throws IOException {
        Assert.assertEquals(snippet(function(FLAGGED_LINE), "\"admin123\""), "    string password = \"***\";");
        Assert.assertEquals(snippet(function("    string empty = \"\"; // keep"), "\"\""),
                "    string empty = \"***\"; // keep");
        Assert.assertEquals(snippet(function("    int pin = 1234 + 0x1F; float rate = 1.5;"), "1234"),
                "    int pin = *** + ***; float rate = ***;");
        Assert.assertEquals(snippet(function("    string token = string `abc${pin}def`;"), "string `"),
                "    string token = string `***${pin}***`;");
        Assert.assertEquals(snippet(function("    byte[] key = base16 `aabbccdd`;"), "base16"),
                "    byte[] key = base16 `***`;");
        Assert.assertEquals(snippet("﻿" + "string password = \"admin123\";\n", "\"admin123\""),
                "string password = \"***\";");

        // The snippet is only for review: the fingerprint is computed from the literal as written
        Scanned first = scan(function(FLAGGED_LINE), "\"admin123\"");
        Scanned second = scan(function("    string password = \"other\";"), "\"other\"");
        Assert.assertEquals(first.finding(0).snippet(), second.finding(0).snippet());
        Assert.assertNotEquals(first.finding(0).hash(), second.finding(0).hash());
    }

    @Test(description = "test an issue in a file the package does not hold is fingerprinted from the file on disk")
    void testIssueOutsideThePackage() throws IOException {
        Scanned scanned = scan(function(FLAGGED_LINE), "\"admin123\"");
        Path outside = temporaryDirectory.resolve("outside-" + fileCount++ + ".bal");
        String source = function(FLAGGED_LINE);
        Files.writeString(outside, source);
        int start = source.indexOf("\"admin123\"");
        IssueImpl issue = new IssueImpl(location(TextDocuments.from(source), "outside.bal", start, 10),
                SECRET_RULE, Source.BUILT_IN, "outside.bal", outside.toString());
        Fingerprints.assign(scanned.project(), new ArrayList<>(List.of(issue)));
        // A file outside the root is identified by its name
        Assert.assertEquals(issue.finding().filePath(), "outside.bal");
        Assert.assertEquals(issue.finding().hash(), Fingerprints.hash("ballerina:13", scanned.packageName(),
                "outside.bal", "string password = \"admin123\" ;"));
    }

    private static String function(String body) {
        return "public function main() {\n" + body + "\n}\n";
    }

    private String hash(String source, String flagged) throws IOException {
        return scan(source, flagged).finding(0).hash();
    }

    private String hash(String source, String flagged, Rule rule) throws IOException {
        return hash(source, flagged, rule, "main.bal");
    }

    private String hash(String source, String flagged, Rule rule, String fileName) throws IOException {
        int start = source.indexOf(flagged);
        return scan(source, rule, fileName, List.<int[]>of(new int[]{start, flagged.length()})).finding(0).hash();
    }

    private String hash(String source, int start, int length) throws IOException {
        return scan(source, start, length).finding(0).hash();
    }

    private String snippet(String source, String flagged) throws IOException {
        return scan(source, flagged).finding(0).snippet();
    }

    private Scanned scan(String source, String flagged) throws IOException {
        int start = source.indexOf(flagged);
        Assert.assertTrue(start >= 0, flagged);
        return scan(source, start, flagged.length());
    }

    private Scanned scan(String source, int start, int length) throws IOException {
        return scan(source, SECRET_RULE, "main.bal", List.<int[]>of(new int[]{start, length}));
    }

    /**
     * Writes the source to a new single file project and fingerprints an issue for each range of it.
     */
    private Scanned scan(String source, Rule rule, String fileName, List<int[]> ranges) throws IOException {
        Path directory = Files.createDirectories(temporaryDirectory.resolve("project-" + fileCount++));
        Path file = directory.resolve(fileName);
        Files.writeString(file, source, StandardCharsets.UTF_8);
        Project project = ProjectLoader.load(file).project();
        Module module = project.currentPackage().getDefaultModule();
        Document document = module.document(module.documentIds().iterator().next());
        TextDocument textDocument = document.textDocument();
        List<Issue> issues = new ArrayList<>();
        for (int[] range : ranges) {
            issues.add(new IssueImpl(location(textDocument, document.name(), range[0], range[1]), rule,
                    Source.BUILT_IN, document.name(), ScanUtils.getReportFilePath(document)));
        }
        Fingerprints.assign(project, issues);
        return new Scanned(project, issues);
    }

    private static BLangDiagnosticLocation location(TextDocument textDocument, String fileName, int start,
                                                    int length) {
        LinePosition startPosition = textDocument.linePositionFrom(start);
        LinePosition endPosition = textDocument.linePositionFrom(start + length);
        return new BLangDiagnosticLocation(fileName, startPosition.line(), endPosition.line(),
                startPosition.offset(), endPosition.offset(), start, length);
    }

    private record Scanned(Project project, List<Issue> issues) {
        Finding finding(int index) {
            Finding finding = ((IssueImpl) issues.get(index)).finding();
            Assert.assertNotNull(finding);
            return finding;
        }

        String packageName() {
            return Fingerprints.packageName(project);
        }

        String fileName() {
            return finding(0).filePath();
        }
    }
}
