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

import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NonTerminalNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.compiler.syntax.tree.SyntaxTree;
import io.ballerina.compiler.syntax.tree.Token;
import io.ballerina.projects.Document;
import io.ballerina.projects.Module;
import io.ballerina.projects.ModuleId;
import io.ballerina.projects.Package;
import io.ballerina.projects.Project;
import io.ballerina.scan.Issue;
import io.ballerina.scan.utils.ScanUtils;
import io.ballerina.tools.text.TextDocument;
import io.ballerina.tools.text.TextDocuments;
import io.ballerina.tools.text.TextLine;
import io.ballerina.tools.text.TextRange;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Computes the {@code ballerinaScanHash/v1} fingerprint of every issue of a package.
 *
 * <p>The fingerprint hashes the rule ID, the package, the path of the file relative to the package root and the text
 * of the tokens on the first flagged line, so that it stays the same when lines are added above the issue, the line is
 * re-indented or a comment is added to it. Issues with the same hash are numbered in the order of their position in
 * the file, and the number is written after the hash, so that every fingerprint of a scan is unique.
 *
 * @since 0.15.0
 */
final class Fingerprints {
    static final String KEY = "ballerinaScanHash/v1";
    private static final String VERSION = "1";
    private static final String SEPARATOR = "\u001F";
    private static final int HASH_BYTES = 16;
    private static final char BYTE_ORDER_MARK = '﻿';
    private static final String REDACTED = "***";
    private static final Set<SyntaxKind> NUMERIC_LITERALS = EnumSet.of(SyntaxKind.DECIMAL_INTEGER_LITERAL_TOKEN,
            SyntaxKind.HEX_INTEGER_LITERAL_TOKEN, SyntaxKind.DECIMAL_FLOATING_POINT_LITERAL_TOKEN,
            SyntaxKind.HEX_FLOATING_POINT_LITERAL_TOKEN);
    // The text between the backticks of string templates and byte array literals, and the text of XML templates
    private static final Set<SyntaxKind> TEMPLATE_CONTENTS = EnumSet.of(SyntaxKind.TEMPLATE_STRING,
            SyntaxKind.XML_TEXT_CONTENT);

    private Fingerprints() {
    }

    /**
     * Computes the fingerprint of each issue of a package and records it on the issue. Every issue is numbered among
     * the issues with the same hash, suppressed or not, so this runs before rule selection and suppressions.
     *
     * @param project the package or single file the issues were reported in
     * @param issues  every issue the analyzers reported
     */
    static void assign(Project project, List<Issue> issues) {
        String packageName = packageName(project);
        Path root = project.sourceRoot().toAbsolutePath().normalize();
        Map<String, Document> documents = documentsByPath(project.currentPackage());
        Map<String, SourceFile> sourceFiles = new HashMap<>();

        Map<String, List<IssueImpl>> issuesByHash = new LinkedHashMap<>();
        Map<IssueImpl, Finding> findings = new HashMap<>();
        for (Issue issue : issues) {
            if (!(issue instanceof IssueImpl issueImpl)) {
                continue;
            }
            SourceFile sourceFile = sourceFiles.computeIfAbsent(issueImpl.filePath(),
                    path -> SourceFile.of(documents.get(path), path));
            int line = issueImpl.location().lineRange().startLine().line();
            String ruleId = issueImpl.rule().id();
            String filePath = packagePath(root, issueImpl.filePath(), issueImpl.location().lineRange().fileName());
            String hash = hash(ruleId, packageName, filePath, sourceFile.lineTokens(line));
            findings.put(issueImpl, new Finding(hash, 0, ruleId, packageName, filePath, sourceFile.snippet(line)));
            issuesByHash.computeIfAbsent(hash, key -> new ArrayList<>()).add(issueImpl);
        }

        // The sort is stable, so issues at the same position keep the order the analyzers reported them in
        Comparator<IssueImpl> byPosition = Comparator
                .comparingInt((IssueImpl issue) -> issue.location().textRange().startOffset())
                .thenComparingInt(issue -> issue.location().textRange().length());
        for (List<IssueImpl> sameHash : issuesByHash.values()) {
            sameHash.sort(byPosition);
            for (int i = 0; i < sameHash.size(); i++) {
                IssueImpl issue = sameHash.get(i);
                Finding finding = findings.get(issue);
                issue.setFinding(new Finding(finding.hash(), i + 1, finding.ruleId(), finding.packageName(),
                        finding.filePath(), finding.snippet()));
            }
        }
    }

    /**
     * Returns the hash of the inputs of a fingerprint: the first 32 hexadecimal digits of their SHA-256 hash.
     *
     * @param ruleId      the ID of the rule
     * @param packageName the organization and name of the package
     * @param filePath    the path of the file relative to the package root, with {@code /} separators
     * @param lineTokens  the text of the tokens on the first flagged line, joined with a space
     * @return the hash, in lowercase
     */
    static String hash(String ruleId, String packageName, String filePath, String lineTokens) {
        String input = String.join(SEPARATOR, VERSION, ruleId, packageName, filePath, lineTokens);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, HASH_BYTES);
        } catch (NoSuchAlgorithmException ex) {
            // Every Java platform is required to support SHA-256
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Returns the organization and name of a package, such as {@code myorg/orders}, as a fingerprint and a baseline
     * entry name it.
     */
    static String packageName(Project project) {
        Package currentPackage = project.currentPackage();
        return currentPackage.packageOrg().value() + "/" + currentPackage.packageName().value();
    }

    private static Map<String, Document> documentsByPath(Package currentPackage) {
        Map<String, Document> documents = new HashMap<>();
        for (ModuleId moduleId : currentPackage.moduleIds()) {
            Module module = currentPackage.module(moduleId);
            module.documentIds().forEach(id -> addDocument(documents, module.document(id)));
            module.testDocumentIds().forEach(id -> addDocument(documents, module.document(id)));
        }
        return documents;
    }

    private static void addDocument(Map<String, Document> documents, Document document) {
        documents.put(ScanUtils.getReportFilePath(document), document);
    }

    /**
     * Returns the path of a file relative to the package root, with {@code /} separators, so that a package scanned
     * alone and in a workspace gets the same fingerprints.
     *
     * @param root     the absolute, normalized package root
     * @param filePath the path of the file, as issues report it
     * @param fallback the name to use for a file outside the root, such as a single file, whose root is the file itself
     * @return the relative path, or the fallback
     */
    static String packagePath(Path root, String filePath, String fallback) {
        try {
            Path path = Paths.get(filePath);
            if (path.isAbsolute()) {
                Path normalizedPath = path.normalize();
                if (normalizedPath.startsWith(root) && !normalizedPath.equals(root)) {
                    StringJoiner segments = new StringJoiner("/");
                    root.relativize(normalizedPath).forEach(segment -> segments.add(segment.toString()));
                    return segments.toString();
                }
            }
        } catch (InvalidPathException ex) {
            // A document with no path on disk is identified by its name
        }
        return fallback;
    }

    /**
     * The tokens and lines of a source file.
     */
    private static final class SourceFile {
        private final TextDocument textDocument;
        private final int lineCount;
        // Sorted by position; tokens never overlap, so their end offsets are sorted too
        private final List<Token> tokens;

        private SourceFile(SyntaxTree syntaxTree) {
            this.textDocument = syntaxTree.textDocument();
            this.lineCount = textDocument.textLines().size();
            this.tokens = tokens(syntaxTree.rootNode());
        }

        /**
         * Returns the source of a document, parsing the file when the issue is in a file the package does not hold.
         */
        static SourceFile of(Document document, String filePath) {
            if (document != null) {
                return new SourceFile(document.syntaxTree());
            }
            String content;
            try {
                content = Files.readString(Path.of(filePath), StandardCharsets.UTF_8);
            } catch (IOException | InvalidPathException ex) {
                content = "";
            }
            return new SourceFile(SyntaxTree.from(TextDocuments.from(content)));
        }

        private static List<Token> tokens(Node root) {
            List<Token> tokens = new ArrayList<>();
            // Walked without recursion, so that a deeply nested expression cannot overflow the stack
            Deque<Node> pending = new ArrayDeque<>();
            pending.push(root);
            while (!pending.isEmpty()) {
                Node node = pending.pop();
                if (node instanceof Token token) {
                    if (!token.isMissing() && !token.text().isEmpty()) {
                        tokens.add(token);
                    }
                } else if (node instanceof NonTerminalNode nonTerminal) {
                    nonTerminal.children().forEach(pending::push);
                }
            }
            tokens.sort(Comparator.comparingInt(token -> token.textRange().startOffset()));
            return tokens;
        }

        /**
         * Returns the text of the tokens on a line, without their minutiae, joined with one space. A token that spans
         * several lines is included in full when any of its lines is the given line.
         */
        String lineTokens(int lineNumber) {
            TextLine line = line(lineNumber);
            if (line == null) {
                return "";
            }
            StringJoiner text = new StringJoiner(" ");
            tokensOn(line).forEach(token -> text.add(token.text().replace("\r\n", "\n")));
            return stripByteOrderMark(text.toString());
        }

        /**
         * Returns the line as written, with the content of every literal on it replaced by {@code ***}, so that a
         * baseline committed to the repository never holds the value of a hardcoded secret.
         */
        String snippet(int lineNumber) {
            TextLine line = line(lineNumber);
            if (line == null) {
                return "";
            }
            StringBuilder snippet = new StringBuilder(line.text());
            List<Token> lineTokens = tokensOn(line);
            // Replaced from the end of the line, so that the offsets of the earlier literals stay valid
            for (int i = lineTokens.size() - 1; i >= 0; i--) {
                TextRange content = literalContent(lineTokens.get(i));
                if (content == null) {
                    continue;
                }
                int start = Math.max(content.startOffset(), line.startOffset());
                int end = Math.min(content.endOffset(), line.endOffset());
                if (start <= end) {
                    snippet.replace(start - line.startOffset(), end - line.startOffset(), REDACTED);
                }
            }
            return stripByteOrderMark(snippet.toString());
        }

        private TextLine line(int lineNumber) {
            return lineNumber >= 0 && lineNumber < lineCount ? textDocument.line(lineNumber) : null;
        }

        private List<Token> tokensOn(TextLine line) {
            int lineStart = line.startOffset();
            int lineEnd = line.endOffsetWithNewLines();
            List<Token> lineTokens = new ArrayList<>();
            for (int i = firstTokenEndingAfter(lineStart); i < tokens.size(); i++) {
                Token token = tokens.get(i);
                if (token.textRange().startOffset() >= lineEnd) {
                    break;
                }
                lineTokens.add(token);
            }
            return lineTokens;
        }

        private int firstTokenEndingAfter(int offset) {
            int low = 0;
            int high = tokens.size();
            while (low < high) {
                int middle = (low + high) >>> 1;
                if (tokens.get(middle).textRange().endOffset() > offset) {
                    high = middle;
                } else {
                    low = middle + 1;
                }
            }
            return low;
        }

        /**
         * Returns the part of a literal token that holds its value: the text between the quotes of a string, the
         * whole of a number, and the text of a template. Returns null for any other token.
         */
        private static TextRange literalContent(Token token) {
            TextRange range = token.textRange();
            SyntaxKind kind = token.kind();
            if (kind == SyntaxKind.STRING_LITERAL_TOKEN && range.length() >= 2) {
                return TextRange.from(range.startOffset() + 1, range.length() - 2);
            }
            if (NUMERIC_LITERALS.contains(kind) || TEMPLATE_CONTENTS.contains(kind)) {
                return range;
            }
            return null;
        }

        private static String stripByteOrderMark(String text) {
            return !text.isEmpty() && text.charAt(0) == BYTE_ORDER_MARK ? text.substring(1) : text;
        }
    }
}
