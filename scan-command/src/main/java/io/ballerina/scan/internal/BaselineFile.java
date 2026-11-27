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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.ballerina.scan.internal.BaselineJson.ArrayValue;
import io.ballerina.scan.internal.BaselineJson.Member;
import io.ballerina.scan.internal.BaselineJson.NumberValue;
import io.ballerina.scan.internal.BaselineJson.ObjectValue;
import io.ballerina.scan.internal.BaselineJson.StringValue;
import io.ballerina.scan.internal.BaselineJson.Value;
import io.ballerina.scan.utils.Constants;
import io.ballerina.scan.utils.DiagnosticCode;
import io.ballerina.scan.utils.DiagnosticLog;
import io.ballerina.scan.utils.ScanUtils;
import io.ballerina.tools.text.LinePosition;
import io.ballerina.tools.text.LineRange;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A baseline file: the issues a team has accepted, so that a scan reports and gates only the issues that are not in
 * it. The file is JSON, committed to the repository and written in a stable order, with no line numbers or dates, so
 * that an unrelated change or a rerun does not change it.
 *
 * @since 0.15.0
 */
final class BaselineFile {
    static final int FORMAT_VERSION = 1;
    private static final String VERSION_FIELD = "version";
    private static final String FINGERPRINT_FIELD = "fingerprint";
    private static final String SCAN_VERSION_FIELD = "balScanVersion";
    private static final String ISSUES_FIELD = "issues";
    private static final String RULE_ID_FIELD = "ruleId";
    private static final String PACKAGE_FIELD = "package";
    private static final String FILE_PATH_FIELD = "filePath";
    private static final String SNIPPET_FIELD = "snippet";
    private static final List<String> FILE_FIELDS = List.of(VERSION_FIELD, FINGERPRINT_FIELD, SCAN_VERSION_FIELD,
            ISSUES_FIELD);
    private static final List<String> ENTRY_FIELDS = List.of(FINGERPRINT_FIELD, RULE_ID_FIELD, PACKAGE_FIELD,
            FILE_PATH_FIELD, SNIPPET_FIELD);
    private static final Set<String> SUPPORTED_FINGERPRINTS = Set.of(Fingerprints.KEY);
    private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{32}:[1-9][0-9]{0,8}");
    private static final String FINGERPRINT_VALUES = "a 32-digit lowercase hexadecimal hash and an occurrence "
            + "number, such as \"9f2c51d0a4b87e13c6f0e2d9b1a47c58:1\"";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final Path path;
    private final String displayPath;
    private final boolean exists;
    private final List<Entry> entries;

    private BaselineFile(Path path, String displayPath, boolean exists, List<Entry> entries) {
        this.path = path;
        this.displayPath = displayPath;
        this.exists = exists;
        this.entries = List.copyOf(entries);
    }

    /**
     * An accepted issue. Only the fingerprint is matched on; the other fields make the file reviewable, and decide
     * whether the entry is in the scope of a scan.
     *
     * @param fingerprint the fingerprint of the issue, with its occurrence number
     * @param ruleId      the ID of the rule
     * @param packageName the organization and name of the package
     * @param filePath    the path of the file relative to the package root
     * @param snippet     the first flagged line, with the content of every literal redacted
     */
    record Entry(String fingerprint, String ruleId, String packageName, String filePath, String snippet) {
        static final Comparator<Entry> ORDER = Comparator.comparing(Entry::packageName)
                .thenComparing(Entry::filePath)
                .thenComparing(Entry::ruleId)
                .thenComparing(Entry::hash)
                .thenComparingInt(Entry::occurrence);

        static Entry of(Finding finding) {
            return new Entry(finding.fingerprint(), finding.ruleId(), finding.packageName(), finding.filePath(),
                    finding.snippet());
        }

        String hash() {
            return fingerprint.substring(0, fingerprint.indexOf(':'));
        }

        int occurrence() {
            return Integer.parseInt(fingerprint.substring(fingerprint.indexOf(':') + 1));
        }
    }

    /**
     * Returns a baseline that does not exist yet, which {@code --create-baseline} creates.
     *
     * @param path        the absolute path of the file
     * @param displayPath the path as shown to the user
     * @return the baseline, with no entries
     */
    static BaselineFile absent(Path path, String displayPath) {
        return new BaselineFile(path, displayPath, false, List.of());
    }

    /**
     * Reads and validates a baseline file.
     *
     * @param path        the absolute path of the file, which exists
     * @param displayPath the path as shown to the user
     * @return the baseline
     * @throws ScanFailure if the file cannot be read or is not a valid baseline, with every error at its position
     */
    static BaselineFile read(Path path, String displayPath) {
        String content;
        try {
            content = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw ScanFailure.runtime(DiagnosticLog.error(DiagnosticCode.BASELINE_READ_FAILED, displayPath,
                    ScanFailure.describe(ex)));
        }
        Value document;
        try {
            document = BaselineJson.parse(content);
        } catch (BaselineJson.SyntaxError ex) {
            throw failure(displayPath, List.of(new FileError(ex.position(),
                    DiagnosticLog.error(DiagnosticCode.BASELINE_INVALID_JSON, ex.getMessage()))));
        }
        List<FileError> errors = new ArrayList<>();
        List<Entry> entries = readDocument(document, errors);
        if (!errors.isEmpty()) {
            throw failure(displayPath, errors);
        }
        return new BaselineFile(path, displayPath, true, entries);
    }

    Path path() {
        return path;
    }

    String displayPath() {
        return displayPath;
    }

    boolean exists() {
        return exists;
    }

    List<Entry> entries() {
        return entries;
    }

    /**
     * Writes the entries to the file, in a stable order, unless the file already holds exactly these entries, so that
     * a rerun leaves the file and its {@code balScanVersion} unchanged.
     *
     * @param newEntries the entries to write
     * @return whether the file was written
     * @throws ScanFailure if the file cannot be written
     */
    boolean write(List<Entry> newEntries) {
        List<Entry> sortedEntries = new ArrayList<>(newEntries);
        sortedEntries.sort(Entry.ORDER);
        List<Entry> currentEntries = new ArrayList<>(entries);
        currentEntries.sort(Entry.ORDER);
        if (exists && currentEntries.equals(sortedEntries)) {
            return false;
        }
        Path temporaryFile = null;
        try {
            Path directory = path.toAbsolutePath().getParent();
            if (directory == null) {
                throw new IOException("the path names no file");
            }
            Files.createDirectories(directory);
            // Written to a temporary file first, so that a failed write never leaves a truncated baseline
            temporaryFile = Files.createTempFile(directory, ".scan-baseline-", ".tmp");
            Files.writeString(temporaryFile, render(sortedEntries), StandardCharsets.UTF_8);
            try {
                Files.move(temporaryFile, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temporaryFile, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException | RuntimeException ex) {
            throw ScanFailure.runtime(DiagnosticLog.error(DiagnosticCode.BASELINE_WRITE_FAILED, displayPath,
                    ScanFailure.describe(ex)));
        } finally {
            deleteQuietly(temporaryFile);
        }
        return true;
    }

    /**
     * Returns the JSON of a baseline holding the given entries, in the given order.
     */
    static String render(List<Entry> entries) {
        JsonObject file = new JsonObject();
        file.addProperty(VERSION_FIELD, FORMAT_VERSION);
        file.addProperty(FINGERPRINT_FIELD, Fingerprints.KEY);
        file.addProperty(SCAN_VERSION_FIELD, Constants.SARIF_TOOL_VERSION);
        JsonArray issues = new JsonArray();
        for (Entry entry : entries) {
            JsonObject issue = new JsonObject();
            issue.addProperty(FINGERPRINT_FIELD, entry.fingerprint());
            issue.addProperty(RULE_ID_FIELD, entry.ruleId());
            issue.addProperty(PACKAGE_FIELD, entry.packageName());
            issue.addProperty(FILE_PATH_FIELD, entry.filePath());
            issue.addProperty(SNIPPET_FIELD, entry.snippet());
            issues.add(issue);
        }
        file.add(ISSUES_FIELD, issues);
        return GSON.toJson(file) + "\n";
    }

    private static void deleteQuietly(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException ex) {
            // The temporary file is only left behind; the baseline itself is already written or reported
        }
    }

    private static List<Entry> readDocument(Value document, List<FileError> errors) {
        if (!(document instanceof ObjectValue file)) {
            errors.add(new FileError(document.position(),
                    DiagnosticLog.error(DiagnosticCode.BASELINE_NOT_AN_OBJECT, document.describe())));
            return List.of();
        }
        List<FileError> fieldErrors = new ArrayList<>();
        Map<String, Member> fields = fields(file, FILE_FIELDS, fieldErrors);
        Member version = fields.get(VERSION_FIELD);
        if (version != null && !isFormatVersion(version.value(), errors)) {
            // The other fields of another format version may mean something else, so they are not checked
            return List.of();
        }
        errors.addAll(fieldErrors);
        for (String required : List.of(VERSION_FIELD, FINGERPRINT_FIELD, ISSUES_FIELD)) {
            if (!fields.containsKey(required)) {
                errors.add(new FileError(file.position(),
                        DiagnosticLog.error(DiagnosticCode.BASELINE_MISSING_FIELD, required)));
            }
        }
        Member fingerprint = fields.get(FINGERPRINT_FIELD);
        if (fingerprint != null) {
            if (!(fingerprint.value() instanceof StringValue fingerprintVersion)) {
                errors.add(invalidValue(fingerprint, "the name of a fingerprint version, such as \""
                        + Fingerprints.KEY + "\""));
            } else if (!SUPPORTED_FINGERPRINTS.contains(fingerprintVersion.value())) {
                errors.add(new FileError(fingerprint.value().position(), DiagnosticLog.error(
                        DiagnosticCode.BASELINE_UNSUPPORTED_FINGERPRINT, fingerprintVersion.value(),
                        "'" + Fingerprints.KEY + "'")));
            }
        }
        Member scanVersion = fields.get(SCAN_VERSION_FIELD);
        if (scanVersion != null && !(scanVersion.value() instanceof StringValue)) {
            errors.add(invalidValue(scanVersion, "the version of the scan tool, such as \"0.15.0\""));
        }
        Member issues = fields.get(ISSUES_FIELD);
        if (issues == null) {
            return List.of();
        }
        if (!(issues.value() instanceof ArrayValue issueArray)) {
            errors.add(invalidValue(issues, "an array of issues"));
            return List.of();
        }
        List<Entry> entries = new ArrayList<>();
        Set<String> fingerprints = new HashSet<>();
        for (Value element : issueArray.elements()) {
            Entry entry = readEntry(element, errors);
            if (entry == null) {
                continue;
            }
            if (!fingerprints.add(entry.fingerprint())) {
                errors.add(new FileError(element.position(),
                        DiagnosticLog.error(DiagnosticCode.BASELINE_DUPLICATE_ENTRY, entry.fingerprint())));
                continue;
            }
            entries.add(entry);
        }
        return entries;
    }

    private static boolean isFormatVersion(Value version, List<FileError> errors) {
        if (version instanceof NumberValue number && number.text().matches("-?[0-9]+")) {
            if (number.text().equals(String.valueOf(FORMAT_VERSION))) {
                return true;
            }
            errors.add(new FileError(version.position(), DiagnosticLog.error(
                    DiagnosticCode.BASELINE_UNSUPPORTED_VERSION, number.text(), FORMAT_VERSION)));
            return false;
        }
        errors.add(new FileError(version.position(), DiagnosticLog.error(DiagnosticCode.BASELINE_INVALID_VALUE,
                version.describe(), VERSION_FIELD, "the version of the baseline format, such as " + FORMAT_VERSION)));
        return false;
    }

    /**
     * Reads an entry of {@code issues}, adding an error for each problem. Returns null when the entry is not valid.
     */
    private static Entry readEntry(Value element, List<FileError> errors) {
        if (!(element instanceof ObjectValue issue)) {
            errors.add(new FileError(element.position(), DiagnosticLog.error(
                    DiagnosticCode.BASELINE_INVALID_VALUE, element.describe(), ISSUES_FIELD,
                    "an array of issues, each an object")));
            return null;
        }
        int errorCount = errors.size();
        Map<String, Member> fields = fields(issue, ENTRY_FIELDS, errors);
        String fingerprint = requiredString(issue, fields, FINGERPRINT_FIELD, FINGERPRINT_VALUES, errors);
        if (fingerprint != null && !FINGERPRINT.matcher(fingerprint).matches()) {
            errors.add(invalidValue(fields.get(FINGERPRINT_FIELD), FINGERPRINT_VALUES));
        }
        String ruleId = requiredString(issue, fields, RULE_ID_FIELD, "a rule ID, such as \"ballerina:1\"", errors);
        String packageName = requiredString(issue, fields, PACKAGE_FIELD,
                "the organization and name of a package, such as \"myorg/orders\"", errors);
        String filePath = requiredString(issue, fields, FILE_PATH_FIELD,
                "the path of a file relative to the package root", errors);
        String snippet = "";
        Member snippetField = fields.get(SNIPPET_FIELD);
        if (snippetField != null) {
            if (snippetField.value() instanceof StringValue snippetValue) {
                snippet = snippetValue.value();
            } else {
                errors.add(invalidValue(snippetField, "the flagged line as a string"));
            }
        }
        return errors.size() > errorCount ? null : new Entry(fingerprint, ruleId, packageName, filePath, snippet);
    }

    private static String requiredString(ObjectValue object, Map<String, Member> fields, String name,
                                         String expected, List<FileError> errors) {
        Member field = fields.get(name);
        if (field == null) {
            errors.add(new FileError(object.position(),
                    DiagnosticLog.error(DiagnosticCode.BASELINE_MISSING_FIELD, name)));
            return null;
        }
        if (!(field.value() instanceof StringValue value) || value.value().isEmpty()) {
            errors.add(invalidValue(field, expected));
            return null;
        }
        return value.value();
    }

    /**
     * Returns the fields of an object by name, adding an error for each unknown or repeated field.
     */
    private static Map<String, Member> fields(ObjectValue object, List<String> known, List<FileError> errors) {
        Map<String, Member> fields = new LinkedHashMap<>();
        for (Member member : object.members()) {
            if (!known.contains(member.name())) {
                errors.add(new FileError(member.position(),
                        DiagnosticLog.error(DiagnosticCode.BASELINE_UNKNOWN_FIELD, member.name(),
                                ScanUtils.joinWith(known.stream().map(name -> "'" + name + "'").toList(), "or"))));
            } else if (fields.putIfAbsent(member.name(), member) != null) {
                errors.add(new FileError(member.position(),
                        DiagnosticLog.error(DiagnosticCode.BASELINE_DUPLICATE_FIELD, member.name())));
            }
        }
        return fields;
    }

    private static FileError invalidValue(Member member, String expected) {
        return new FileError(member.value().position(), DiagnosticLog.error(DiagnosticCode.BASELINE_INVALID_VALUE,
                member.value().describe(), member.name(), expected));
    }

    private static ScanFailure failure(String displayPath, List<FileError> errors) {
        List<FileError> sorted = new ArrayList<>(errors);
        sorted.sort(Comparator.comparingInt((FileError error) -> error.position().line())
                .thenComparingInt(error -> error.position().offset()));
        return ScanFailure.runtime(DiagnosticLog.error(DiagnosticCode.CONFIG_FILE_HAS_ERRORS, displayPath,
                sorted.size()), sorted.stream()
                .map(error -> DiagnosticLog.fileError(displayPath,
                        LineRange.from(displayPath, error.position(), error.position()), error.message()))
                .toList());
    }

    // An error found in a baseline file, at its position
    private record FileError(LinePosition position, String message) {
    }
}
