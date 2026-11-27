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

import io.ballerina.scan.Issue;
import io.ballerina.scan.Rule;
import io.ballerina.scan.Source;
import io.ballerina.tools.diagnostics.Location;
import io.ballerina.tools.text.LineRange;
import io.ballerina.tools.text.TextRange;
import org.wso2.ballerinalang.compiler.diagnostic.BLangDiagnosticLocation;

import java.util.Map;

/**
 * Represents the implementation of the {@link Issue} interface.
 *
 * @since 0.1.0
 * */
public class IssueImpl implements Issue {
    private final BLangDiagnosticLocation location;
    private final RuleImpl rule;
    private final Source source;
    private final String fileName;
    private final String filePath;
    // Transient, so that the JSON report writes them in its own form instead of serializing them
    private transient Finding finding;
    private transient BaselineState baselineState;

    IssueImpl(Location location,
              Rule rule,
              Source source,
              String fileName,
              String filePath) {
        LineRange lineRange = location.lineRange();
        TextRange textRange = location.textRange();
        this.location = new BLangDiagnosticLocation(lineRange.fileName(), lineRange.startLine().line(),
                lineRange.endLine().line(), lineRange.startLine().offset(), lineRange.endLine().offset(),
                textRange.startOffset(), textRange.length());
        this.rule = (RuleImpl) rule;
        this.source = source;
        this.fileName = fileName;
        this.filePath = filePath;
    }

    @Override
    public Location location() {
        return location;
    }

    @Override
    public Rule rule() {
        return rule;
    }

    @Override
    public Source source() {
        return source;
    }

    public String filePath() {
        return filePath;
    }

    public String fileName() {
        return fileName;
    }

    @Override
    public Map<String, String> partialFingerprints() {
        return finding == null ? Map.of() : Map.of(Fingerprints.KEY, finding.fingerprint());
    }

    /**
     * Returns whether the issue is new or in the baseline, as written to the {@code baselineState} of the reports.
     *
     * @return {@code new} or {@code unchanged}, or null when the scan uses no baseline
     * @since 0.15.0
     */
    public String baselineState() {
        return baselineState == null ? null : baselineState.value();
    }

    Finding finding() {
        return finding;
    }

    void setFinding(Finding finding) {
        this.finding = finding;
    }

    void setBaselineState(BaselineState baselineState) {
        this.baselineState = baselineState;
    }
}
