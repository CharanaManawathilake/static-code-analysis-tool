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

import com.google.gson.annotations.SerializedName;
import io.ballerina.scan.Rule;
import io.ballerina.scan.RuleKind;
import io.ballerina.scan.Severity;
import io.ballerina.scan.Standards;

import java.util.List;

/**
 * Represents the implementation of the {@link Rule} interface.
 *
 * @since 0.1.0
 * */
public class RuleImpl implements Rule {

    private final String id;
    private final int numericId;
    private final String name;
    private final String description;
    // Serialized as "details" in the Ballerina JSON output (SARIF keeps its own separate
    // "fullDescription" property, built independently in ScanUtils - this annotation only affects
    // Gson's field-based reflection over this class).
    @SerializedName("details")
    private final String fullDescription;
    private final String helpUri;
    private final Severity severity;
    private final List<String> tags;
    private final Standards standards;
    private final RuleKind ruleKind;

    RuleImpl(String id, int numericId, String description, RuleKind ruleKind) {
        this(id, numericId, description, ruleKind, null, null, null, null, null, null);
    }

    RuleImpl(String id, int numericId, String description, RuleKind ruleKind, String name, String fullDescription,
             String helpUri, Severity severity, List<String> tags, Standards standards) {
        this.id = id;
        this.numericId = numericId;
        this.description = description;
        this.ruleKind = ruleKind;
        this.name = name;
        this.fullDescription = fullDescription;
        this.helpUri = helpUri;
        this.severity = severity;
        this.tags = tags;
        this.standards = standards;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public int numericId() {
        return numericId;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public RuleKind kind() {
        return ruleKind;
    }

    @Override
    public String name() {
        // Field stays null (and thus omitted from the Ballerina JSON output) when not explicitly
        // set, but the Java API contract (see Rule#name()) still promises a fallback to
        // description() so callers such as ScanUtils never see a null name.
        return name != null ? name : description;
    }

    @Override
    public String fullDescription() {
        return fullDescription != null ? fullDescription : description;
    }

    @Override
    public String helpUri() {
        return helpUri;
    }

    @Override
    public Severity severity() {
        return severity;
    }

    @Override
    public List<String> tags() {
        return tags != null ? List.copyOf(tags) : null;
    }

    @Override
    public Standards standards() {
        return standards;
    }
}
