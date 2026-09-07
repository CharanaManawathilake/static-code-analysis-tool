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

import io.ballerina.scan.Rule;
import io.ballerina.scan.RuleKind;

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
    private final String fullDescription;
    private final String helpUri;
    private final String level;
    private final Boolean enabled;
    private final List<String> tags;
    // cwe/owasp are intentionally left out of the Ballerina JSON output (they are redundant with
    // "tags", which already carries the same CWE/OWASP references) but remain available through
    // the Rule API for callers that want structured access.
    private final transient List<Integer> cwe;
    private final transient List<String> owasp;
    private final String precision;
    private final Double securitySeverity;
    private final RuleKind ruleKind;

    RuleImpl(String id, int numericId, String description, RuleKind ruleKind) {
        this(id, numericId, description, ruleKind, null, null, null, null, null, null, null, null, null);
    }

    RuleImpl(String id, int numericId, String description, RuleKind ruleKind, String name, String fullDescription,
             String helpUri, String level, Boolean enabled, List<String> tags, List<Integer> cwe,
             List<String> owasp, String precision) {
        this(id, numericId, description, ruleKind, name, fullDescription, helpUri, level, enabled, tags, cwe, owasp,
                precision, null);
    }

    RuleImpl(String id, int numericId, String description, RuleKind ruleKind, String name, String fullDescription,
             String helpUri, String level, Boolean enabled, List<String> tags, List<Integer> cwe,
             List<String> owasp, String precision, Double securitySeverity) {
        this.id = id;
        this.numericId = numericId;
        this.description = description;
        this.ruleKind = ruleKind;
        this.name = name;
        this.fullDescription = fullDescription;
        this.helpUri = helpUri;
        this.level = level;
        this.enabled = enabled;
        this.tags = tags;
        this.cwe = cwe;
        this.owasp = owasp;
        this.precision = precision;
        this.securitySeverity = securitySeverity;
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
        return name;
    }

    @Override
    public String fullDescription() {
        return fullDescription;
    }

    @Override
    public String helpUri() {
        return helpUri;
    }

    @Override
    public String level() {
        return level;
    }

    @Override
    public Boolean enabled() {
        return enabled;
    }

    @Override
    public List<String> tags() {
        return tags != null ? List.copyOf(tags) : null;
    }

    @Override
    public List<Integer> cwe() {
        return cwe != null ? List.copyOf(cwe) : null;
    }

    @Override
    public List<String> owasp() {
        return owasp != null ? List.copyOf(owasp) : null;
    }

    @Override
    public String precision() {
        return precision;
    }

    @Override
    public Double securitySeverity() {
        return securitySeverity;
    }
}
