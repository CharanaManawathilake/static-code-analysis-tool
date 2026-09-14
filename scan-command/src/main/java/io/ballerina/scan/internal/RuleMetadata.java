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

import io.ballerina.scan.RuleKind;
import io.ballerina.scan.Severity;
import io.ballerina.scan.Standards;

import java.util.List;

/**
 * {@code RuleMetadata} is an immutable holder for the rich, authored metadata of a core static
 * code analysis rule, loaded from its bundled JSON resource file and passed to
 * {@link RuleFactory#createCoreRule(RuleMetadata)}.
 *
 * @since 0.1.0
 */
final class RuleMetadata {

    private final int numericId;
    private final String name;
    private final String description;
    private final String fullDescription;
    private final RuleKind ruleKind;
    private final Severity severity;
    private final List<String> tags;
    private final Standards standards;

    private RuleMetadata(Builder builder) {
        this.numericId = builder.numericId;
        this.name = builder.name;
        this.description = builder.description;
        this.fullDescription = builder.fullDescription;
        this.ruleKind = builder.ruleKind;
        this.severity = builder.severity;
        this.tags = builder.tags;
        this.standards = builder.standards;
    }

    int numericId() {
        return numericId;
    }

    String name() {
        return name;
    }

    String description() {
        return description;
    }

    String fullDescription() {
        return fullDescription;
    }

    RuleKind ruleKind() {
        return ruleKind;
    }

    Severity severity() {
        return severity;
    }

    List<String> tags() {
        return tags;
    }

    Standards standards() {
        return standards;
    }

    static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        private int numericId;
        private String name;
        private String description;
        private String fullDescription;
        private RuleKind ruleKind;
        private Severity severity;
        private List<String> tags;
        private Standards standards;

        Builder numericId(int numericId) {
            this.numericId = numericId;
            return this;
        }

        Builder name(String name) {
            this.name = name;
            return this;
        }

        Builder description(String description) {
            this.description = description;
            return this;
        }

        Builder fullDescription(String fullDescription) {
            this.fullDescription = fullDescription;
            return this;
        }

        Builder ruleKind(RuleKind ruleKind) {
            this.ruleKind = ruleKind;
            return this;
        }

        Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }

        Builder standards(Standards standards) {
            this.standards = standards;
            return this;
        }

        RuleMetadata build() {
            return new RuleMetadata(this);
        }
    }
}
