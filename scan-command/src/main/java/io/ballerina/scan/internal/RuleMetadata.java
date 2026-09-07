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
    private final String description;
    private final String fullDescription;
    private final RuleKind ruleKind;
    private final List<String> tags;
    private final List<Integer> cwe;
    private final List<String> owasp;
    private final String precision;
    private final Double securitySeverity;

    private RuleMetadata(Builder builder) {
        this.numericId = builder.numericId;
        this.description = builder.description;
        this.fullDescription = builder.fullDescription;
        this.ruleKind = builder.ruleKind;
        this.tags = builder.tags;
        this.cwe = builder.cwe;
        this.owasp = builder.owasp;
        this.precision = builder.precision;
        this.securitySeverity = builder.securitySeverity;
    }

    int numericId() {
        return numericId;
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

    List<String> tags() {
        return tags;
    }

    List<Integer> cwe() {
        return cwe;
    }

    List<String> owasp() {
        return owasp;
    }

    String precision() {
        return precision;
    }

    Double securitySeverity() {
        return securitySeverity;
    }

    static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        private int numericId;
        private String description;
        private String fullDescription;
        private RuleKind ruleKind;
        private List<String> tags;
        private List<Integer> cwe;
        private List<String> owasp;
        private String precision;
        private Double securitySeverity;

        Builder numericId(int numericId) {
            this.numericId = numericId;
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

        Builder tags(List<String> tags) {
            this.tags = tags;
            return this;
        }

        Builder cwe(List<Integer> cwe) {
            this.cwe = cwe;
            return this;
        }

        Builder owasp(List<String> owasp) {
            this.owasp = owasp;
            return this;
        }

        Builder precision(String precision) {
            this.precision = precision;
            return this;
        }

        Builder securitySeverity(Double securitySeverity) {
            this.securitySeverity = securitySeverity;
            return this;
        }

        RuleMetadata build() {
            return new RuleMetadata(this);
        }
    }
}
