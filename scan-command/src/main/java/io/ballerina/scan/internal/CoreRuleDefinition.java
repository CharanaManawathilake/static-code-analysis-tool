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
 * {@code CoreRuleDefinition} is a Gson deserialization target mirroring the JSON shape of a
 * bundled core rule metadata resource file (see {@code core-rules/rule-0NN.json}).
 *
 * @since 0.1.0
 */
final class CoreRuleDefinition {

    private int id;
    private String kind;
    private String description;
    private String fullDescription;
    private String precision;
    private List<String> tags;
    private List<Integer> cwe;
    private List<String> owasp;
    private Double securitySeverity;

    RuleMetadata toMetadata() {
        return RuleMetadata.builder()
                .numericId(id)
                .description(description)
                .fullDescription(fullDescription != null ? fullDescription : description)
                .ruleKind(RuleKind.valueOf(kind))
                .tags(tags != null ? tags : List.of())
                .cwe(cwe != null ? cwe : List.of())
                .owasp(owasp != null ? owasp : List.of())
                .precision(precision)
                .securitySeverity(securitySeverity)
                .build();
    }
}
