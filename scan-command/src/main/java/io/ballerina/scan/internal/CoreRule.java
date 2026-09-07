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

import com.google.gson.Gson;
import io.ballerina.scan.Rule;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static io.ballerina.scan.internal.ScanToolConstants.CORE_RULES_DIRECTORY;

/**
 * {@code CoreRule} contains the core static code analysis rules. The rich metadata for each rule
 * (full description, tags, precision, CWE/OWASP references, etc.) is authored in a dedicated JSON
 * resource file under {@code core-rules/} rather than inline here, so that content can be
 * reviewed/updated per rule without touching this wiring.
 *
 * @since 0.1.0
 * */
enum CoreRule {

    AVOID_CHECKPANIC(loadCoreRule("rule-001.json")),
    UNUSED_FUNCTION_PARAMETER(loadCoreRule("rule-002.json")),
    PUBLIC_NON_ISOLATED_FUNCTION_CONSTRUCT(loadCoreRule("rule-003.json")),
    PUBLIC_NON_ISOLATED_METHOD_CONSTRUCT(loadCoreRule("rule-004.json")),
    PUBLIC_NON_ISOLATED_CLASS_CONSTRUCT(loadCoreRule("rule-005.json")),
    PUBLIC_NON_ISOLATED_OBJECT_CONSTRUCT(loadCoreRule("rule-006.json")),
    OPERATION_ALWAYS_EVALUATES_TO_TRUE(loadCoreRule("rule-007.json")),
    OPERATION_ALWAYS_EVALUATES_TO_FALSE(loadCoreRule("rule-008.json")),
    OPERATION_ALWAYS_EVALUATES_TO_SELF_VALUE(loadCoreRule("rule-009.json")),
    SELF_ASSIGNMENT(loadCoreRule("rule-010.json")),
    UNUSED_PRIVATE_CLASS_FIELD(loadCoreRule("rule-011.json")),
    INVALID_RANGE_EXPRESSION(loadCoreRule("rule-012.json")),
    HARD_CODED_SECRET(loadCoreRule("rule-013.json")),
    NON_CONFIGURABLE_SECRET(loadCoreRule("rule-014.json"));

    private final Rule rule;

    CoreRule(Rule rule) {
        this.rule = rule;
    }

    Rule rule() {
        return rule;
    }

    static List<Rule> rules() {
        List<Rule> coreRules = new ArrayList<>();
        for (CoreRule coreRule: CoreRule.values()) {
            coreRules.add(coreRule.rule());
        }
        return coreRules;
    }

    /**
     * Loads a core rule's metadata from its bundled JSON resource file and builds the
     * corresponding {@link Rule} instance.
     *
     * @param resourceFileName the JSON resource file name, e.g. {@code rule-001.json}
     * @return the fully populated core rule instance
     */
    private static Rule loadCoreRule(String resourceFileName) {
        String resourcePath = CORE_RULES_DIRECTORY + resourceFileName;
        try (InputStream input = CoreRule.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (input == null) {
                throw new IllegalStateException("Missing core rule metadata resource: " + resourcePath);
            }
            String content = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            CoreRuleDefinition definition = new Gson().fromJson(content, CoreRuleDefinition.class);
            return RuleFactory.createCoreRule(definition.toMetadata());
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to load core rule metadata: " + resourcePath, ex);
        }
    }
}
