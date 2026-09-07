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
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

/**
 * Core static code analysis rules tests.
 *
 * @since 0.1.0
 */
public class CoreRuleTest {
    public static final String AVOID_CHECKPANIC = "Avoid checkpanic";
    public static final String UNUSED_FUNCTION_PARAMETER = "Unused function parameter";
    public static final String OPERATION_ALWAYS_EVALUATES_TO_TRUE = "This operation always evaluates to true";
    public static final String OPERATION_ALWAYS_EVALUATES_TO_FALSE = "This operation always evaluates to false";
    public static final String OPERATION_ALWAYS_EVALUATES_TO_SELF_VALUE =
            "This operation always evaluates to the same value";
    public static final String SELF_ASSIGNMENT = "This variable is assigned to itself";
    public static final String PUBLIC_NON_ISOLATED_FUNCTION_CONSTRUCT =
            "Non isolated public function";
    public static final String PUBLIC_NON_ISOLATED_METHOD_CONSTRUCT =
            "Non isolated public method";
    public static final String PUBLIC_NON_ISOLATED_CLASS_CONSTRUCT =
            "Non isolated public class";
    public static final String PUBLIC_NON_ISOLATED_OBJECT_CONSTRUCT =
            "Non isolated public object";
    public static final String HARD_CODED_SECRET = "Hard-coded secrets are security-sensitive";
    public static final String NON_CONFIGURABLE_SECRET = "Non configurable secrets are security-sensitive";

    @Test(description = "test all rules")
    void testAllRules() {
        Assert.assertEquals(CoreRule.rules().size(), 14);
    }

    @Test(description = "test that every core rule carries its rich metadata")
    void testAllRulesHaveRichMetadata() {
        for (Rule rule : CoreRule.rules()) {
            Assert.assertEquals(rule.name(), rule.description(), "name should default to description for " +
                    rule.id());
            Assert.assertNotNull(rule.fullDescription(), "fullDescription should be populated for " + rule.id());
            Assert.assertNotNull(rule.helpUri(), "helpUri should be populated for " + rule.id());
            Assert.assertNotNull(rule.level(), "level should be populated for " + rule.id());
            Assert.assertEquals(rule.enabled(), Boolean.TRUE, "enabled should default to true for " + rule.id());
            // precision has not been vetted for any core rule yet, so none of the bundled
            // core-rules/rule-0NN.json files specify it - it must stay null/omitted until it has.
            Assert.assertNull(rule.precision(), "precision should not be set for " + rule.id() +
                    " until it has been reviewed for that rule");
            Assert.assertNotNull(rule.securitySeverity(), "securitySeverity should be populated for " + rule.id());
        }
    }

    @Test(description = "test checkpanic rule")
    void testCheckpanicRule() {
        Rule rule = CoreRule.AVOID_CHECKPANIC.rule();
        Assert.assertEquals(rule.id(), "ballerina:1");
        Assert.assertEquals(rule.numericId(), 1);
        Assert.assertEquals(rule.description(), AVOID_CHECKPANIC);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
        Assert.assertEquals(rule.level(), "note");
        Assert.assertNull(rule.precision());
        Assert.assertEquals(rule.tags(), List.of("maintainability", "external/cwe/cwe-248",
                "external/cwe/cwe-636", "external/owasp/owasp-a10-2025"));
        Assert.assertEquals(rule.cwe(), List.of(248, 636));
        Assert.assertEquals(rule.owasp(), List.of("A10:2025"));
        Assert.assertEquals(rule.securitySeverity(), Double.valueOf(5.3));
    }

    @Test(description = "test unused function parameters test")
    void testUnusedFunctionParameterRule() {
        Rule rule = CoreRule.UNUSED_FUNCTION_PARAMETER.rule();
        Assert.assertEquals(rule.id(), "ballerina:2");
        Assert.assertEquals(rule.numericId(), 2);
        Assert.assertEquals(rule.description(), UNUSED_FUNCTION_PARAMETER);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
        Assert.assertEquals(rule.tags(), List.of("maintainability"));
        Assert.assertTrue(rule.cwe().isEmpty());
        Assert.assertTrue(rule.owasp().isEmpty());
        Assert.assertEquals(rule.securitySeverity(), Double.valueOf(0.0));
    }

    @Test(description = "test unused class fields rule")
    void testUnusedClassFieldsRule() {
        Rule rule = CoreRule.UNUSED_PRIVATE_CLASS_FIELD.rule();
        Assert.assertEquals(rule.id(), "ballerina:11");
        Assert.assertEquals(rule.numericId(), 11);
        Assert.assertEquals(rule.description(), "Unused class private fields");
    }
    
    @Test(description = "test always true evaluates")
    void testTrueEvaluates() {
        Rule rule = CoreRule.OPERATION_ALWAYS_EVALUATES_TO_TRUE.rule();
        Assert.assertEquals(rule.id(), "ballerina:7");
        Assert.assertEquals(rule.numericId(), 7);
        Assert.assertEquals(rule.description(), OPERATION_ALWAYS_EVALUATES_TO_TRUE);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test always false evaluates")
    void testFalseEvaluates() {
        Rule rule = CoreRule.OPERATION_ALWAYS_EVALUATES_TO_FALSE.rule();
        Assert.assertEquals(rule.id(), "ballerina:8");
        Assert.assertEquals(rule.numericId(), 8);
        Assert.assertEquals(rule.description(), OPERATION_ALWAYS_EVALUATES_TO_FALSE);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test evaluate to the same value")
    void testSelfEvaluates() {
        Rule rule = CoreRule.OPERATION_ALWAYS_EVALUATES_TO_SELF_VALUE.rule();
        Assert.assertEquals(rule.id(), "ballerina:9");
        Assert.assertEquals(rule.numericId(), 9);
        Assert.assertEquals(rule.description(), OPERATION_ALWAYS_EVALUATES_TO_SELF_VALUE);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test self assignment")
    void testSelfAssignmentAnalyzer() {
        Rule rule = CoreRule.SELF_ASSIGNMENT.rule();
        Assert.assertEquals(rule.id(), "ballerina:10");
        Assert.assertEquals(rule.numericId(), 10);
        Assert.assertEquals(rule.description(), SELF_ASSIGNMENT);
    }

    @Test(description = "test non isolated public functions")
    void testNonIsolatedPublicFunctionConstructsRule() {
        Rule rule = CoreRule.PUBLIC_NON_ISOLATED_FUNCTION_CONSTRUCT.rule();
        Assert.assertEquals(rule.id(), "ballerina:3");
        Assert.assertEquals(rule.numericId(), 3);
        Assert.assertEquals(rule.description(), PUBLIC_NON_ISOLATED_FUNCTION_CONSTRUCT);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test non isolated public methods")
    void testNonIsolatedPublicMethodConstructsRule() {
        Rule rule = CoreRule.PUBLIC_NON_ISOLATED_METHOD_CONSTRUCT.rule();
        Assert.assertEquals(rule.id(), "ballerina:4");
        Assert.assertEquals(rule.numericId(), 4);
        Assert.assertEquals(rule.description(), PUBLIC_NON_ISOLATED_METHOD_CONSTRUCT);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test non isolated public classes")
    void testNonIsolatedPublicClassConstructsRule() {
        Rule rule = CoreRule.PUBLIC_NON_ISOLATED_CLASS_CONSTRUCT.rule();
        Assert.assertEquals(rule.id(), "ballerina:5");
        Assert.assertEquals(rule.numericId(), 5);
        Assert.assertEquals(rule.description(), PUBLIC_NON_ISOLATED_CLASS_CONSTRUCT);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test non isolated public objects")
    void testNonIsolatedPublicObjectConstructsRule() {
        Rule rule = CoreRule.PUBLIC_NON_ISOLATED_OBJECT_CONSTRUCT.rule();
        Assert.assertEquals(rule.id(), "ballerina:6");
        Assert.assertEquals(rule.numericId(), 6);
        Assert.assertEquals(rule.description(), PUBLIC_NON_ISOLATED_OBJECT_CONSTRUCT);
        Assert.assertEquals(rule.kind(), RuleKind.CODE_SMELL);
    }

    @Test(description = "test hard coded secret")
    void testHardCodedSecretRule() {
        Rule rule = CoreRule.HARD_CODED_SECRET.rule();
        Assert.assertEquals(rule.id(), "ballerina:13");
        Assert.assertEquals(rule.numericId(), 13);
        Assert.assertEquals(rule.description(), HARD_CODED_SECRET);
        Assert.assertEquals(rule.kind(), RuleKind.VULNERABILITY);
        Assert.assertEquals(rule.level(), "warning");
        Assert.assertNull(rule.precision());
        Assert.assertEquals(rule.tags(), List.of("security", "external/cwe/cwe-798",
                "external/owasp/owasp-a07-2025"));
        Assert.assertEquals(rule.cwe(), List.of(798));
        Assert.assertEquals(rule.owasp(), List.of("A07:2025"));
        Assert.assertEquals(rule.securitySeverity(), Double.valueOf(8.6));
    }

    @Test(description = "test non configurable coded secret")
    void testNonConfigurableSecretRule() {
        Rule rule = CoreRule.NON_CONFIGURABLE_SECRET.rule();
        Assert.assertEquals(rule.id(), "ballerina:14");
        Assert.assertEquals(rule.numericId(), 14);
        Assert.assertEquals(rule.description(), NON_CONFIGURABLE_SECRET);
        Assert.assertEquals(rule.kind(), RuleKind.VULNERABILITY);
        Assert.assertEquals(rule.level(), "warning");
        Assert.assertNull(rule.precision());
        Assert.assertEquals(rule.tags(), List.of("security", "external/cwe/cwe-798",
                "external/owasp/owasp-a07-2025"));
        Assert.assertEquals(rule.cwe(), List.of(798));
        Assert.assertEquals(rule.owasp(), List.of("A07:2025"));
        Assert.assertEquals(rule.securitySeverity(), Double.valueOf(6.5));
    }
}
