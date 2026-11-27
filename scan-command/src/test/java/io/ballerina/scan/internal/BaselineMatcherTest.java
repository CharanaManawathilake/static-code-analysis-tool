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

import io.ballerina.scan.Issue;
import io.ballerina.scan.RuleKind;
import io.ballerina.scan.Source;
import io.ballerina.scan.internal.BaselineFile.Entry;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.ballerinalang.compiler.diagnostic.BLangDiagnosticLocation;

import java.util.List;
import java.util.Set;

/**
 * Tests for matching the issues of a package against its baseline by hash and count.
 *
 * @since 0.15.0
 */
public class BaselineMatcherTest {
    private static final String HASH = "9f2c51d0a4b87e13c6f0e2d9b1a47c58";
    private static final String OTHER_HASH = "4be1a7c3f09d2e8b5a6c1f7e3d9b0a24";
    private static final String PACKAGE = "myorg/orders";

    @Test(description = "test as many identical issues as entries are all in the baseline")
    void testAsManyIssuesAsEntries() {
        List<Issue> issues = List.of(issue(HASH, 1), issue(HASH, 2));
        BaselineMatcher.Match match = BaselineMatcher.match(issues, List.of(entry(HASH, 1), entry(HASH, 2)));
        Assert.assertEquals(match.baselined().size(), 2);
        Assert.assertTrue(match.stale().isEmpty());
        Assert.assertEquals(match.kept().size(), 2);
    }

    @Test(description = "test more identical issues than entries makes the last ones in source order new")
    void testMoreIssuesThanEntries() {
        Issue first = issue(HASH, 1);
        Issue second = issue(HASH, 2);
        Issue third = issue(HASH, 3);
        // Given out of order, as they are matched by occurrence number, not by list order
        BaselineMatcher.Match match = BaselineMatcher.match(List.of(third, first, second),
                List.of(entry(HASH, 2), entry(HASH, 1)));
        Assert.assertEquals(match.baselined(), Set.of(first, second));
        Assert.assertFalse(match.baselined().contains(third));
        Assert.assertTrue(match.stale().isEmpty());
    }

    @Test(description = "test fewer identical issues than entries makes the entries with the highest numbers stale")
    void testFewerIssuesThanEntries() {
        Issue remaining = issue(HASH, 1);
        BaselineMatcher.Match match = BaselineMatcher.match(List.of(remaining),
                List.of(entry(HASH, 3), entry(HASH, 1), entry(HASH, 2)));
        Assert.assertEquals(match.baselined(), Set.of(remaining));
        Assert.assertEquals(match.stale(), List.of(entry(HASH, 2), entry(HASH, 3)));
        Assert.assertEquals(match.kept(), List.of(entry(HASH, 1)));
    }

    @Test(description = "test an issue renumbered by the removal of a suppressed one before it is still in the "
            + "baseline, and the kept entry takes its current number")
    void testRenumberedIssue() {
        // The first of two identical issues was suppressed, so the second was baselined as :2; removing the first
        // renumbers the second as :1
        Issue renumbered = issue(HASH, 1);
        BaselineMatcher.Match match = BaselineMatcher.match(List.of(renumbered), List.of(entry(HASH, 2)));
        Assert.assertEquals(match.baselined(), Set.of(renumbered));
        Assert.assertTrue(match.stale().isEmpty());
        Assert.assertEquals(match.kept(), List.of(entry(HASH, 1)));
    }

    @Test(description = "test a replaced identical issue cannot be told apart, as only the count is compared")
    void testReplacementIsNotDetected() {
        // One identical issue removed and another added in the same change leaves the count unchanged
        List<Issue> issues = List.of(issue(HASH, 1), issue(HASH, 2));
        BaselineMatcher.Match match = BaselineMatcher.match(issues, List.of(entry(HASH, 1), entry(HASH, 2)));
        Assert.assertEquals(match.baselined().size(), 2);
    }

    @Test(description = "test issues and entries of different hashes are matched independently")
    void testDifferentHashes() {
        Issue newIssue = issue(OTHER_HASH, 1);
        Issue baselined = issue(HASH, 1);
        BaselineMatcher.Match match = BaselineMatcher.match(List.of(newIssue, baselined),
                List.of(entry(HASH, 1), entry("0123456789abcdef0123456789abcdef", 1)));
        Assert.assertEquals(match.baselined(), Set.of(baselined));
        Assert.assertEquals(match.stale(), List.of(entry("0123456789abcdef0123456789abcdef", 1)));
    }

    @Test(description = "test an issue without a fingerprint is always new")
    void testIssueWithoutFingerprint() {
        IssueImpl issue = new IssueImpl(location(), RuleFactory.createRule(1, "rule 1", RuleKind.CODE_SMELL),
                Source.BUILT_IN, "main.bal", "main.bal");
        BaselineMatcher.Match match = BaselineMatcher.match(List.of(issue), List.of(entry(HASH, 1)));
        Assert.assertTrue(match.baselined().isEmpty());
        Assert.assertEquals(match.stale().size(), 1);
    }

    @Test(description = "test an entry is in the scope of a scan only for its package, a selected rule and an "
            + "analyzed file")
    void testScope() {
        BaselineMatcher.Scope scope = new BaselineMatcher.Scope(PACKAGE,
                new RuleSelection(List.of(), List.of("ballerina:2")), Set.of("tests/main_test.bal"));
        Assert.assertTrue(scope.contains(new Entry(HASH + ":1", "ballerina:1", PACKAGE, "main.bal", "")));
        Assert.assertFalse(scope.contains(new Entry(HASH + ":1", "ballerina:1", "myorg/other", "main.bal", "")));
        Assert.assertFalse(scope.contains(new Entry(HASH + ":1", "ballerina:2", PACKAGE, "main.bal", "")));
        Assert.assertFalse(scope.contains(new Entry(HASH + ":1", "ballerina:1", PACKAGE, "tests/main_test.bal",
                "")));

        BaselineMatcher.Scope included = new BaselineMatcher.Scope(PACKAGE,
                new RuleSelection(List.of("ballerina:13"), List.of()), Set.of());
        Assert.assertTrue(included.contains(new Entry(HASH + ":1", "ballerina:13", PACKAGE, "main.bal", "")));
        Assert.assertFalse(included.contains(new Entry(HASH + ":1", "ballerina:1", PACKAGE, "main.bal", "")));
    }

    private static IssueImpl issue(String hash, int occurrence) {
        IssueImpl issue = new IssueImpl(location(), RuleFactory.createRule(1, "rule 1", RuleKind.CODE_SMELL),
                Source.BUILT_IN, "main.bal", "main.bal");
        issue.setFinding(new Finding(hash, occurrence, "ballerina:1", PACKAGE, "main.bal", "snippet"));
        return issue;
    }

    private static Entry entry(String hash, int occurrence) {
        return new Entry(hash + ":" + occurrence, "ballerina:1", PACKAGE, "main.bal", "snippet");
    }

    private static BLangDiagnosticLocation location() {
        return new BLangDiagnosticLocation("main.bal", 0, 0, 0, 1, 0, 1);
    }
}
