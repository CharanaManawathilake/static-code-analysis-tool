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
import io.ballerina.scan.internal.BaselineFile.Entry;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Matches the issues of a package against the entries of its baseline.
 *
 * <p>Issues and entries are matched by hash and by count, not by occurrence number: for each hash, the first
 * {@code k} unsuppressed issues in source order are in the baseline when it has {@code k} entries with that hash, and
 * the rest are new. When it has more entries than issues, the entries with the highest occurrence numbers are stale.
 * So adding, removing or suppressing one of several identical issues, which renumbers the ones after it, never makes an
 * unchanged issue new.
 *
 * @since 0.15.0
 */
final class BaselineMatcher {

    private BaselineMatcher() {
    }

    /**
     * The entries of a baseline that a scan of a package can see: those of the package, of a rule the scan selects
     * and of a file it analyzes. The scan treats the other entries as unknown, not as stale, so that a scan filtered
     * to some rules, or a package scanned alone against a workspace baseline, never removes them.
     *
     * @param packageName       the organization and name of the package
     * @param ruleSelection     the rules the scan selects for the package
     * @param excludedFilePaths the files of the package the scan leaves out, relative to the package root
     */
    record Scope(String packageName, RuleSelection ruleSelection, Set<String> excludedFilePaths) {
        Scope {
            excludedFilePaths = Set.copyOf(excludedFilePaths);
        }

        boolean contains(Entry entry) {
            return entry.packageName().equals(packageName) && ruleSelection.selects(entry.ruleId())
                    && !excludedFilePaths.contains(entry.filePath());
        }
    }

    /**
     * The result of matching the issues of a package against the entries in its scope.
     *
     * @param baselined the unsuppressed issues that are in the baseline
     * @param kept      the matched entries, rewritten with the current fingerprint of the issue each matches
     * @param stale     the entries that match no issue
     */
    record Match(Set<Issue> baselined, List<Entry> kept, List<Entry> stale) {
        Match {
            baselined = Collections.unmodifiableSet(baselined);
            kept = List.copyOf(kept);
            stale = List.copyOf(stale);
        }
    }

    /**
     * Matches the unsuppressed issues of a package against the entries of its baseline in the scope of the scan.
     *
     * @param activeIssues   the issues left after rule selection and suppressions
     * @param entriesInScope the entries of the baseline in the scope of the scan
     * @return the issues in the baseline, and the entries that are kept or stale
     */
    static Match match(Collection<Issue> activeIssues, Collection<Entry> entriesInScope) {
        Map<String, List<IssueImpl>> issuesByHash = new LinkedHashMap<>();
        for (Issue issue : activeIssues) {
            if (issue instanceof IssueImpl issueImpl && issueImpl.finding() != null) {
                issuesByHash.computeIfAbsent(issueImpl.finding().hash(), hash -> new ArrayList<>()).add(issueImpl);
            }
        }
        Map<String, List<Entry>> entriesByHash = new LinkedHashMap<>();
        entriesInScope.forEach(entry -> entriesByHash.computeIfAbsent(entry.hash(), hash -> new ArrayList<>())
                .add(entry));

        Set<Issue> baselined = Collections.newSetFromMap(new IdentityHashMap<>());
        List<Entry> kept = new ArrayList<>();
        List<Entry> stale = new ArrayList<>();
        for (Map.Entry<String, List<Entry>> sameHash : entriesByHash.entrySet()) {
            List<Entry> entries = sameHash.getValue();
            entries.sort(Comparator.comparingInt(Entry::occurrence));
            List<IssueImpl> issues = issuesByHash.getOrDefault(sameHash.getKey(), new ArrayList<>());
            issues.sort(Comparator.comparingInt(issue -> issue.finding().occurrence()));
            int matched = Math.min(entries.size(), issues.size());
            for (int i = 0; i < matched; i++) {
                baselined.add(issues.get(i));
                kept.add(Entry.of(issues.get(i).finding()));
            }
            stale.addAll(entries.subList(matched, entries.size()));
        }
        return new Match(baselined, kept, stale);
    }
}
