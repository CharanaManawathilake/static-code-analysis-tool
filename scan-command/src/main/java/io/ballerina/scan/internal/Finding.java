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

/**
 * The identity of an issue: its fingerprint, and the inputs of the fingerprint that a baseline entry records for
 * review.
 *
 * @param hash        the hash of the rule ID, package, file path and flagged line
 * @param occurrence  the position of the issue among the issues of the file with the same hash, from 1
 * @param ruleId      the ID of the rule
 * @param packageName the organization and name of the package, such as {@code myorg/orders}
 * @param filePath    the path of the file relative to the package root, with {@code /} separators
 * @param snippet     the first flagged line as written, with the content of every literal redacted
 * @since 0.15.0
 */
record Finding(String hash, int occurrence, String ruleId, String packageName, String filePath, String snippet) {

    /**
     * Returns the fingerprint as written to the reports and the baseline: the hash and the occurrence number.
     */
    String fingerprint() {
        return hash + ":" + occurrence;
    }
}
