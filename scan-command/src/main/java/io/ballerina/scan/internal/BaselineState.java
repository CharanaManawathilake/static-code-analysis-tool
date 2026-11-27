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
 * Whether an issue is in the baseline, as written to the SARIF {@code baselineState} of a result. The scan writes
 * only these two of the SARIF values: a changed finding gets a new fingerprint, and a baseline entry that matches no
 * finding has no location to report.
 *
 * @since 0.15.0
 */
enum BaselineState {
    NEW("new"),
    UNCHANGED("unchanged");

    private final String value;

    BaselineState(String value) {
        this.value = value;
    }

    String value() {
        return value;
    }
}
