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

import org.testng.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Asserts a table of cases in one test, listing every failing case instead of stopping at the first.
 *
 * @since 0.14.0
 */
final class CaseTables {
    private CaseTables() {
    }

    /**
     * Asserts each {input, expected} row of the table.
     */
    static void assertCases(Object[][] cases, Function<String, Object> actual) {
        List<String> mismatches = new ArrayList<>();
        for (Object[] testCase : cases) {
            check((String) testCase[0], testCase[1], actual, mismatches);
        }
        assertNoMismatches(mismatches);
    }

    /**
     * Asserts every input of the table gives the same expected value.
     */
    static void assertCases(Object[][] inputs, Function<String, Object> actual, Object expected) {
        List<String> mismatches = new ArrayList<>();
        for (Object[] input : inputs) {
            check((String) input[0], expected, actual, mismatches);
        }
        assertNoMismatches(mismatches);
    }

    private static void check(String input, Object expected, Function<String, Object> actual,
                              List<String> mismatches) {
        Object result = actual.apply(input);
        if (!Objects.equals(result, expected)) {
            mismatches.add("'" + input + "': expected " + expected + " but was " + result);
        }
    }

    private static void assertNoMismatches(List<String> mismatches) {
        Assert.assertTrue(mismatches.isEmpty(),
                mismatches.size() + " failing cases:\n" + String.join("\n", mismatches) + "\n");
    }
}
