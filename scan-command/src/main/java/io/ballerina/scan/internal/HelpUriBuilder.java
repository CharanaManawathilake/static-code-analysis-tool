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

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;

/**
 * {@code HelpUriBuilder} constructs the helpUri for a rule from its rule ID and human-readable
 * name. Shared by SARIF generation (for every rule, in the {@code utils} package) and core/external
 * rule construction (in {@link RuleFactory}), so both formats surface the exact same value - the
 * reason this single method is public while the rest of rule construction stays package-private.
 *
 * @since 0.1.0
 */
public final class HelpUriBuilder {

    private static final String TOOL_VERSION = resolveToolVersion();

    /**
     * Constructs the helpUri for a rule based on its rule ID and human-readable name.
     *
     * @param ruleId the rule ID
     * @param name   the rule's human-readable name
     * @return the constructed helpUri
     */
    public static String buildHelpUri(String ruleId, String name) {
        String baseUri = ScanToolConstants.SARIF_TOOL_HELP_BASE_URI + TOOL_VERSION;
        String idPart = ruleId.replace(":", "").replace("/", "");
        String namePart = name.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("-$", "")
                .replaceAll("^-", "");
        return baseUri + "#" + idPart + "---" + namePart;
    }

    /**
     * Resolves the tool's application version the same way {@code Constants} does, kept as a
     * local copy so this internal-package class does not need to depend on the {@code utils}
     * package (which already depends on {@code internal}).
     *
     * @return the resolved application version
     */
    private static String resolveToolVersion() {
        try (InputStream input = HelpUriBuilder.class.getClassLoader().getResourceAsStream("version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                return props.getProperty("app.version", "0.1.0");
            }
        } catch (IOException ignored) {
            // Fall through to the default below, mirroring Constants#getAppVersion.
        }
        return System.getProperty("app.version", "0.1.0");
    }

    private HelpUriBuilder() {
    }
}
