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

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;

import static io.ballerina.scan.internal.ScanToolConstants.BALLERINA_RULE_PREFIX;
import static io.ballerina.scan.internal.ScanToolConstants.FORWARD_SLASH;

/**
 * {@code RuleFactory} contains the logic to create a {@link Rule} with fully qualified identifier.
 *
 * @since 0.1.0
 * */
public class RuleFactory {

    private static final String SARIF_TOOL_HELP_BASE_URI = "https://central.ballerina.io/ballerina/tool_scan/";
    private static final String TOOL_VERSION = resolveToolVersion();

    /**
     * Returns a core static code analysis {@link Rule} instance.
     *
     * @param numericId   numeric identifier of the static code analysis rule
     * @param description description of the static code analysis rule
     * @param ruleKind    {@link RuleKind} of the static code analysis rule
     *
     * @return a core static code analysis rule instance
     */
    static Rule createRule(int numericId, String description, RuleKind ruleKind) {
        return new RuleImpl(BALLERINA_RULE_PREFIX + numericId, numericId, description, ruleKind);
    }

    /**
     * Returns an external static code analysis {@link Rule} instance.
     *
     * @param numericId   numeric identifier of the static code analysis rule
     * @param description description of the static code analysis rule
     * @param ruleKind    {@link RuleKind} of the static code analysis rule
     * @param org         Ballerina package organisation name of the compiler plugin
     * @param name        Ballerina package name of the compiler plugin
     *
     * @return an external static code analysis rule instance
     */
    static Rule createRule(int numericId, String description, RuleKind ruleKind, String org, String name) {
        String reportedSource = org + FORWARD_SLASH + name;
        return new RuleImpl(reportedSource + ":" + numericId, numericId, description,
                ruleKind);
    }

    /**
     * Returns a fully populated core static code analysis {@link Rule} instance, built from the
     * rich rule metadata bundled for built-in Ballerina rules.
     *
     * @param metadata the rich metadata describing the core rule
     * @return a core static code analysis rule instance carrying the full rule metadata
     */
    static Rule createCoreRule(RuleMetadata metadata) {
        String id = BALLERINA_RULE_PREFIX + metadata.numericId();
        String description = metadata.description();
        String helpUri = buildHelpUri(id, description);
        String level = deriveLevel(metadata.ruleKind());
        return new RuleImpl(id, metadata.numericId(), description, metadata.ruleKind(), description,
                metadata.fullDescription(), helpUri, level, true, metadata.tags(), metadata.cwe(), metadata.owasp(),
                metadata.precision(), metadata.securitySeverity());
    }

    /**
     * Constructs the helpUri for a rule based on its rule ID and description. Shared by SARIF
     * generation (for every rule) and core-rule construction, so both formats surface the exact
     * same value.
     *
     * @param ruleId      the rule ID
     * @param description the rule description
     * @return the constructed helpUri
     */
    public static String buildHelpUri(String ruleId, String description) {
        String baseUri = SARIF_TOOL_HELP_BASE_URI + TOOL_VERSION;
        String idPart = ruleId.replace(":", "").replace("/", "");
        String descPart = description.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("-$", "")
                .replaceAll("^-", "");
        return baseUri + "#" + idPart + "---" + descPart;
    }

    /**
     * Resolves the tool's application version the same way {@code Constants} does, kept as a
     * local copy so this internal-package class does not need to depend on the {@code utils}
     * package (which already depends on {@code internal}).
     *
     * @return the resolved application version
     */
    private static String resolveToolVersion() {
        try (InputStream input = RuleFactory.class.getClassLoader().getResourceAsStream("version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                return props.getProperty("app.version", "0.1.0");
            }
        } catch (IOException ex) {
            // ignore: fall back to the system property/default below
        }
        return System.getProperty("app.version", "0.1.0");
    }

    /**
     * Derives the default SARIF reporting level for a {@link RuleKind}.
     *
     * @param ruleKind the rule kind
     * @return the corresponding SARIF level
     */
    static String deriveLevel(RuleKind ruleKind) {
        return switch (ruleKind) {
            case BUG -> "error";
            case CODE_SMELL -> "note";
            case VULNERABILITY -> "warning";
        };
    }

    private RuleFactory() {
    }
}
