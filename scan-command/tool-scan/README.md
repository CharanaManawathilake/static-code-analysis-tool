# Ballerina Scan Tool

## Overview

Static Code Analysis (SCA) uses tools to examine code without executing it. It is used for identifying potential issues like bugs, vulnerabilities, and code smells early, improving software quality, maintainability, and security. Ballerina supports SCA using the Ballerina scan tool.

The scan tool compiles and performs static code analysis, prints results to the console, and reports results. It analyzes the source code defined in each module when compiling a package, or analyzes the given source file when compiling a single Ballerina file.

> **Note**: Analyzing individual Ballerina files of a package is not allowed.

Each issue reported by the tool is backed by a **rule**. Every rule has a `severity` (`BLOCKER`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`) that indicates how important it is to act on it, and where applicable, is mapped to its relevant CWE and OWASP Top 10 coverage. See [Severity levels](#severity-levels) and [Rules](#rules) below for details.

## Commands

### `bal scan`

**Synopsis:**

```bash
bal scan [OPTIONS] [<package>|<source-file>]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--target-dir=<path>` | Target directory path for saving analysis reports (only for Ballerina projects). |
| `--scan-report` | Generate an HTML report containing the analysis results (only for Ballerina projects). |
| `--format=<json\|sarif>` | Specify the format of the report. Default is `json`. |
| `--list-rules` | List all available rules, along with their kind and severity. |
| `--include-rules=<rule1, ...>` | Run analysis for a specific set of rules. |
| `--exclude-rules=<rule1, ...>` | Exclude analysis for a specific set of rules. |
| `--platforms=<platformName1, ...>` | Define platform(s) to report results to. More than one platform can be defined. |

## Examples

```bash
# Run analysis against all Ballerina documents in the current package, print results to the
# console, and save results in JSON file format in the target directory.
bal scan

# Run analysis against a standalone Ballerina file and print results to the console. The
# file path of the Ballerina file can be relative or absolute.
bal scan main.bal

# Run analysis and save analysis results in a specified directory.
bal scan --target-dir="results"

# Run analysis and generate an HTML report in the target directory.
bal scan --scan-report

# Run analysis and generate a report in JSON format (default).
bal scan --format=json

# Run analysis and generate a report in SARIF format.
bal scan --format=sarif

# View all available rules.
bal scan --list-rules

# Run analysis for a specific rule.
bal scan --include-rules="ballerina:101"

# Run analysis for a specific set of rules.
bal scan --include-rules="ballerina:101, ballerina/io:101"

# Exclude analysis for a specific rule.
bal scan --exclude-rules="ballerina/io:101"

# Exclude analysis for a specific set of rules.
bal scan --exclude-rules="ballerina:101, ballerina/io:101"

# Run analysis and report to sonarqube.
bal scan --platforms=sonarqube

# Run analysis and report to multiple platforms.
bal scan --platforms="sonarqube, semgrep, codeql"
```

### Example output

Running `bal scan --list-rules` prints a table of every available rule with its kind and severity:

```
RuleID       | Rule Kind    | Rule Description
-------------|--------------|----------------------------------------------
ballerina:1  | CODE_SMELL   | Avoid checkpanic
ballerina:2  | CODE_SMELL   | Unused function parameter
...
ballerina:13 | VULNERABILITY| Hard-coded secrets are security-sensitive
ballerina:14 | VULNERABILITY| Non configurable secrets are security-sensitive
...
```

Running `bal scan` reports each finding as a JSON issue with its location and full rule metadata, including the rule's `severity`:

```json
[
  {
    "location": {
      "filePath": "main.bal",
      "startLine": 20,
      "endLine": 20,
      "startColumn": 17,
      "endColumn": 39,
      "snippet": "checkpanic getResult()"
    },
    "rule": {
      "id": "ballerina:1",
      "name": "Avoid checkpanic",
      "description": "Using `checkpanic` lets an unhandled error panic and crash the program instead of being handled.",
      "helpUri": "https://ballerina.io/learn/scan-rules/#avoid-checkpanic",
      "severity": "LOW",
      "ruleKind": "CODE_SMELL"
    },
    "source": "BUILT_IN",
    "fileName": "main.bal"
  }
]
```

## Rules

The full list of rules, with detailed explanations and noncompliant/compliant code examples, is documented at [ballerina.io/learn/scan-rules](https://ballerina.io/learn/scan-rules/).

### Severity levels

The `severity` of a rule indicates how urgently a reported issue should be addressed, and how it can affect development and deployment if left unresolved:

| Severity | Meaning | Impact |
|----------|---------|--------|
| `BLOCKER` | A critical issue that is very likely to cause application failure or a security breach. | Should block merging or deployment until fixed. |
| `HIGH` | A serious issue likely to cause incorrect behavior or expose the application to exploitation. | Should be fixed before deployment. |
| `MEDIUM` | An issue that affects reliability, maintainability, or security to a moderate degree. | Should be scheduled and fixed soon, does not need to block deployment on its own. |
| `LOW` | A minor issue such as a code smell that affects readability or maintainability. | Safe to defer, but worth cleaning up over time. |
| `INFO` | An informational finding with no material severity. | Does not require action; useful for awareness. |

### Core rules

The language-level rules below are defined within this tool.

| Rule ID | Name | Kind | Severity | Description |
|---------|------|------|----------|-------------|
| `ballerina:1` | [Avoid checkpanic](https://ballerina.io/learn/scan-rules/#avoid-checkpanic) | Code Smell | Low | Using `checkpanic` lets an unhandled error panic and crash the program instead of being handled. |
| `ballerina:2` | [Unused function parameter](https://ballerina.io/learn/scan-rules/#unused-function-parameter) | Code Smell | Low | A function parameter is declared but never used within the function body. |
| `ballerina:3` | [Non isolated public function](https://ballerina.io/learn/scan-rules/#non-isolated-public-function) | Code Smell | Low | A public function is not marked `isolated`, so it cannot be safely called from concurrently executing code. |
| `ballerina:4` | [Non isolated public method](https://ballerina.io/learn/scan-rules/#non-isolated-public-method) | Code Smell | Low | A public method is not marked `isolated`, so it cannot be safely called from concurrently executing code. |
| `ballerina:5` | [Non isolated public class](https://ballerina.io/learn/scan-rules/#non-isolated-public-class) | Code Smell | Low | A public class is not marked isolated, so its instances cannot be safely shared across concurrently executing code. |
| `ballerina:6` | [Non isolated public object](https://ballerina.io/learn/scan-rules/#non-isolated-public-object) | Code Smell | Low | A public object is not marked isolated, so its instances cannot be safely shared across concurrently executing code. |
| `ballerina:7` | [This operation always evaluates to true](https://ballerina.io/learn/scan-rules/#this-operation-always-evaluates-to-true) | Code Smell | Low | An operation always evaluates to `true` regardless of its operands' runtime values. |
| `ballerina:8` | [This operation always evaluates to false](https://ballerina.io/learn/scan-rules/#this-operation-always-evaluates-to-false) | Code Smell | Low | An operation always evaluates to `false` regardless of its operands' runtime values. |
| `ballerina:9` | [This operation always evaluates to the same value](https://ballerina.io/learn/scan-rules/#this-operation-always-evaluates-to-the-same-value) | Code Smell | Low | An operation always reduces to one of its own operands, making the operation itself redundant. |
| `ballerina:10` | [This variable is assigned to itself](https://ballerina.io/learn/scan-rules/#this-variable-is-assigned-to-itself) | Code Smell | Low | A variable is assigned to itself, which has no effect and usually signals a mistake. |
| `ballerina:11` | [Unused class private fields](https://ballerina.io/learn/scan-rules/#unused-class-private-fields) | Code Smell | Low | A private class field is declared but never used. |
| `ballerina:12` | [Invalid range expression](https://ballerina.io/learn/scan-rules/#invalid-range-expression) | Code Smell | Low | A range expression's bounds never produce any elements, making it dead code. |
| `ballerina:13` | [Hard-coded secrets are security-sensitive](https://ballerina.io/learn/scan-rules/#hard-coded-secrets-are-security-sensitive) | Vulnerability | High | A secret such as a password, API key, or token is embedded as a literal value in source code. |
| `ballerina:14` | [Non configurable secrets are security-sensitive](https://ballerina.io/learn/scan-rules/#non-configurable-secrets-are-security-sensitive) | Vulnerability | Medium | A secret is assigned a fixed value instead of being exposed as a configurable one. |

### Library tools

Rules for other Ballerina libraries (`ballerina/file`, `ballerina/http`, `ballerina/io`, `ballerina/log`, `ballerina/os`, etc.) are specified separately by each library's own compiler plugin and are reported alongside the core rules when that library is used in the project being scanned. Refer to [ballerina.io/learn/scan-rules](https://ballerina.io/learn/scan-rules/) for the full list of rules contributed by each library tool.

> **Note**: Run `bal scan --list-rules` inside a Ballerina project to see the complete set of rules available to it, including any additional rules contributed by library tools or static code analysis platforms.
