# Severity Levels

RedKite classifies every vulnerability finding into one of six severity levels, ordered lowest to highest:

| Level | Meaning |
|---|---|
| **None** | No vulnerability, or a finding that carries no severity information at all. |
| **Unknown** | A severity string RedKite couldn't map to one of the levels below (data quality issue upstream, not a real "no severity" case). |
| **Low** | CVSS score under 4.0. |
| **Medium** | CVSS score 4.0 up to 7.0. |
| **High** | CVSS score 7.0 up to 9.0. |
| **Critical** | CVSS score 9.0 or above. |

When an advisory reports a severity as a label (e.g. GitHub Security Advisories' own `LOW`/`MODERATE`/`HIGH`/`CRITICAL`) rather than a raw CVSS score, RedKite maps the label directly — `MODERATE` and `MEDIUM` both map to **Medium**.

## Where this ordering matters

A component can be affected by more than one advisory, and a dependency's card in the remediation view rolls its own findings — and, for a direct dependency, its transitive children's findings too — up into a single worst-case severity using this ordering: **Critical** always wins over **High**, which always wins over **Medium**, and so on. This is what drives the "N Critical / N High / ..." breakdown shown on a dependency card when its children carry vulnerabilities of their own — see [Child Dependency Vulnerabilities](../analysis/transitive-dependencies.md#child-dependency-vulnerabilities).
