# Mechanical Security Assessment — tableau-mcp

_Tier-1 policy scan · Internal use · System of record for open CRITICAL/HIGH/MEDIUM: `llm-wiki/wiki/security-findings/{fingerprint}.md`_

## Executive summary

**6** active finding(s) for **tableau-mcp** (CRITICAL=0 · HIGH=2 · MEDIUM=0 · LOW=1 · INFORMATIONAL=3).
**2** blocking (CRITICAL/HIGH) — require remediation or an explicit waiver before treating the repo as clear.

Highest-severity open items are listed first in Detailed findings.

## Scope

- **Target:** C:\Users\abatten\Code\tableau-mcp
- **Scanned at:** 2026-10-27T17:56:30.776Z
- **Suite:** llm-wiki mechanical security (Tier 1)
- **Checks executed:** supply-chain-lockfile, supply-chain-min-release-age, supply-chain-lifecycle-exfil, supply-chain-script-shell-risk, supply-chain-python, cicd-actions-pinning, cicd-script-injection, cicd-secret-artifact-exfil, cicd-suspicious-security-workflow, cicd-pull-request-target, cicd-workflow-permissions, agent-autonomy-guardrails, agent-browser-guardrails, agent-confluence-guardrails, agent-drive-guardrails, agent-mcp-supply-chain, mcp-config-snapshot, user-global-mcp-snapshot, repo-secrets-hygiene, repo-blob-hygiene, capability-reversibility, dep-vuln-osv, code-injection-sast, untrusted-content-to-exec, secret-history-scan, electron-hardening
- **Classification:** Internal — MarTech engineering security

## Methodology

Tier-1 **mechanical** policy checks (deterministic, offline, no LLM). Aligned with UNIVERSAL_SECURITY_PLAYBOOK.md domains and finding schema (severity, OWASP category, attack vector, affected components, mitigation, risk assessment, recommendation, effort). Does **not** replace Tier-2 LLM static audit, Tier-3 PR diff review, or Tier-4 runtime red-team. Shai-Hulud-style deleted workflow runs and laptop egress are out of scope for this suite.

## Severity distribution

| Severity | Active count |
|----------|--------------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 0 |
| LOW | 1 |
| INFORMATIONAL | 3 |
| _Waived (excluded)_ | 0 |

## Findings index

| ID | Title | Severity | OWASP | Domain | Waived |
|----|-------|----------|-------|--------|--------|
| MECH-DEP-VULN-OSV-003 | GHSA-86w9-cpqp-85rv in node-forge@1.4.0 | HIGH | A06:2021 Vulnerable and Outdated Components | 8 | no |
| MECH-DEP-VULN-OSV-004 | GHSA-mrhx-c7xc-m3w5 in zod@3.25.76 | HIGH | A06:2021 Vulnerable and Outdated Components | 8 | no |
| MECH-REPO-BLOB-HYGIENE-002 | Large tracked blob (>10.0MB): tests/e2e/fixtures/workbooks/forecast.twbx | LOW | A06:2025 Insecure Design | 8 | no |
| MECH-CODE-INJECTION-SAST-005 | semgrep is not installed — code-injection-sast did not run | INFORMATIONAL | A03:2021 Injection | 3 | no |
| MECH-MCP-CONFIG-SNAPSHOT-001 | No MCP configuration files found to baseline | INFORMATIONAL | MCP04 Shadow MCP Servers | 1 | no |
| MECH-SECRET-HISTORY-SCAN-006 | gitleaks is not installed — secret-history-scan did not run | INFORMATIONAL | A02:2021 Cryptographic Failures | 4 | no |

## Detailed findings

### MECH-DEP-VULN-OSV-003: GHSA-86w9-cpqp-85rv in node-forge@1.4.0

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **HIGH** |
| OWASP | A06:2021 Vulnerable and Outdated Components |
| Playbook domain | 8 |
| Check | `dep-vuln-osv` |
| Fingerprint | `2e42a9184c76eb45` |
| Effort | M |

**Attack vector**

node-forge RSA PKCS#1 v1.5 signature verification accepts extra nested DigestAlgorithm elements

**Affected components**

C:/Users/abatten/Code/tableau-mcp/package-lock.json :: node-forge@1.4.0 :: GHSA-86w9-cpqp-85rv

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Supply-chain CVE in a committed lockfile; exploitability depends on whether the package is reachable at runtime.

**Recommendation**

Upgrade or replace the package to a non-vulnerable release. If no patch exists, pin a patched fork or isolate the dependency and record a dated waiver.

### MECH-DEP-VULN-OSV-004: GHSA-mrhx-c7xc-m3w5 in zod@3.25.76

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **HIGH** |
| OWASP | A06:2021 Vulnerable and Outdated Components |
| Playbook domain | 8 |
| Check | `dep-vuln-osv` |
| Fingerprint | `7322bd42b77aea61` |
| Effort | M |

**Attack vector**

Zod can exhaust memory while validating oversized constrained collections

**Affected components**

C:/Users/abatten/Code/tableau-mcp/package-lock.json :: zod@3.25.76 :: GHSA-mrhx-c7xc-m3w5

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Supply-chain CVE in a committed lockfile; exploitability depends on whether the package is reachable at runtime.

**Recommendation**

Upgrade or replace the package to a non-vulnerable release. If no patch exists, pin a patched fork or isolate the dependency and record a dated waiver.

### MECH-REPO-BLOB-HYGIENE-002: Large tracked blob (>10.0MB): tests/e2e/fixtures/workbooks/forecast.twbx

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **LOW** |
| OWASP | A06:2025 Insecure Design |
| Playbook domain | 8 |
| Check | `repo-blob-hygiene` |
| Fingerprint | `79065e651cd6b746` |
| Effort | S |

**Attack vector**

Accumulating multi-MB assets slowly grows clone size.

**Affected components**

tests/e2e/fixtures/workbooks/forecast.twbx (20.3MB)

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Low — audit only; leave in place unless actively painful.

**Recommendation**

Prefer links or compressed previews for new assets. Do not rewrite history for these alone.

### MECH-CODE-INJECTION-SAST-005: semgrep is not installed — code-injection-sast did not run

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **INFORMATIONAL** |
| OWASP | A03:2021 Injection |
| Playbook domain | 3 |
| Check | `code-injection-sast` |
| Fingerprint | `c142084c45ed9c30` |
| Effort | S |

**Attack vector**

The semgrep adapter never executed, so known code-injection-sast classes are currently untested on this tree.

**Affected components**

semgrep

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Informational locally; install the tool or run in CI where adapters are provisioned.

**Recommendation**

Install semgrep on the PATH (CI workflow already attempts this) and re-run the scan.

### MECH-MCP-CONFIG-SNAPSHOT-001: No MCP configuration files found to baseline

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **INFORMATIONAL** |
| OWASP | MCP04 Shadow MCP Servers |
| Playbook domain | 1 |
| Check | `mcp-config-snapshot` |
| Fingerprint | `72be11bfc7543667` |
| Effort | S |

**Attack vector**

N/A — no MCP config detected in standard paths.

**Affected components**

.cursor/mcp.json, .claude/mcp.json, .mcp.json, mcp.json

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Informational — enable baseline once MCP servers are configured.

**Recommendation**

When MCP servers are added, run `npm run security:baseline -- --repo <path>` to record a baseline and diff it on every scan.

### MECH-SECRET-HISTORY-SCAN-006: gitleaks is not installed — secret-history-scan did not run

| Field | Value |
|-------|-------|
| Project | Code/tableau-mcp |
| Severity | **INFORMATIONAL** |
| OWASP | A02:2021 Cryptographic Failures |
| Playbook domain | 4 |
| Check | `secret-history-scan` |
| Fingerprint | `1cefe7e102c6f6ae` |
| Effort | S |

**Attack vector**

The gitleaks adapter never executed, so known secret-history-scan classes are currently untested on this tree.

**Affected components**

gitleaks

**Current mitigation**

None identified by mechanical check.

**Risk assessment**

Informational locally; install the tool or run in CI where adapters are provisioned.

**Recommendation**

Install gitleaks on the PATH (CI workflow already attempts this) and re-run the scan.

## Residual risk & limitations

- Mechanical checks can miss logic bugs, authz flaws, and runtime-only issues.
- Waived findings remain residual risk until expiry or removal of the waiver.
- Registry lifecycle (first detected, reopen episodes, resolution notes) is tracked in llm-wiki, not in this point-in-time report.

## Next actions

- Triage CRITICAL/HIGH/MEDIUM via Today → Security / `/cos-security-findings`; remediate or waive with reason + expiry.
- Prefer fix or explicit waiver over dismiss. Record resolution notes on close.
