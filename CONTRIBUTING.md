# Contributing to Cyber Lab Detection Rules

Thank you for contributing! Follow the conventions below so every rule stays consistent, reviewable, and automatable.

---

## Table of Contents

1. [Rule ID conventions](#1-rule-id-conventions)
2. [File naming](#2-file-naming)
3. [Required metadata](#3-required-metadata)
4. [MITRE ATT&CK formatting](#4-mitre-attck-formatting)
5. [Sigma-specific requirements](#5-sigma-specific-requirements)
6. [Non-Sigma rules (KQL / SPL)](#6-non-sigma-rules-kql--spl)
7. [Validation](#7-validation)
8. [Pull-request checklist](#8-pull-request-checklist)

---

## 1. Rule ID conventions

| Field | Format | Example |
|-------|--------|---------|
| `id`  | UUID v4 (random) | `a3e7b4c1-2f85-4d62-9e10-7c3a5b8f91d2` |

* Generate a fresh UUID for every **new** rule. Never reuse or recycle an existing ID.
* Do **not** change the `id` of an existing rule when updating it — the ID is an immutable identifier.

---

## 2. File naming

Use **lowercase `snake_case`** for all rule files.  
Include a short but descriptive name that reflects the technique being detected.

```
sigma/<tactic>/<technique_description>.yml    # Sigma rules
kql/<technique_description>.kql              # KQL / Microsoft Sentinel rules
splunk/<technique_description>.spl            # Splunk SPL rules
```

**Examples**

| ✅ Good | ❌ Bad |
|---------|-------|
| `registry_run_key_persistence.yml` | `Persistence_Rule1.yml` |
| `suspicious_recon_process_execution.kql` | `recon.kql` |
| `dns_c2_beaconing.spl` | `DNS-Beaconing Query.spl` |

Tactic sub-directories for Sigma rules must match the lowercase ATT&CK tactic name:
`initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `exfiltration`, `command_and_control`, `impact`.

---

## 3. Required metadata

Every Sigma rule **must** include all of the following fields, in this order:

```yaml
title:          # Human-readable, title-case, ≤ 100 characters
id:             # UUID v4
status:         # experimental | test | stable | deprecated
description:    # One or more sentences; explain WHAT is detected and WHY it matters
references:     # List of URLs (ATT&CK page, vendor docs, blog posts)
author:         # Your name / handle, or "Cyber Lab Detection Rules"
date:           # YYYY-MM-DD (creation date; do not update on edits)
modified:       # YYYY-MM-DD (add/update whenever the rule logic changes; omit on first commit)
tags:           # See Section 4
logsource:      # category + product (and optionally service)
detection:      # selection / filter / condition
fields:         # List of fields shown in alert output (optional but strongly recommended)
falsepositives: # Known benign sources; use ["None identified"] if unknown
level:          # informational | low | medium | high | critical
```

The fields `title`, `id`, `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, and `level` are **required** for all Sigma rules and are enforced by the CI validation script. The `modified` field should be added the first time a rule is updated after its initial commit. The `fields` field is optional but strongly recommended.  
For KQL and SPL files, include an equivalent header comment block with at minimum: rule name, platform, log source, MITRE technique(s), and description.

---

## 4. MITRE ATT&CK formatting

### Tags (Sigma `tags:` field)

Use the **lowercase Sigma tag format** — never full technique names or mixed-case identifiers.

| Category | Format | Example |
|----------|--------|---------|
| Tactic   | `attack.<tactic>` | `attack.persistence` |
| Technique | `attack.t<id>` | `attack.t1547` |
| Sub-technique | `attack.t<id>.<sub>` | `attack.t1547.001` |

**Rules:**

* Always include at least one tactic tag **and** at least one technique tag.
* Do **not** use free-text tags like `attack.registry_run_keys` — use the numeric `attack.tXXXX.XXX` form instead.
* List tags in order: tactic first, then technique(s) ascending by ID.

**Correct example:**

```yaml
tags:
    - attack.persistence
    - attack.t1547.001
```

### References

Link directly to the ATT&CK page for each technique:

```
https://attack.mitre.org/techniques/T1547/001/
```

Use the canonical HTTPS URL; do not abbreviate or redirect.

---

## 5. Sigma-specific requirements

* **`status`** must be one of: `experimental`, `test`, `stable`, `deprecated`.  
  New rules should start as `experimental` or `test`.
* **`level`** must be calibrated to your environment; do not default everything to `high`.
* Filters that reduce false positives should be documented with inline comments explaining *why* each entry is trusted.
* Do not commit rules with placeholder values such as `TODO` or `FIXME` in detection logic.

---

## 6. Non-Sigma rules (KQL / SPL)

Include a structured comment header at the top of every file:

```
// Rule:        <Title>
// Platform:    <SIEM / query language>
// Log Source:  <table(s) or index/sourcetype>
// MITRE ATT&CK: <TID – Technique Name>
// Description: <One-paragraph summary>
```

Use `//` for KQL and `/*` … `*/` or line-by-line comments for SPL where appropriate.

---

## 7. Validation

Before opening a pull request, run the local validation script to catch common issues:

```bash
# Requires: pip install yamllint sigma-cli
bash scripts/validate.sh
```

The CI workflow (`.github/workflows/lint.yml`) runs the same checks automatically on every push and pull request.  
Pull requests will not be merged if the CI checks fail.

---

## 8. Pull-request checklist

- [ ] Rule file follows the naming convention in Section 2
- [ ] All required metadata fields are present and correctly formatted (Section 3)
- [ ] ATT&CK tags use the `attack.tXXXX.XXX` format (Section 4)
- [ ] No placeholder / stub values in detection logic
- [ ] `CHANGELOG.md` updated with a one-line summary under the relevant version / `Unreleased` section
- [ ] CI passes (yamllint + sigma-cli convert check)
