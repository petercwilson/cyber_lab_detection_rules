# Cyber Lab Detection Rules

[![Lint & Validate](https://github.com/petercwilson/cyber_lab_detection_rules/actions/workflows/lint.yml/badge.svg)](https://github.com/petercwilson/cyber_lab_detection_rules/actions/workflows/lint.yml)

A collection of high-fidelity detection rules built for a cybersecurity lab environment. Each rule targets a specific stage of a simulated malware execution chain and is tuned to minimise false positives.

---

## Quick Start

```bash
# 1. Install validation dependencies
pip install yamllint sigma-cli pySigma-backend-splunk

# 2. (Optional) install pre-commit hooks so checks run automatically before every commit
pip install pre-commit
pre-commit install

# 3. Run all validation checks locally
bash scripts/validate.sh
```

> **CI** runs the same checks automatically on every push and pull request via `.github/workflows/lint.yml`. Pull requests will not be merged if CI fails.

---

## Rule Summary

| # | Rule | Platform | MITRE Technique | File |
|---|------|----------|-----------------|------|
| 1 | Registry Run Key Persistence | **Sigma (Sysmon EID 13)** | T1547.001 | [`sigma/persistence/registry_run_key_persistence.yml`](sigma/persistence/registry_run_key_persistence.yml) |
| 2 | DNS Beaconing to C2 Domain | **Splunk SPL (Sysmon EID 22)** | T1071.004 | [`splunk/dns_c2_beaconing.spl`](splunk/dns_c2_beaconing.spl) |
| 3 | Suspicious Reconnaissance Process Execution | **Kusto / KQL (Sysmon EID 1)** | T1033, T1016 | [`kql/suspicious_recon_process_execution.kql`](kql/suspicious_recon_process_execution.kql) |
| 4 | LSASS Memory Dump | **Sigma (Sysmon EID 10)** | T1003.001 | [`sigma/credential_access/lsass_memory_dump.yml`](sigma/credential_access/lsass_memory_dump.yml) |
| 5 | PowerShell Encoded Command Execution | **Sigma (Sysmon EID 1)** | T1059.001 | [`sigma/execution/powershell_encoded_command.yml`](sigma/execution/powershell_encoded_command.yml) |

---

## Rule Details

### 1 · Registry Run Key Persistence (Sigma)

**File:** `sigma/persistence/registry_run_key_persistence.yml`  
**Log Source:** Windows / Sysmon Event ID 13 (RegistryEvent – Value Set)  
**Technique:** [T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)

Detects any process writing a new value under:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\
```

A filter list of well-known signed applications (OneDrive, Teams, Slack, etc.) suppresses the most common benign sources. Expand the filter for your environment's baseline.

---

### 2 · DNS Beaconing to Suspicious Domain (Splunk SPL)

**File:** `splunk/dns_c2_beaconing.spl`  
**Log Source:** Sysmon Event ID 22 (DNSQuery)  
**Technique:** [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

Three escalating queries are provided:

1. **Wildcard match** – uses `LIKE "%evil-c2-callback.%"` to catch the exact domain and any subdomain prefixes (e.g. `sub.evil-c2-callback.local`) while excluding unrelated strings.  
2. **Aggregated view** – counts queries per host/domain/process combination to show scope across the environment.  
3. **Beacon pattern** – flags the same host querying the domain ≥ 3 times within any 10-minute bucket, indicating automated C2 check-in behaviour.

---

### 3 · Suspicious Reconnaissance Process Execution (KQL)

**File:** `kql/suspicious_recon_process_execution.kql`  
**Log Source:** Sysmon Event ID 1 (Process Creation) ingested into Microsoft Sentinel **or** Microsoft Defender for Endpoint `DeviceProcessEvents` (Option B, commented out)  
**Techniques:** [T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) · [T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)

Correlates the execution of **both** `whoami.exe` and `ipconfig.exe` spawned from the same parent process within a configurable 5-minute window. Requiring both commands to be present dramatically reduces noise compared to alerting on either command in isolation.

---

### 4 · LSASS Memory Dump (Sigma)

**File:** `sigma/credential_access/lsass_memory_dump.yml`  
**Log Source:** Windows / Sysmon Event ID 10 (ProcessAccess)  
**Technique:** [T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

Detects process-access events where a non-system process opens `lsass.exe` with memory-read access rights (e.g. `0x1fffff`, `0x1010`). This is the prerequisite step for credential extraction by tools such as Mimikatz or ProcDump. A filter list of known-legitimate security products reduces false positives; extend it for your EDR baseline.

---

### 5 · PowerShell Encoded Command Execution (Sigma)

**File:** `sigma/execution/powershell_encoded_command.yml`  
**Log Source:** Windows / Sysmon Event ID 1 (Process Creation)  
**Technique:** [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

Detects `powershell.exe` or `pwsh.exe` launched with the `-EncodedCommand` flag (and common aliases `-enc`, `-en`, `-ec`). Encoding is a common obfuscation technique used by droppers, loaders, and post-exploitation frameworks to conceal payload content. A filter list of known-legitimate management processes reduces noise.

---

## Simulated Malware Behaviour

The rules above are designed to detect the following Python-simulated malware actions:

```
1. Registry persistence  →  HKCU\...\Run key write
2. DNS C2 beacon         →  DNS query for evil-c2-callback.local
3. Reconnaissance        →  whoami + ipconfig output saved to a hidden folder
```

---

## Tooling & Conversion

The Sigma rules can be converted to other SIEM query languages using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Install sigma-cli and the Splunk backend
pip install sigma-cli pySigma-backend-splunk

# Convert to Splunk SPL (using the Splunk Windows pipeline for field mapping)
sigma convert -t splunk -p splunk_windows sigma/persistence/registry_run_key_persistence.yml

# Convert all Sigma rules to Splunk SPL at once
find sigma/ -name "*.yml" | xargs sigma convert -t splunk -p splunk_windows

# Convert to KQL (Microsoft Sentinel) — requires pySigma-backend-microsoft365defender
sigma convert -t microsoft365defender sigma/persistence/registry_run_key_persistence.yml

# Convert to Elastic (EQL) — requires pySigma-backend-elasticsearch
sigma convert -t es-eql sigma/persistence/registry_run_key_persistence.yml
```

---

## Feature Roadmap

The following improvements are planned in priority order:

| Priority | Feature | Description |
|----------|---------|-------------|
| 🔴 High | **Rule test harness** | Sample log events (JSON) paired with each Sigma rule + a pytest runner that asserts expected hits/misses against the detection logic. |
| 🔴 High | **Additional Sigma rules** | Expand coverage across the full simulated attack chain: lateral movement (PsExec, WMI), defence evasion (event log clearing, AMSI bypass), and exfiltration. |
| 🟠 Medium | **ATT&CK coverage matrix** | Auto-generate a heatmap of covered techniques using [attack-navigator](https://github.com/mitre-attack/attack-navigator) layer JSON from rule metadata. |
| 🟠 Medium | **Rule catalog page** | GitHub Pages site auto-generated from rule YAML — searchable table with severity, technique, and platform filters. |
| 🟠 Medium | **Multi-backend CI exports** | Extend CI to export each Sigma rule to Splunk, Elastic, and Sentinel formats as build artefacts (uploaded as workflow artefacts). |
| 🟡 Low | **Duplicate ID guard** | CI check that asserts every rule `id` is globally unique across the repo. |
| 🟡 Low | **Semantic versioning** | Adopt SemVer (`v1.2.3`) rather than date-based changelog versions; add a `version` field to rule metadata. |
| 🟡 Low | **Pre-commit sigma-cli hook** | Add a pre-commit hook entry that runs `sigma convert` on changed `.yml` files before every commit. |

