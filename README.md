# Cyber Lab Detection Rules

A collection of high-fidelity detection rules built for a cybersecurity lab environment. Each rule targets a specific stage of a simulated malware execution chain and is tuned to minimise false positives.

---

## Rule Summary

| # | Rule | Platform | MITRE Technique | File |
|---|------|----------|-----------------|------|
| 1 | Registry Run Key Persistence | **Sigma (Sysmon EID 13)** | T1547.001 | [`sigma/persistence/registry_run_key_persistence.yml`](sigma/persistence/registry_run_key_persistence.yml) |
| 2 | DNS Beaconing to C2 Domain | **Splunk SPL (Sysmon EID 22)** | T1071.004 | [`splunk/dns_c2_beaconing.spl`](splunk/dns_c2_beaconing.spl) |
| 3 | Suspicious Reconnaissance Process Execution | **Kusto / KQL (Sysmon EID 1)** | T1033, T1016 | [`kql/suspicious_recon_process_execution.kql`](kql/suspicious_recon_process_execution.kql) |

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

## Simulated Malware Behaviour

The rules above are designed to detect the following Python-simulated malware actions:

```
1. Registry persistence  →  HKCU\...\Run key write
2. DNS C2 beacon         →  DNS query for evil-c2-callback.local
3. Reconnaissance        →  whoami + ipconfig output saved to a hidden folder
```

---

## Tooling & Conversion

The Sigma rule can be converted to other SIEM query languages using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Convert to Splunk SPL
sigma convert -t splunk sigma/persistence/registry_run_key_persistence.yml

# Convert to KQL (Microsoft Sentinel)
sigma convert -t microsoft365defender sigma/persistence/registry_run_key_persistence.yml

# Convert to Elastic (EQL)
sigma convert -t es-eql sigma/persistence/registry_run_key_persistence.yml
```
