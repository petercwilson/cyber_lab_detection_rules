# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versions correspond to the date of the change set using `YYYY-MM-DD` as the version label.

---

## [Unreleased]

### Added
- `sigma/credential_access/lsass_memory_dump.yml` – Sigma rule detecting LSASS memory access by credential-theft tools via Sysmon EID 10 (T1003.001).
- `sigma/execution/powershell_encoded_command.yml` – Sigma rule detecting PowerShell launched with `-EncodedCommand` (and aliases) via Sysmon EID 1 (T1059.001).
- `.gitignore` – excludes Python artefacts, virtual environments, editor directories, and OS files from version control.
- `.pre-commit-config.yaml` – pre-commit hooks for trailing whitespace, end-of-file fixer, merge-conflict detection, and yamllint, mirroring the CI pipeline.
- `CONTRIBUTING.md` with naming conventions, rule-ID format, required metadata fields, and ATT&CK tag guidelines.
- `.github/workflows/lint.yml` – CI lint/validation pipeline (yamllint + sigma-cli convert check) that runs on every push and pull request.
- `scripts/validate.sh` – local validation script mirroring the CI checks.
- `CHANGELOG.md` (this file).

### Changed
- `README.md`: added CI status badge, Quick Start section, details for two new rules, updated Tooling & Conversion section with correct `pySigma-backend-splunk` install step, and new Feature Roadmap table.
- `.github/workflows/lint.yml`: added `pySigma-backend-splunk` to pip install; added `--without-pipeline` flag to `sigma convert` so the parse/convert check works without requiring a named pipeline; switched metadata check to `python3`; added UUID v4 format validation for the `id` field.
- `scripts/validate.sh`: same fixes as `lint.yml` — `pySigma-backend-splunk`, `--without-pipeline`, `python3`, and UUID v4 validation.
- Sigma rule tag `attack.registry_run_keys` replaced with the standard numeric tag `attack.t1547.001` in `sigma/persistence/registry_run_key_persistence.yml`.
- Added missing `modified` field to `sigma/persistence/registry_run_key_persistence.yml`.
- Standardized rule title in README to "Suspicious Reconnaissance Process Execution" (was inconsistently "Reconnaissance Process Execution" in the rule summary table).

---

## [2026-04-14]

### Added
- `sigma/persistence/registry_run_key_persistence.yml` – Sigma rule detecting HKCU Run key writes via Sysmon EID 13 (T1547.001).
- `splunk/dns_c2_beaconing.spl` – Splunk SPL queries detecting DNS beaconing to a suspicious domain via Sysmon EID 22 (T1071.004, T1568).
- `kql/suspicious_recon_process_execution.kql` – KQL rule correlating `whoami.exe` + `ipconfig.exe` execution from the same parent process (T1033, T1016).
- `README.md` – Rule summary table and usage documentation.
