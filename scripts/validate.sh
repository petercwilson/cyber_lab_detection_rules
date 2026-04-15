#!/usr/bin/env bash
# validate.sh – local mirror of the CI lint/validation pipeline.
# Usage: bash scripts/validate.sh
# Requirements: pip install yamllint sigma-cli pySigma-backend-splunk

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Step 1: yamllint ==="
yamllint -c .yamllint.yml sigma/
echo "yamllint passed."

echo ""
echo "=== Step 2: sigma-cli convert (Splunk backend) ==="
find sigma/ -name "*.yml" | while read -r rule; do
    echo "  Checking: $rule"
    sigma convert -t splunk --without-pipeline "$rule" > /dev/null
done
echo "sigma-cli convert passed."

echo ""
echo "=== Step 3: Sigma metadata field check ==="
python3 - <<'EOF'
import sys, glob, re
import yaml

REQUIRED_FIELDS = [
    "title", "id", "status", "description",
    "references", "author", "date", "tags",
    "logsource", "detection", "falsepositives", "level",
]

VALID_STATUSES = {"experimental", "test", "stable", "deprecated"}
VALID_LEVELS   = {"informational", "low", "medium", "high", "critical"}
UUID_RE        = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

errors = []

for path in glob.glob("sigma/**/*.yml", recursive=True):
    with open(path) as fh:
        try:
            rule = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            errors.append(f"{path}: YAML parse error – {exc}")
            continue

    if not isinstance(rule, dict):
        errors.append(f"{path}: root document is not a mapping")
        continue

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"{path}: missing required field '{field}'")

    rule_id = rule.get("id")
    if rule_id and not UUID_RE.match(str(rule_id)):
        errors.append(
            f"{path}: 'id' field '{rule_id}' is not a valid UUID v4"
        )

    status = rule.get("status")
    if status and status not in VALID_STATUSES:
        errors.append(
            f"{path}: invalid status '{status}' "
            f"(must be one of: {', '.join(sorted(VALID_STATUSES))})"
        )

    level = rule.get("level")
    if level and level not in VALID_LEVELS:
        errors.append(
            f"{path}: invalid level '{level}' "
            f"(must be one of: {', '.join(sorted(VALID_LEVELS))})"
        )

    tags = rule.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if tag.startswith("attack.") and not (
                tag.replace("attack.", "").replace("_", "").isalpha()
                or tag[len("attack."):].lower().startswith("t")
            ):
                errors.append(
                    f"{path}: non-standard ATT&CK tag '{tag}' – "
                    "use 'attack.tXXXX' or 'attack.<tactic>' format"
                )

if errors:
    print("\nMetadata validation FAILED:\n")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)
else:
    print("Metadata validation passed.")
EOF

echo ""
echo "All checks passed."
