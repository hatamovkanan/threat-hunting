import tomllib
import sys
import re
from pathlib import Path

REQUIRED_FIELDS = ["author", "description", "integration", "uuid", "name", "language", "mitre", "query"]
MITRE_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')

errors = []
toml_files = list(Path(".").rglob("queries/*.toml"))

if not toml_files:
    print("No TOML files found.")
    sys.exit(0)

for path in toml_files:
    print(f"Validating: {path}")
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except Exception as e:
            errors.append(f"{path}: Invalid TOML syntax — {e}")
            continue

    hunt = data.get("hunt", {})

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in hunt:
            errors.append(f"{path}: Missing required field '{field}'")

    # UUID v4 format
    if "uuid" in hunt and not UUID_PATTERN.match(hunt["uuid"]):
        errors.append(f"{path}: 'uuid' is not a valid UUID v4")

    # MITRE technique format
    if "mitre" in hunt:
        for technique in hunt["mitre"]:
            if not MITRE_PATTERN.match(technique):
                errors.append(f"{path}: Invalid MITRE technique '{technique}'")

    # query must not be empty
    if "query" in hunt:
        if not hunt["query"] or all(q.strip() == "" for q in hunt["query"]):
            errors.append(f"{path}: 'query' field is empty")

if errors:
    print("\n❌ Validation failed:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("\n✅ All TOML files are valid.")
