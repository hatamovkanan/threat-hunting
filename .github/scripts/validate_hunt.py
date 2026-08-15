import tomllib
import yaml
import sys
import re
from pathlib import Path

REQUIRED_FIELDS = ["author", "description", "integration", "uuid", "name", "language", "mitre", "query", "hunt_type"]
MITRE_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
URL_PATTERN = re.compile(r'^https?://.+')
VALID_HUNT_TYPES = {"Hypothesis-Driven", "Analytics-Driven", "Intel-Driven"}
VALID_LANGUAGES = {"ES|QL", "EQL", "KQL", "AQL", "SPL", "XQL", "CQL", "SQL"}


def load_existing_uuids() -> dict:
    """Load all existing UUIDs from index.yml. Returns {uuid: toml_path}."""
    index_path = Path("index.yml")
    if not index_path.exists():
        return {}

    with open(index_path, "r", encoding="utf-8") as f:
        try:
            index = yaml.safe_load(f)
        except Exception:
            return {}

    existing = {}
    if isinstance(index, dict):
        for platform, hunts in index.items():
            if isinstance(hunts, dict):
                for uuid, hunt in hunts.items():
                    existing[str(uuid)] = hunt.get("path", "unknown")
    return existing


errors = []
toml_files = list(Path(".").rglob("queries/*.toml"))

if not toml_files:
    print("No TOML files found.")
    sys.exit(0)

# Load existing UUIDs from index.yml for duplicate check
existing_uuids = load_existing_uuids()

# Track UUIDs within the current PR to catch duplicates between new files
seen_uuids = {}

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

    # UUID v4 format + duplicate check
    if "uuid" in hunt:
        uuid = hunt["uuid"]

        if not UUID_PATTERN.match(uuid):
            errors.append(f"{path}: 'uuid' is not a valid UUID v4")
        else:
            toml_path_str = str(path).replace("\\", "/")

            # Check duplicate against index.yml
            if uuid in existing_uuids:
                existing_path = existing_uuids[uuid]
                # Allow if it's the same file (tuning an existing hunt)
                if existing_path.lstrip("./") != toml_path_str.lstrip("./"):
                    errors.append(
                        f"{path}: Duplicate UUID '{uuid}' — already exists in index.yml at '{existing_path}'"
                    )

            # Check duplicate within this PR
            if uuid in seen_uuids:
                errors.append(
                    f"{path}: Duplicate UUID '{uuid}' — also found in '{seen_uuids[uuid]}' within this PR"
                )
            else:
                seen_uuids[uuid] = str(path)

    # MITRE technique format
    if "mitre" in hunt:
        for technique in hunt["mitre"]:
            if not MITRE_PATTERN.match(technique):
                errors.append(f"{path}: Invalid MITRE technique '{technique}'")

    # query must not be empty
    if "query" in hunt:
        if not hunt["query"] or all(q.strip() == "" for q in hunt["query"]):
            errors.append(f"{path}: 'query' field is empty")

    # hunt_type must be one of the valid values
    if "hunt_type" in hunt:
        if hunt["hunt_type"] not in VALID_HUNT_TYPES:
            errors.append(f"{path}: Invalid 'hunt_type' value '{hunt['hunt_type']}' — must be one of: {', '.join(sorted(VALID_HUNT_TYPES))}")

    # language must be valid values
    if "language" in hunt:
        if not isinstance(hunt["language"], list):
            errors.append(f"{path}: 'language' must be an array")
        else:
            for lang in hunt["language"]:
                if lang not in VALID_LANGUAGES:
                    errors.append(f"{path}: Invalid 'language' value '{lang}' — must be one of: {', '.join(sorted(VALID_LANGUAGES))}")

    # references must be valid URLs (optional field)
    if "references" in hunt:
        if not isinstance(hunt["references"], list):
            errors.append(f"{path}: 'references' must be an array")
        else:
            for ref in hunt["references"]:
                if not URL_PATTERN.match(ref):
                    errors.append(f"{path}: Invalid reference URL '{ref}' — must start with http:// or https://")

if errors:
    print("\n❌ Validation failed:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("\n✅ All TOML files are valid.")
