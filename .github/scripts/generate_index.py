import tomllib
import yaml
import re
from pathlib import Path
from datetime import datetime, timezone


def generate_index_yml(hunts_by_platform: dict) -> None:
    with open("index.yml", "w", encoding="utf-8") as f:
        yaml.dump(hunts_by_platform, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    total = sum(len(v) for v in hunts_by_platform.values())
    print(f"✅ index.yml generated ({total} hunts across {len(hunts_by_platform)} platforms)")


def generate_index_md(hunts_by_platform: dict) -> None:
    total = sum(len(v) for v in hunts_by_platform.values())

    lines = []
    lines.append("# Threat Hunting Index")
    lines.append("")
    lines.append(f"> Total hunts: **{total}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    for platform, hunts in sorted(hunts_by_platform.items()):
        lines.append(f"## {platform.capitalize()}")
        lines.append("")
        lines.append("| Name | Hunt Type | Language | MITRE |")
        lines.append("|------|-----------|----------|-------|")

        for uuid, hunt in sorted(hunts.items(), key=lambda x: x[1]["name"]):
            name = hunt["name"]
            docs_path = hunt.get("docs_path", hunt["path"].replace("queries/", "docs/").replace(".toml", ".md"))
            hunt_type = hunt.get("hunt_type", "")
            languages = ", ".join(f"`{l}`" for l in hunt.get("language", []))
            mitre = ", ".join(
                f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')})"
                for t in hunt.get("mitre", [])
            )
            lines.append(f"| [{name}]({docs_path}) | {hunt_type} | {languages} | {mitre} |")

        lines.append("")

    with open("index.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"✅ index.md generated")


def main():
    toml_files = sorted(Path(".").rglob("queries/*.toml"))

    if not toml_files:
        print("No TOML files found.")
        return

    hunts_by_platform = {}

    for path in toml_files:
        with open(path, "rb") as f:
            try:
                data = tomllib.load(f)
            except Exception as e:
                print(f"  ⚠️  Skipping {path}: {e}")
                continue

        hunt = data.get("hunt", {})
        uuid = hunt.get("uuid", "")
        if not uuid:
            print(f"  ⚠️  Skipping {path}: missing uuid")
            continue

        # Platform = top-level directory name
        platform = path.parts[0]

        docs_file = path.stem + ".md"
        docs_path = f"./{platform}/docs/{docs_file}"

        entry = {
            "name": hunt.get("name", ""),
            "path": f"./{str(path).replace(chr(92), '/')}",
            "mitre": hunt.get("mitre", []),
        }

        # Include extra fields in index for md generation (not written to yml)
        entry_with_meta = dict(entry)
        entry_with_meta["hunt_type"] = hunt.get("hunt_type", "")
        entry_with_meta["language"] = hunt.get("language", [])
        entry_with_meta["docs_path"] = docs_path

        hunts_by_platform.setdefault(platform, {})[uuid] = entry_with_meta

    # For yml: only name, path, mitre (clean format like the example)
    yml_data = {}
    for platform, hunts in hunts_by_platform.items():
        yml_data[platform] = {}
        for uuid, hunt in hunts.items():
            yml_data[platform][uuid] = {
                "name": hunt["name"],
                "path": hunt["path"],
                "mitre": hunt["mitre"],
            }

    generate_index_yml(yml_data)
    generate_index_md(hunts_by_platform)


if __name__ == "__main__":
    main()
