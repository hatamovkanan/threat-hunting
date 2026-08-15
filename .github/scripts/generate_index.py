import tomllib
import yaml
from pathlib import Path


def generate_index_yml(yml_data: dict) -> None:
    with open("index.yml", "w", encoding="utf-8") as f:
        yaml.dump(yml_data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    total = sum(len(v) for v in yml_data.values())
    print(f"✅ index.yml generated ({total} hunts across {len(yml_data)} platforms)")


def generate_index_md(hunts_by_platform: dict) -> None:
    total = sum(len(v) for v in hunts_by_platform.values())

    lines = []
    lines.append("# List of Available Queries")
    lines.append("")
    lines.append(f"Here are the queries currently available ({total} total):")
    lines.append("")

    for platform, hunts in sorted(hunts_by_platform.items()):
        lines.append(f"## {platform}")
        lines.append("")

        for uuid, hunt in sorted(hunts.items(), key=lambda x: x[1]["name"]):
            name = hunt["name"]
            docs_path = hunt["docs_path"]
            languages = ", ".join(hunt.get("language", []))
            lines.append(f"- [{name}]({docs_path}) ({languages})")

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
    yml_data = {}

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

        toml_path_str = f"./{str(path).replace(chr(92), '/')}"
        docs_file = path.stem + ".md"
        docs_path = f"./{platform}/docs/{docs_file}"

        # Full entry for index.md generation
        hunts_by_platform.setdefault(platform, {})[uuid] = {
            "name": hunt.get("name", ""),
            "docs_path": docs_path,
            "language": hunt.get("language", []),
        }

        # Clean entry for index.yml (queries path + mitre only)
        yml_data.setdefault(platform, {})[uuid] = {
            "name": hunt.get("name", ""),
            "path": toml_path_str,
            "mitre": hunt.get("mitre", []),
        }

    generate_index_yml(yml_data)
    generate_index_md(hunts_by_platform)


if __name__ == "__main__":
    main()
