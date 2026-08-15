import tomllib
import yaml
import re
from pathlib import Path
from datetime import datetime, timezone


def slugify(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')


def load_all_hunts() -> list[dict]:
    hunts = []
    toml_files = sorted(Path(".").rglob("queries/*.toml"))

    for path in toml_files:
        with open(path, "rb") as f:
            try:
                data = tomllib.load(f)
            except Exception as e:
                print(f"  ⚠️  Skipping {path}: {e}")
                continue

        hunt = data.get("hunt", {})

        # Determine platform from path (linux, windows, network)
        parts = path.parts
        platform = parts[0] if len(parts) > 0 else "unknown"

        # Relative docs path
        docs_file = path.stem + ".md"
        docs_path = str(path.parent.parent / "docs" / docs_file)

        hunts.append({
            "uuid": hunt.get("uuid", ""),
            "name": hunt.get("name", ""),
            "author": hunt.get("author", ""),
            "platform": platform,
            "hunt_type": hunt.get("hunt_type", ""),
            "language": hunt.get("language", []),
            "integration": hunt.get("integration", []),
            "mitre": hunt.get("mitre", []),
            "toml_path": str(path),
            "docs_path": docs_path,
        })

    return hunts


def generate_index_yml(hunts: list[dict]) -> None:
    index = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(hunts),
        "hunts": hunts,
    }

    with open("index.yml", "w", encoding="utf-8") as f:
        yaml.dump(index, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    print(f"✅ index.yml generated ({len(hunts)} hunts)")


def generate_index_md(hunts: list[dict]) -> None:
    lines = []
    lines.append("# Threat Hunting Index")
    lines.append("")
    lines.append(f"> Total hunts: **{len(hunts)}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Group by platform
    platforms = {}
    for hunt in hunts:
        p = hunt["platform"]
        platforms.setdefault(p, []).append(hunt)

    for platform, platform_hunts in sorted(platforms.items()):
        lines.append(f"## {platform.capitalize()}")
        lines.append("")
        lines.append("| Name | Hunt Type | Language | MITRE |")
        lines.append("|------|-----------|----------|-------|")

        for hunt in sorted(platform_hunts, key=lambda h: h["name"]):
            name = hunt["name"]
            docs_path = hunt["docs_path"]
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
    hunts = load_all_hunts()

    if not hunts:
        print("No hunt TOML files found.")
        return

    generate_index_yml(hunts)
    generate_index_md(hunts)


if __name__ == "__main__":
    main()
