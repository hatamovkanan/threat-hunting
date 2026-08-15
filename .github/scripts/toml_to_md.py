import tomllib
import sys
import re
from pathlib import Path


def slugify(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')


def mitre_link(technique: str) -> str:
    parts = technique.split('.')
    base = parts[0]
    if len(parts) == 2:
        url = f"https://attack.mitre.org/techniques/{base}/{parts[1]}"
    else:
        url = f"https://attack.mitre.org/techniques/{base}"
    return f"- [{technique}]({url})"


def integration_link(integration: str) -> str:
    return f"[{integration}](https://docs.elastic.co/integrations/{integration})"


def generate_md(toml_path: Path) -> str:
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)

    hunt = data["hunt"]

    name = hunt["name"]
    author = hunt["author"]
    description = hunt.get("description", "").strip()
    uuid = hunt["uuid"]
    integrations = hunt.get("integration", [])
    languages = hunt.get("language", [])
    hunt_type = hunt.get("hunt_type", "")
    notes = hunt.get("notes", [])
    mitre = hunt.get("mitre", [])
    queries = hunt.get("query", [])
    references = hunt.get("references", [])

    # Docs path relative to queries file
    toml_filename = toml_path.name
    source_link = f"[{name}](../queries/{toml_filename})"

    integration_str = ", ".join(integration_link(i) for i in integrations)
    language_str = "`" + "`, `".join(languages) + "`"

    lines = []

    # Title
    lines.append(f"# {name}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Metadata
    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- **Author:** {author}")
    lines.append(f"- **Description:** {description}")
    lines.append("")
    lines.append(f"- **UUID:** `{uuid}`")
    lines.append(f"- **Integration:** {integration_str}")
    lines.append(f"- **Language:** `[{', '.join(languages)}]`")
    lines.append(f"- **Hunt Type:** {hunt_type}")
    lines.append(f"- **Source File:** {source_link}")
    lines.append("")

    # Queries
    lines.append("## Query")
    lines.append("")
    for query in queries:
        lines.append("```sql")
        lines.append(query.strip())
        lines.append("```")
        lines.append("")

    # Notes
    if notes:
        lines.append("## Notes")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")

    # MITRE
    if mitre:
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("")
        for technique in mitre:
            lines.append(mitre_link(technique))
        lines.append("")

    # References
    if references:
        lines.append("## References")
        lines.append("")
        for ref in references:
            lines.append(f"- {ref}")
        lines.append("")

    return "\n".join(lines)


def main():
    # Find all changed/new .toml files in queries directories
    toml_files = list(Path(".").rglob("queries/*.toml"))

    if not toml_files:
        print("No TOML files found.")
        sys.exit(0)

    for toml_path in toml_files:
        print(f"Processing: {toml_path}")

        md_content = generate_md(toml_path)

        # Output path: same parent's sibling docs/ directory
        docs_dir = toml_path.parent.parent / "docs"
        docs_dir.mkdir(exist_ok=True)

        md_filename = toml_path.stem + ".md"
        md_path = docs_dir / md_filename

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        print(f"  ✅ Generated: {md_path}")


if __name__ == "__main__":
    main()
