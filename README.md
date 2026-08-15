# Threat Hunting

A collection of threat hunting scenarios organized by platform.

## Structure

| Directory | Content |
|-----------|---------|
| `linux/` | Threat hunting scenarios for Linux environments |
| `windows/` | Threat hunting scenarios for Windows environments |
| `network/` | Threat hunting scenarios based on network traffic analysis |

Each platform directory contains two subdirectories:

```
{platform}/
├── docs/        ← auto-generated Markdown documentation
└── queries/     ← TOML hunt files (contributed here)
```

---

## How to Contribute

### 1. Clone (or fork) the repository

```bash
git clone https://github.com/hatamovkanan/threat-hunting.git
cd threat-hunting
```

---

### 2. Create a new branch

Branch naming convention: `{platform}/{hunt-name}`

```bash
git checkout -b linux/hidden-process-execution
```

---

### 3. Create a TOML file

Navigate to the relevant platform's `queries/` directory and create a new TOML file. Name it descriptively to reflect the threat being hunted (e.g., `hidden_process_execution.toml`).

**Required fields:**

| Field | Description |
|-------|-------------|
| `author` | Your name or organization |
| `name` | Unique, descriptive hunt name |
| `description` | Clear explanation of the threat and hunt goal |
| `uuid` | A valid UUID v4 — generate one at [uuidgenerator.net](https://www.uuidgenerator.net/) |
| `integration` | Elastic integration (e.g., `endpoint`, `aws`, `okta`) |
| `language` | Query language: `ES\|QL`, `EQL`, `KQL`, `AQL`, `SPL`, `XQL`, `CQL`, or `SQL` |
| `hunt_type` | `Hypothesis-Driven`, `Analytics-Driven`, or `Intel-Driven` |
| `mitre` | MITRE ATT&CK technique IDs (e.g., `["T1059", "T1036.004"]`) |
| `query` | Array of actual hunt queries |
| `notes` | *(Optional)* Insights, pivoting tips, false positive guidance |
| `references` | *(Optional)* Relevant URLs for additional context |

**Example:**

```toml
[hunt]
author = "Your Name"
name = "Hidden Process Execution"
description = """
This hunt identifies processes executed from hidden files on Linux systems.
"""
uuid = "00461198-9a2d-4823-b4cc-f3d1b5c17935"
integration = ["endpoint"]
language = ["ES|QL"]
hunt_type = "Hypothesis-Driven"
mitre = ["T1036.004", "T1059"]
notes = [
    "Focus on hidden files, not directories.",
    "Low process count threshold reduces noise.",
]
references = [
    "https://attack.mitre.org/techniques/T1036/004"
]

query = [
'''
FROM logs-endpoint.events.process-*
| WHERE @timestamp > now() - 30 day
| WHERE host.os.type == "linux" AND event.type == "start"
| LIMIT 100
'''
]
```

---

### 4. Validate your TOML file

Before opening a PR, validate your file locally:

```bash
python .github/scripts/validate_hunt.py
```

The validator checks:
- All required fields are present
- `uuid` is a valid UUID v4 and not a duplicate of an existing hunt
- `hunt_type` is one of the allowed values
- `language` values are valid
- `mitre` technique IDs are in correct format
- `query` is not empty
- `references` are valid URLs (if provided)

---

### 5. Commit and push your branch

```bash
git add linux/queries/hidden_process_execution.toml
git commit -m "Hunt: Add hidden process execution for Linux"
git push origin linux/hidden-process-execution
```

---

### 6. Open a Pull Request

Open a PR from your branch to `main`. Use the `[Hunt]` prefix in your PR title:

```
[Hunt] Linux - Hidden Process Execution
```

In the PR description, include:
- What threat or behavior the hunt detects
- Why this hunt is valuable
- Any relevant notes or data considerations

---

### 7. Automated checks and review

Once the PR is opened, the following happens automatically:

1. **Validation** — `validate_hunt.py` checks your TOML file. If it fails, the PR is blocked until fixed.
2. **Review** — A maintainer reviews the hunt logic, MITRE mappings, and query quality.
3. **Merge** — Once approved and merged into `main`:
   - A Markdown doc is auto-generated in `{platform}/docs/`
   - `index.yml` and `index.md` are automatically updated

> ⚠️ Direct pushes to `main` are not allowed. All changes must go through a Pull Request.

---

## Available Hunts

See [index.md](./index.md) for the full list of available hunt queries organized by platform.
