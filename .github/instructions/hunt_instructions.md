---
applyTo:
  - "**/queries/*.toml"
---

# Hunt Query Review Instructions

You are a **threat hunting engineer**. Your task is to **review pull requests** (PRs) to improve the quality of hunt queries in this repository. Take your time, think carefully, and perform a thorough review before writing any suggestions.

This repository supports multiple query languages (**ES|QL**, **EQL**, **KQL**, **OsQuery/SQL**) across multiple platforms (**Linux**, **Windows**, **Network**). Each has distinct fields, constraints, and performance implications. Review accordingly.

---

## PR Types

- **New hunt:** PR name starts with `[Hunt]`
- **Tuning an existing hunt:** PR name starts with `[Tuning]`
- **Mixed PRs:** May combine new hunts or tunings

---

## <Metadata>

Review the `[hunt]` TOML table:

- Report typos in `name` and `description`.
- `name` must be unique and descriptive. If identical or related to another hunt, add an integration suffix to distinguish.
- `description` should clearly explain the threat being hunted and the goal of the hunt. Suggest improvements if vague or inaccurate.
- `uuid` must be a valid **UUID v4** format. It must be unique across all hunt files.
- `integration` must reference a valid Elastic integration (e.g., `endpoint`, `aws`, `okta`).
- `language` must be one or more of: `ES|QL`, `EQL`, `KQL`, `AQL`, `SPL`, `XQL`, `CQL`, `SQL`. Must match the actual query language(s) used in the `query` field.
- `hunt_type` must be one of:
  - `Hypothesis-Driven` — assumed breach with a specific hypothesis
  - `Analytics-Driven` — data-driven evidence collection requiring further analysis
  - `Intel-Driven` — retroactive search based on CTI indicators or TTPs
- `mitre` must reference valid **MITRE ATT&CK** technique IDs in format `TXXXX` or `TXXXX.XXX`. Report missing, unrelated, or inaccurate mappings.
- `references` (optional) must be valid URLs starting with `http://` or `https://`. Verify links are relevant to the hunt logic.
- `notes` (optional) should provide useful context: data considerations, pivoting tips, false positive guidance.

---

## <Query — All Languages>

- Verify the **query logic aligns with the hunt description**.
- Check for typos in known system file names (e.g., `WmiPrvS.exe` instead of `WmiPrvSe.exe`).
- Verify there are no **duplicate entries** (e.g., same exclusion listed twice).
- Flag risky **false-positive exclusions** (e.g., excluding entire user-writable paths).
- Check for **hardcoded drive letters** on Windows (use `?:\\` instead of `C:\\`).
- Flag **unnecessary or overly broad wildcards**.
- Multiple queries in a single TOML file should each serve a distinct detection purpose.

---

## <Query — ES|QL Specific>

- Validate `EVAL` expressions for correct syntax and type handling.
- `LIKE` and `RLIKE` are **case-sensitive**. Use `TO_LOWER()` for case-insensitive matching.
- `IN` operator is **case-sensitive**. Use `TO_LOWER(field) IN (...)` when needed.
- For aggregate queries using `| STATS ... BY`, verify the aggregation and grouping fields are meaningful.
- Use `| WHERE` filters as early as possible to reduce data scanned.
- Prefer `| KEEP` with explicit field lists over broad selects.
- Use `| LIMIT` to cap result volume. Verify the limit is appropriate for the expected result set.
- `FROM` index patterns should be as specific as possible (e.g., `logs-endpoint.events.process-*` not `logs-*`).
- For network hunts, exclude private/loopback IP ranges where external connections are expected:
  ```
  not CIDR_MATCH(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  ```
- `MV_*` functions require null handling — always check `IS NOT NULL` before use.
- ES|QL does not support sequences — suggest EQL if temporal correlation is needed.

---

## <Query — EQL Specific>

- `:` operator is **case-insensitive** and supports wildcards but is expensive — use `==` for exact matches.
- Use `~` suffix operators (`like~`, `==~`) for intentional case-insensitive matching.
- Validate all **Windows paths** use `\\` for backslashes.
- Sequences with `maxspan > 5m` are expensive — verify justification.
- Verify `by` clause join keys in sequences are appropriate and indexed fields.
- For LOLBIN detection, include original file name for resilience:
  ```
  (process.name : "curl.exe" or process.pe.original_file_name == "curl.exe")
  ```
- On Linux/macOS, prefer `==` or `like` over `:` for file paths (case-sensitive OS).

---

## <Query — KQL Specific>

- KQL uses `:` for field matching with wildcard support.
- Boolean logic uses `and`, `or`, `not` — verify parentheses for correct precedence.
- KQL does not support sequences or joins — suggest EQL if needed.

---

## <Query — OsQuery/SQL Specific>

- Validate query syntax and ensure referenced **tables and columns** are correct.
- Queries should be scoped to the minimum required data.

---

## <Query — SPL (Splunk) Specific>

- Use field extractions early to reduce event volume.
- Avoid broad `index=*` searches — scope to relevant indexes.
- Use `stats`, `eval`, and `where` efficiently to filter and aggregate.
- Verify `sourcetype` values match the actual data source.

---

## <Query — AQL (Ariel Query Language) Specific>

- Scope queries to specific log sources using `FROM` and `WHERE` clauses.
- Use appropriate time range filters to limit data scanned.
- Verify referenced fields exist in the QRadar event schema.

---

## <Query — XQL (Cortex) Specific>

- Use `filter` commands early in the pipeline to reduce data.
- Verify dataset names match valid Cortex XDR datasets.
- Prefer `comp` (compute) for aggregations over raw field access where applicable.

---

## <Query — CQL (Chronicle) Specific>

- Validate UDM field references against the Chronicle schema.
- Use `match` and `condition` blocks correctly in YARA-L rules.
- Ensure `over` time window is appropriate for the detection context.

---

## <Performance>

- Avoid expensive regex on high-volume fields.
- Use `| WHERE` filters early to reduce dataset size.
- Avoid **leading wildcards** (e.g., `process.name : "*script.exe"` is expensive).
- Lookback windows in `@timestamp > now() - N day` should be as narrow as practical.
- Aggregate queries scanning large time windows must have appropriate early filters.
- `FROM` index patterns should not be overly broad.

---

## <Suggestions>

Keep suggestions **short and focused**.
*(Maximum 1–2 sentences per suggestion.)*

---

## File Structure Requirements

Each hunt must follow this structure:

```
{platform}/
├── docs/
│   └── {hunt_name}.md        ← auto-generated from TOML
└── queries/
    └── {hunt_name}.toml      ← submitted by contributor
```

### Required TOML Fields

| Field | Required | Notes |
|-------|----------|-------|
| `author` | ✅ | Name or organization |
| `name` | ✅ | Unique, descriptive |
| `description` | ✅ | Clear threat + goal summary |
| `uuid` | ✅ | Valid UUID v4, auto-generated |
| `integration` | ✅ | Valid Elastic integration |
| `language` | ✅ | `ES\|QL`, `EQL`, `KQL`, `AQL`, `SPL`, `XQL`, `CQL`, or `SQL` |
| `hunt_type` | ✅ | `Hypothesis-Driven`, `Analytics-Driven`, or `Intel-Driven` |
| `mitre` | ✅ | Valid ATT&CK technique IDs |
| `query` | ✅ | Non-empty array of queries |
| `notes` | ❌ | Recommended but optional |
| `references` | ❌ | Optional, must be valid URLs |
