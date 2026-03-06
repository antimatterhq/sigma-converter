# Sigma → LakeWatch Rules

## Run (LakeWatch only)

```bash
# from repo root
# Use a repo-local virtualenv (`.venv/`) so dependencies are isolated per-project and
# `poetry run ...` doesn't accidentally use a global Python env missing required packages.
poetry config virtualenvs.in-project true --local
poetry install --no-interaction

# OPTIONAL: generate/update mappings (requires OPENAI_KEY)
export OPENAI_KEY='...'
# IMPORTANT: `convert-lakewatch` expects FULL Sigma rules with an `ocsf_mapping` block.
poetry run field-mapper --map --output fieldmapper/mappings/ --full

# convert mapped YAML -> LakeWatch JSON
poetry run convert-lakewatch -i fieldmapper/mappings -o output
```

## Output

- **Files**: `output/<rule_filename>.json`

Example (trimmed):

```json
{
  "spec": {
    "input": {
      "batch": {
        "sql": "SELECT * FROM file_activity WHERE ..."
      }
    }
  }
}
```

## How it works (high level)

### 1) Source of truth (OCSF files) — and why `activity_id` matters

The OCSF Lite files in `fieldmapper/ocsf_data/` are the “schema truth” for what fields exist, what their **datatypes** are, and (crucially) which **activities** are valid for a given event class.

This is important because **Sigma is not table-aware**. Sigma’s `logsource` keys (`category/product/service`) were designed for “flat” SIEM backends, but LakeWatch queries are written against **OCSF event-class tables** (e.g. `process_activity`, `file_activity`, `http_activity`) and often need an `activity_id` to be precise.

Two OCSF inputs are used:

- **AI schema index**: `fieldmapper/ocsf_data/ocsf_lite_ai_schema.json` is a flattened index of event classes + fields (each field has `path`, `type`, and `description`). The mapper uses this as an allow-list so field mappings can only target valid OCSF columns.
- **Raw per-class JSON**: `fieldmapper/ocsf_data/_ocsf_lite/events/**/<class>.json` (e.g. `.../events/**/process_activity.json`) is used to extract `attributes.activity_id.enum`. That enum constrains which integer `activity_id` values are valid for that class, so the AI can’t guess/hallucinate an activity.

Why `activity_id` matters:

- Within a single OCSF table, different activities can represent very different semantics (create/update/delete/etc.).
- If we can confidently choose `activity_id`, `convert-lakewatch` injects it into the SQL to narrow results (better precision and usually better performance).

### 2) AI mapping (`field-mapper`): the core nuance (table first, then columns)

`field-mapper` reads Sigma rules from `rules/`, builds a **MappingContext**, then calls the OpenAI model in three steps. The most important nuance is: **we must decide the OCSF event class/table first**, because the event class determines the meaning and availability of field names.

For example, the same Sigma field like `Image` might map to different OCSF targets depending on the chosen class:

- In `process_activity`, the *subject* is the process being created/observed, so `Image` → `process.name`.
- In `file_activity` or `network_activity`, the *subject* is a file or connection, so the same `Image` often describes the *actor process*, mapping to `actor.process.name`.

That’s why “pick the right table” is the single biggest mapping problem: if the class is wrong, the column mapping will be wrong even if the AI is trying its best.

The three AI steps:

- **Step A — choose the target event class/table** (example: `system/process_activity`):
  - **Inputs used from the Sigma rule**: `logsource.category`, `logsource.product`, `logsource.service`, rule `title`, rule `tags`, and the list of detection field names.
  - **Primary decision rule**: if `logsource.category` matches the category→event-class table embedded in the prompt, it returns that immediately. This is how a Sigma key like `process_creation` becomes an OCSF table like `process_activity`.
  - **When the primary keys aren’t enough**: for some rules, the Sigma logsource keys and field names don’t cleanly identify an OCSF class (especially cloud/SaaS rules). In those cases the prompt uses **MITRE ATT&CK technique tags** (`attack.t*`) to pull in MITRE “data components” (process creation vs file modification vs network traffic, etc.) as extra signal to select the right event class.

- **Step B — map detection fields to OCSF fields**:
  - The AI is given the chosen event class and the list of Sigma field names.
  - The AI is also given the **allow-list** of valid OCSF fields for that event class from `ocsf_lite_ai_schema.json` (plus a few hard-coded augmentations for known schema gaps).
  - The mapper filters out “computed/derived” targets (e.g. `*_uid`, `*_name`, and fields like `severity/status/activity`).

- **Step C — choose an `activity_id`** (optional):
  - Uses rule context + the `activity_id` enum extracted from the raw per-class JSON.
  - The prompt is intentionally conservative and returns `UNMAPPED` when unsure.

If a Sigma rule contains keyword-based detections (detection block names containing `keywords`), the mapper skips field mapping because there are no stable field names to map.

### 3) What a mapping run produces (and what it’s used for)

A mapping run writes YAML files into `fieldmapper/mappings/`. For LakeWatch conversion, these files must be **full Sigma rules** plus an extra `ocsf_mapping` block.

That `ocsf_mapping` block is what `convert-lakewatch` relies on to:

- choose the LakeWatch/OCSF **table** (`class_name`)
- inject **`activity_id`** when available
- rename Sigma fields to OCSF fields (via `detection_fields` mappings)

Example mapping (trimmed from `fieldmapper/mappings/aws_delete_identity.yml`):

```yaml
title: SES Identity Has Been Deleted
logsource:
  product: aws
  service: cloudtrail
# ... detection omitted ...
ocsf_mapping:
  class_name: file_activity
  activity_id: 4
  detection_fields:
    - source_field: eventSource
      target_table: file_activity
      target_field: metadata.product.name
    - source_field: eventName
      target_table: file_activity
      target_field: metadata.event_code
```

### 4) Rerunning + fixing “wrong” mappings (where, exactly)

If a generated LakeWatch rule is wrong, you fix the **mapped YAML** that `convert-lakewatch` reads:

- **Where**: edit the file under `fieldmapper/mappings/` (same filename you’re converting), e.g.
  - `fieldmapper/mappings/aws_delete_identity.yml`

- **What to change** (inside the `ocsf_mapping:` block):
  - **Wrong table**: change `ocsf_mapping.class_name`
  - **Wrong column**: change the appropriate `ocsf_mapping.detection_fields[*].target_field`
  - **Wrong/missing activity filter**: change `ocsf_mapping.activity_id`

Then rerun conversion:

```bash
poetry run convert-lakewatch -i fieldmapper/mappings -o output
```

Important: if you rerun `field-mapper` into the *same* `--output` directory, it can overwrite existing mapping files (including your manual fixes). If you expect to do manual overrides, treat `fieldmapper/mappings/` as the source-of-truth and only rerun the mapper intentionally (or map into a separate directory and copy the specific YAMLs you want).

### 5) Is the mapping output idempotent?

- **Mostly yes** when caching is used (see next section) and the schema/prompt/model hasn’t changed.
- It will change if you:
  - clear/ignore cache (`--refresh-cache` / `--no-cache`)
  - change OCSF schema files
  - change the prompts/model (or run without cache and get different AI outputs)

### 6) What is `.mapping_cache.json`? (and should it be in git?)

`.mapping_cache.json` is a **local optimization** used by `field-mapper` to avoid re-calling the OpenAI API for the same decisions.

- **What it stores** (high level):
  - event class decisions (keyed by *sorted detection field names*)
  - field mapping decisions (keyed by `event_class:field_name`)

Example (trimmed):

```json
{
  "logsource": {
    "CommandLine,Image": { "event_class": "process_activity" }
  },
  "detection_fields": {
    "process_activity:ProcessId": { "target_field": "process.pid" }
  }
}
```

- **Where it lives**: by default it’s created in the repo root as `.mapping_cache.json` (you can change the path with `field-mapper --cache <path>`).
- **Git or local?** Typically **local-only** (it’s not a source-of-truth; it’s a performance/cost cache). If you commit it, you risk sharing stale decisions across developers.

### 7) `convert-lakewatch` + backend overview (how SQL and LakeWatch rules are built)

`convert-lakewatch` reads mapped YAML from `fieldmapper/mappings/` and converts each rule with the Databricks Sigma backend + the LakeWatch processing pipeline.

**Why “de-conflicting” exists (correctness + performance):** Sigma’s `(category, product, service)` keys are reused across many rules, but they don’t always map 1:1 to a single OCSF table. The pipeline builder scans all mapped rules and splits logsources into two buckets:

- **1:1 logsources (fast path)**: for a given `(category, product, service)`, *all* mapped rules agree on the same OCSF table. The pipeline can apply a single logsource-scoped table selection + field mapping for all those rules.
- **Conflicted logsources (specific path)**: the same `(category, product, service)` appears across rules that map to *different* OCSF tables. In that case, the pipeline must select the table **per rule id** to avoid generating SQL against the wrong table.

This is a big win because the 1:1 case is both common and cheap to apply, while the conflicted case stays correct by being more specific.

- **Datatype-aware SQL**: once the table is known, the pipeline attaches type hints from the OCSF schema (plus array/struct parent info) so the backend can emit the right casts and array handling.

- **Defaults injected** (correctness/efficiency):
  - **Time window (backend finalization)**: the Databricks backend wraps every rule in a bounded time filter when it finalizes the SQL (default: last 24 hours). This prevents unbounded table scans and matches how scheduled detections are expected to run.

    Example shape:

    ```sql
    SELECT * FROM <table>
    WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24 HOUR AND CURRENT_TIMESTAMP()
      AND (<sigma_detection_conditions>)
    ```

  - **`activity_id` (pipeline transformation)**: the LakeWatch pipeline injects `activity_id = <n>` as an extra condition *only* when the mapping produced a confident integer `activity_id`. This narrows the query to the correct OCSF activity within the chosen table (better precision, often faster).

    Implementation-wise this uses pySigma’s `AddConditionTransformation`, scoped per-rule with `RuleIDCondition`.

Finally, the generated SQL + metadata is wrapped into LakeWatch Rule JSON and written to `output/`.
