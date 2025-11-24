# Setup
## Create a venv & activate it
```
python3.12 -m venv .venv
source .venv/bin/activate
```
## Update poetry dependencies
```
python3 -m pip install poetry
python3 -m poetry update
```

## Run tests
```
pytest
```

Status: **experimental**, work in progress:

* Although `cidrmatch` is generated, you still need to provide corresponding function as UDF (I'll add example later)
* Keywords (text rules without specific field) aren't supported yet
* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* `snake_case`: convert column names into snake case format

It supports the following output formats:

* default: plain Databricks/Apache Spark SQL queries
* dbsql: Databricks SQL queries with rules metadata (title, status) embedded as comment
* detection_yaml: Yaml markup for my own detection framework

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)

---

# OCSF Lite Field Mapper

This repository also includes an AI-powered Sigma to OCSF Lite field mapper. It maps Sigma detection rules to OCSF Lite event classes and fields using OpenAI's structured outputs.

## Installation

After running `poetry install`, the `sigma-ocsf-field-mapper` command is available globally.

```bash
poetry install
export OPENAI_KEY="your-key"
```

## Quick Start

```bash
sigma-ocsf-field-mapper --map --output mappings --limit 5
```

## Key Commands

| Command | Description |
|---------|-------------|
| `--map` | Enable AI mapping |
| `--output DIR` | Export mapped rules to directory |
| `--limit N` | Process first N rules only |
| `--analyze DIR` | Analyze mapping results and generate stats |
| `--refresh-cache` | Clear and rebuild cache from scratch |
| `--no-cache` | Skip cache reads (still writes new mappings) |
| `--debug-prompt` | Show AI prompts and responses |
| `--file NAME` | Map specific file only |
| `--full` | Export full rule details (default: mappings only) |
| `--json` | Export as JSON instead of YAML |

## Common Usage

```bash
# Map all rules and export
sigma-ocsf-field-mapper --map --output mappings/

# Map first 100 rules for testing
sigma-ocsf-field-mapper --map --limit 100 --output mappings

# Map with cache refresh
sigma-ocsf-field-mapper --map --refresh-cache --output mappings

# Analyze mapping results
sigma-ocsf-field-mapper --analyze mappings

# Debug a specific rule
sigma-ocsf-field-mapper --map --file proc_creation_win_cmd_assoc_execution.yml --debug-prompt --no-cache

# Export entire rule object along with the ocsflite mappings
sigma-ocsf-field-mapper --map --output mappings --full
```

## Initial Setup

The mapper requires two data files that power the AI mapping:

### 1. OCSF Schema (`ocsf_lite_ai_schema.json`)

Generated from OCSF Lite schema files in `fieldmapper/ocsf_data/_ocsf_lite/`. Flattens the schema and passed to the AI to show available event classes and fields.

```bash
python fieldmapper/ocsf_data/bin/ocsflite_parser.py --export-ai-schema .
```

**Output**: `fieldmapper/ocsf_data/ocsf_lite_ai_schema.json` - Contains all OCSF event classes with their field paths for the prompts.

### 2. MITRE ATT&CK Data (`mitre_attack_data.json`)

Downloads MITRE ATT&CK STIX data and extracts technique information including detection strategies and data components.

```bash
python fieldmapper/ocsf_data/bin/mitre.py
```

**Output**: `fieldmapper/ocsf_data/mitre_attack_data.json` - Contains technique metadata used to validate category mappings.

## How It Works

- **Category mapping**: Uses mandatory table (e.g., `process_creation` → `process_activity`), followed by rules to map the event class
- **Field mapping**: AI maps detection fields to OCSF fields with few-shot examples based on the selected event class
- **Caching**: Stores mappings in `.mapping_cache.json` for efficiency
- **Field filtering**: Automatically filters out derived fields (`_uid`, `_name`, `activity`, etc.)
- **MITRE context**: Uses ATT&CK data components to validate mappings

## Output Format

**Simple format (default):**
```yaml
event_class: process_activity
field_mappings:
  Image: process.name
  CommandLine: process.cmd_line
  ParentImage: process.parent_process.name
```

**Full format (`--full` flag):**
```yaml
id: abc-123
title: Suspicious Process
status: test
# ... all original rule fields ...
ocsf_mapping:
  class_name: process_activity
  logsource:
    category:
      source_field: category
      source_value: process_creation
      mapped_at: '2025-11-13T...'
  detection_fields:
    - source_field: Image
      target_table: process_activity
      target_field: process.name
      mapped_at: '2025-11-13T...'
```

## Programmatic Usage

```python
from fieldmapper.ocsf import SigmaRuleOCSFLite, load_and_process_rules

# Load and process rules
result = load_and_process_rules(
    map_rules=True,
    api_key="your-openai-key",
    output_dir="mappings/",
    limit=10
)

# Access mapped rules
for rule in result['rules']:
    if rule.ocsflite.class_name:
        print(f"{rule.title} → {rule.ocsflite.class_name}")
```

## Configuration

Edit `PATHS` in `fieldmapper/ocsf/rules.py` to specify rule directories:

```python
PATHS = [
    "rules/"  # Recursively scans all subdirectories
]
```

## Testing

Run OCSF mapper tests:

```bash
pytest tests/test_ocsf_*.py
```
