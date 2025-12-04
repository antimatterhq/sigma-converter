# Sigma → Databricks SQL Converter

Converts Sigma detection rules to Databricks SQL with OCSF field mappings for LakeWatch deployment.

## Quick Start

```bash
# Setup
python3.12 -m venv .venv
source .venv/bin/activate
pip install poetry
poetry install

# Run tests
pytest tests/unittests/
pytest tests/integration/
```

## Architecture

### Core Components

**`sigma/backends/databricks/`** - SQL generation
- `base.py`: Single-event rule conversion, validation orchestration
- `correlation.py`: Multi-event correlation using Spark SQL window functions
- `lakewatch_rule.py`: LakeWatch JSON output format
- `sql_validator.py`: Post-conversion SQL syntax validation via sqlglot

**`sigma/pipelines/lakewatch/`** - OCSF pipeline
- Applies field mappings from `fieldmapper/mappings/`
- Sets `rule.custom_attributes['table']` for OCSF event class
- Injects `activity_id` and other OCSF-specific conditions

**`sigma/validators/ocsf/`** - Pre-conversion validation
- `MissingTableMappingIssue`: Rejects rules without valid OCSF table
- `UnmappedFieldsIssue`: Rejects rules with unmapped detection fields
- Validation runs before conversion; invalid rules are skipped

**`fieldmapper/`** - AI-powered Sigma → OCSF mapping
- `ocsf/mapper.py`: OpenAI structured outputs for field mapping
- `ocsf/rules.py`: Rule loading, OCSF metadata injection
- `mappings/`: Output directory for mapped rules (YAML with `ocsf_mapping` block)
- `.mapping_cache.json`: Caches AI responses

### Data Flow

```
Original Sigma Rule (rules/)
    ↓
AI Field Mapper (field-mapper)
    ↓
Mapped Rule (fieldmapper/mappings/)
    ↓
Pipeline Transformations (lakewatch_pipeline)
    ↓
OCSF Validation (validators)
    ↓
SQL Generation (DatabricksBackend)
    ↓
LakeWatch JSON (convert-lakewatch)
```

## Usage

### 1. Map Rules to OCSF (One-time per rule)

```bash
# Setup OCSF data (one-time)
python fieldmapper/ocsf_data/bin/ocsflite_parser.py --export-ai-schema .
python fieldmapper/ocsf_data/bin/mitre.py

# Map rules (requires OPENAI_API_KEY env var)
field-mapper --map --output fieldmapper/mappings/ --limit 10

# Analyze mapping coverage
field-mapper --analyze fieldmapper/mappings/
```

### 2. Convert to LakeWatch JSON (CLI)

```bash
# Convert all mapped rules
convert-lakewatch

# Options
convert-lakewatch -i fieldmapper/mappings/ -o lakewatch_rules/
convert-lakewatch -f specific_rule.yml
```

Output: `<original_filename>.json` files ready for LakeWatch API deployment.