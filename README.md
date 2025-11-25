# Sigma Converter

Convert Sigma detection rules to Databricks SQL with OCSF field mappings.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python3 -m pip install poetry
python3 -m poetry update
```

## Run Tests

```bash
# Fast unit tests (~0.2 seconds)
pytest tests/unittests/

# Integration tests (~3 minutes)
pytest tests/integration/

# All tests
pytest
```

## Usage

### Convert Rules to Databricks SQL

```python
from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.lakewatch import lakewatch_pipeline
from sigma.collection import SigmaCollection

# Load rules and convert
backend = DatabricksBackend(lakewatch_pipeline())
collection = SigmaCollection.from_yaml("rule.yml")
queries = backend.convert(collection)
```

### Map Rules to OCSF (CLI)

```bash
# Set up data files first (one-time if not already there)
python fieldmapper/ocsf_data/bin/ocsflite_parser.py --export-ai-schema .
python fieldmapper/ocsf_data/bin/mitre.py

# Map rules
requires equivilent of; `export OPENAI_KEY="your-key"` if not already there.
sigma-ocsf-field-mapper --map --output mappings/ --limit 10

# Analyze mappings
sigma-ocsf-field-mapper --analyze mappings/

# Debug specific rule
sigma-ocsf-field-mapper --map --file rule.yml --debug-prompt --no-cache
```

## Code Structure

```
sigma/
├── backends/databricks/     # SQL generation
└── pipelines/
    ├── lakewatch/          # OCSF pipeline transformations
    └── databricks/         # Snake case pipeline -- to be deprecated in future PR.

fieldmapper/
├── ocsf/                   # AI mapper, rule loading
├── mappings/               # OCSF-mapped rules (output)
└── ocsf_data/              # Schema and MITRE data

tests/
├── unittests/              # Fast tests (inline YAML)
└── integration/            # Slow tests (load files)
```

## Key Components

**DatabricksBackend**: Generates Databricks SQL from Sigma rules
- Output formats: TBD:
- Supports field modifiers: `|contains`, `|endswith`, `|startswith`, `|re`

**lakewatch_pipeline**: OCSF-aware processing pipeline
- Maps Sigma fields to OCSF fields
- Auto-assigns OCSF table via `rule.custom_attributes['table']`
- Uses `LogsourceCondition` for non-conflicted logsources
- Uses `RuleIDCondition` for conflicted rules (same logsource → different tables)

**Field Mapper**: AI-powered Sigma → OCSF mapping
- Uses OpenAI structured outputs
- Caches mappings in `.mapping_cache.json`
- Outputs to `fieldmapper/mappings/`

## Known Issues

- `cidrmatch` generated but requires UDF implementation
- Keyword rules (text without fields) not supported
- Needs more testing

## Configuration

Edit rule paths in `fieldmapper/ocsf/rules.py`:
```python
PATHS = ["rules/"]  # Recursively scans subdirectories
```
