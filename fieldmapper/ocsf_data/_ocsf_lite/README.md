# OCSF Schema Lite

A streamlined version of the Open Cybersecurity Schema Framework (OCSF) designed for simplified implementation and easier adoption.

## Overview

This project provides a lightweight, flat schema definition for 16 core OCSF event types, making it easier to implement OCSF-compliant data structures without the complexity of the full schema.

## Key Features

- **Lite Schema**: Focused on 16 essential event types (expandable over time)
- **Flat Structure**: Each schema file contains a complete, flattened definition of table requirements
- **Built-in Profiles**: Cloud, Device, and Date/Time profiles are included by default in the flat files
- **Base Event Integration**: All tables still need to include base event fields
- **Observable Mapping**: Observable types still need to be identified from dictionary.json and added to the observables column
- **Enum Support**: String equivalent columns for all enum fields exist, and are identified via 'sibling' key mapping
- **Dictionary Fallback**: Missing column descriptions should default back to dictionary values

## Project Structure

```
ocsf-schema-lite/
├── events/           # Individual schema files for each event type
├── version.json      # OCSF version and project version tracking
└── dictionary.json   # Centralized field definitions and descriptions
```

## Version Management

The `version.json` file tracks:
- Original OCSF schema version
- Current project version

## Schema Files

Each schema file in the `events/` directory contains:
- Complete flat definition of table requirements
- All necessary fields excluding base event attributes
- Enum definitions with corresponding string columns

### Observable Fields
When mapping schemas, the observable column is populated by checking the attributes dictionary for an 'observable' key, with its value mapped to the type_id for an observable.

### Enum Fields
Fields with enums automatically include their string equivalent columns. The dictionary's 'sibling' key exposes which column receives the enum caption value.

### Missing Descriptions
Where schema file column descriptions are missing, the default description is pulled from the central dictionary.

## Future Enhancements

- Additional event types beyond the initial 16
- New profile inclusions based on feedback
- Additional attributes as needed once battle tested on real data
