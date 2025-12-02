"""
OCSF validators for Sigma rules.

Provides validators for checking OCSF table and field mappings.
"""

from .mappings import (
    OCSFTableMappingValidator,
    OCSFFieldMappingValidator,
    MissingTableMappingIssue,
    UnmappedFieldsIssue,
)

# Registry of OCSF validators for easy importing
ocsf_validators = {
    'ocsf_table_mapping': OCSFTableMappingValidator,
    'ocsf_field_mapping': OCSFFieldMappingValidator,
}

__all__ = [
    'ocsf_validators',
    'OCSFTableMappingValidator',
    'OCSFFieldMappingValidator',
    'MissingTableMappingIssue',
    'UnmappedFieldsIssue',
]

