"""
Unit tests for OCSF validators.
"""

from sigma.collection import SigmaCollection
from sigma.validators.ocsf import (
    OCSFTableMappingValidator,
    OCSFFieldMappingValidator,
    MissingTableMappingIssue,
    ocsf_validators,
)
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validation import SigmaValidator


def test_table_validator_detects_missing_table():
    """Test that OCSFTableMappingValidator detects rules without table mapping."""
    rule_yaml = """
    title: Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    validator = OCSFTableMappingValidator()
    issues = validator.validate(rule)
    
    assert len(issues) == 1
    assert isinstance(issues[0], MissingTableMappingIssue)
    assert issues[0].severity == SigmaValidationIssueSeverity.LOW


def test_table_validator_detects_unmapped_table():
    """Test that validator detects <UNMAPPED_TABLE> placeholder."""
    rule_yaml = """
    title: Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    # Manually set invalid table value
    rule.custom_attributes['table'] = '<UNMAPPED_TABLE>'
    
    validator = OCSFTableMappingValidator()
    issues = validator.validate(rule)
    
    assert len(issues) == 1
    assert isinstance(issues[0], MissingTableMappingIssue)
    assert '<UNMAPPED_TABLE>' in str(issues[0])


def test_table_validator_accepts_valid_table():
    """Test that validator accepts rules with valid table mappings."""
    rule_yaml = """
    title: Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    # Set valid table
    rule.custom_attributes['table'] = 'process_activity'
    
    validator = OCSFTableMappingValidator()
    issues = validator.validate(rule)
    
    assert len(issues) == 0


def test_field_validator_skips_non_ocsf_rules():
    """Test that field validator skips rules without OCSF methods."""
    rule_yaml = """
    title: Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    validator = OCSFFieldMappingValidator()
    issues = validator.validate(rule)
    
    # Should skip since it's not SigmaRuleOCSFLite
    assert len(issues) == 0


def test_ocsf_validators_registry():
    """Test that ocsf_validators dict contains all validators."""
    assert 'ocsf_table_mapping' in ocsf_validators
    assert 'ocsf_field_mapping' in ocsf_validators
    assert ocsf_validators['ocsf_table_mapping'] == OCSFTableMappingValidator
    assert ocsf_validators['ocsf_field_mapping'] == OCSFFieldMappingValidator


def test_validator_with_sigma_validator():
    """Test integration with SigmaValidator."""
    rule_yaml = """
    title: Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    
    # Create validator with OCSF validators
    validator = SigmaValidator(ocsf_validators.values())
    issues = validator.validate_rules(collection.rules)
    
    # Should detect missing table mapping
    assert len(issues) >= 1
    assert any(isinstance(issue, MissingTableMappingIssue) for issue in issues)


def test_issue_includes_rule_information():
    """Test that issues include helpful rule information."""
    rule_yaml = """
    title: My Test Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    validator = OCSFTableMappingValidator()
    issues = validator.validate(rule)
    
    assert len(issues) == 1
    issue_str = str(issues[0])
    
    # Check that issue string contains helpful information
    assert "12345678-1234-1234-1234-123456789abc" in issue_str
    assert "ocsf_mappings" in issue_str


def test_validators_skip_correlation_rules():
    """Test that validators skip correlation rules themselves."""
    rule_yaml = """
    title: Detection Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: test
    detection:
        selection:
            field: value
        condition: selection
    """
    
    correlation_yaml = """
    title: Test Correlation
    id: 87654321-4321-4321-4321-cba987654321
    correlation:
        type: event_count
        rules:
            - 12345678-1234-1234-1234-123456789abc
        group-by:
            - user
        timespan: 10m
        condition:
            gte: 5
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    correlation_rule = collection.rules[1]
    
    # Validators should skip correlation rules
    table_validator = OCSFTableMappingValidator()
    field_validator = OCSFFieldMappingValidator()
    
    table_issues = table_validator.validate(correlation_rule)
    field_issues = field_validator.validate(correlation_rule)
    
    assert len(table_issues) == 0
    assert len(field_issues) == 0

