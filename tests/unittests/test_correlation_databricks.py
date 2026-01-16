import pytest
from sigma.backends.databricks import DatabricksBackend
from sigma.collection import SigmaCollection

def test_event_count_single_rule_single_groupby():
    """Test basic event_count correlation with single rule and single group-by field"""
    backend = DatabricksBackend()
    
    # Create a simple Sigma rule for correlation
    rule_yaml = """
title: Test Failed Login
id: 12345678-1234-1234-1234-123456789abc
logsource:
    category: authentication
detection:
    selection:
        event_type: failed_login
    condition: selection
"""
    
    # Create a correlation rule that references the above rule
    correlation_yaml = """
title: Brute Force Detection
correlation:
    type: event_count
    rules:
        - 12345678-1234-1234-1234-123456789abc
    group-by:
        - user_name
    timespan: 10m
    condition:
        gte: 5
"""
    
    # Load and convert both rules
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on the referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'authentication'
    
    # Convert - this will process the correlation rule
    result = backend.convert(collection, output_format="default")
    
    # Check that we got a correlation query
    assert len(result) > 0
    
    # The last result should be the correlation query
    correlation_query = result[-1]
    
    # Verify key components of the generated SQL
    assert "WITH combined_events AS" in correlation_query
    assert "event_counts AS" in correlation_query
    assert "COUNT(*) OVER" in correlation_query
    assert "PARTITION BY user_name" in correlation_query
    assert "ORDER BY time" in correlation_query
    assert "RANGE BETWEEN INTERVAL '600' SECOND PRECEDING" in correlation_query
    assert "correlation_event_count >= 5" in correlation_query
    assert " UNION ALL " not in correlation_query  # Single rule, no UNION needed


def test_event_count_multiple_groupby():
    """Test event_count correlation with multiple group-by fields"""
    backend = DatabricksBackend()
    
    rule_yaml = """
title: Test Failed Login
id: 22345678-1234-1234-1234-123456789abc
logsource:
    category: authentication
detection:
    selection:
        event_type: failed_login
    condition: selection
"""
    
    correlation_yaml = """
title: Brute Force Detection Multi GroupBy
correlation:
    type: event_count
    rules:
        - 22345678-1234-1234-1234-123456789abc
    group-by:
        - user_name
        - src_ip
    timespan: 10m
    condition:
        gte: 5
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'authentication'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    # Verify both group-by fields are present
    assert "PARTITION BY user_name, src_ip" in correlation_query


def test_event_count_groupby_ignores_field_types():
    """Test that group-by fields do not use custom field types."""
    backend = DatabricksBackend()

    rule_yaml = """
title: Test Process Rule
id: 52345678-1234-1234-1234-123456789abc
logsource:
    category: process_creation
detection:
    selection:
        process.pid: 123
    condition: selection
"""

    correlation_yaml = """
title: Process Correlation
correlation:
    type: event_count
    rules:
        - 52345678-1234-1234-1234-123456789abc
    group-by:
        - process.pid
    timespan: 5m
    condition:
        gte: 2
"""

    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    collection.rules[0].custom_attributes['table'] = 'process_activity'
    collection.rules[1].custom_attributes['field_types'] = {'process.pid': 'INT'}

    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]

    assert "PARTITION BY process.pid" in correlation_query
    assert "CAST(process.pid AS INT)" not in correlation_query


def test_event_count_multi_rule():
    """Test event_count correlation with multiple rules"""
    backend = DatabricksBackend()
    
    # Two different rules
    rules_yaml = """
title: Failed Login
id: 32345678-1234-1234-1234-123456789abc
logsource:
    category: authentication
detection:
    selection:
        event_type: failed_login
    condition: selection
---
title: Privilege Escalation
id: 42345678-1234-1234-1234-123456789abc
logsource:
    category: process_creation
detection:
    selection:
        command: sudo
    condition: selection
"""
    
    correlation_yaml = """
title: Multi-Rule Correlation
correlation:
    type: event_count
    rules:
        - 32345678-1234-1234-1234-123456789abc
        - 42345678-1234-1234-1234-123456789abc
    group-by:
        - user_name
    timespan: 5m
    condition:
        gte: 3
"""
    
    collection = SigmaCollection.from_yaml(rules_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mappings on referenced rules so they pass validation
    collection.rules[0].custom_attributes['table'] = 'authentication'
    collection.rules[1].custom_attributes['table'] = 'process_activity'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    # Verify UNION ALL is present for multi-rule correlation
    assert " UNION ALL " in correlation_query
    # Verify rule_id tracking
    assert "as rule_id" in correlation_query


def test_correlation_operator_gte():
    """Test correlation with >= operator"""
    backend = DatabricksBackend()
    
    rule_yaml = """
title: Test Rule
id: 52345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
    
    correlation_yaml = """
title: Test Correlation GTE
correlation:
    type: event_count
    rules:
        - 52345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 1m
    condition:
        gte: 10
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    assert "correlation_event_count >= 10" in correlation_query


def test_correlation_operator_gt():
    """Test correlation with > operator"""
    backend = DatabricksBackend()
    
    rule_yaml = """
title: Test Rule GT
id: 62345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
    
    correlation_yaml = """
title: Test Correlation GT
correlation:
    type: event_count
    rules:
        - 62345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 1m
    condition:
        gt: 5
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    assert "correlation_event_count > 5" in correlation_query


def test_correlation_operator_eq():
    """Test correlation with = operator"""
    backend = DatabricksBackend()
    
    rule_yaml = """
title: Test Rule EQ
id: 72345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
    
    correlation_yaml = """
title: Test Correlation EQ
correlation:
    type: event_count
    rules:
        - 72345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 1m
    condition:
        eq: 3
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    assert "correlation_event_count = 3" in correlation_query


def test_unsupported_correlation_type():
    """Test that unsupported correlation types raise NotImplementedError"""
    backend = DatabricksBackend()
    
    rule_yaml = """
title: Test Rule
id: 82345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
    
    # Need to add fieldref for value_count type to be valid
    correlation_yaml = """
title: Test Value Count (Not Supported)
correlation:
    type: value_count
    rules:
        - 82345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 1h
    condition:
        gte: 10
        field: src_ip
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    
    # Should raise NotImplementedError for value_count
    with pytest.raises(NotImplementedError, match="value_count.*not supported"):
        backend.convert(collection)


def test_groupby_empty_raises_error():
    """Test that empty group-by fields raise ValueError"""
    backend = DatabricksBackend()
    
    with pytest.raises(ValueError, match="Group-by fields cannot be empty"):
        backend.convert_correlation_aggregation_groupby_from_template([], "default")


def test_rule_id_tracking():
    """Test that rule_id tracking works correctly in UNION ALL"""
    backend = DatabricksBackend()
    
    rules_yaml = """
title: Rule One
id: 92345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field1: value1
    condition: selection
---
title: Rule Two
id: a2345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field2: value2
    condition: selection
"""
    
    correlation_yaml = """
title: Rule ID Tracking Test
correlation:
    type: event_count
    rules:
        - 92345678-1234-1234-1234-123456789abc
        - a2345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 1m
    condition:
        gte: 2
"""
    
    collection = SigmaCollection.from_yaml(rules_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mappings on referenced rules so they pass validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    collection.rules[1].custom_attributes['table'] = 'test_table'
    
    result = backend.convert(collection, output_format="default")
    correlation_query = result[-1]
    
    # Verify rule_id columns are added
    assert "'Rule One' as rule_id" in correlation_query or "'92345678-1234-1234-1234-123456789abc' as rule_id" in correlation_query
    assert "'Rule Two' as rule_id" in correlation_query or "'a2345678-1234-1234-1234-123456789abc' as rule_id" in correlation_query


def test_custom_time_column():
    """Test that custom time_column is used in correlation queries"""
    backend = DatabricksBackend(time_column="event_time")
    
    rule_yaml = """
title: Test Rule Custom Time
id: b2345678-1234-1234-1234-123456789abc
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""
    
    correlation_yaml = """
title: Custom Time Column Test
correlation:
    type: event_count
    rules:
        - b2345678-1234-1234-1234-123456789abc
    group-by:
        - user
    timespan: 5m
    condition:
        gte: 3
"""
    
    collection = SigmaCollection.from_yaml(rule_yaml + "\n---\n" + correlation_yaml)
    
    # Set table mapping on referenced rule so it passes validation
    collection.rules[0].custom_attributes['table'] = 'test_table'
    
    result = backend.convert(collection)
    correlation_query = result[-1]
    
    # Verify custom time column is used
    assert "ORDER BY event_time" in correlation_query

