"""Tests for rule conversion with lakewatch pipeline and Databricks backend."""

from sigma.collection import SigmaCollection
from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.lakewatch import lakewatch_pipeline

# Inline YAML strings for fast testing
SIMPLE_RULE = """
title: Simple Test Rule
id: 12345678-1234-1234-1234-123456789012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test.exe'
    condition: selection
"""

RULE_WITH_MODIFIERS = """
title: Rule with Modifiers
id: 23456789-2345-2345-2345-234567890123
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '.exe'
        CommandLine|contains: 'suspicious'
    condition: selection
"""

PROCESS_CREATION_RULE = """
title: Process Creation Test
id: 12345678-1234-1234-1234-123456789012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test.exe'
        Image|endswith: '.exe'
    condition: selection
"""


def test_single_rule_conversion_from_file():
    """Test converting a single Sigma rule file using lakewatch pipeline."""
    from sigma.rule import SigmaRule
    
    # Load a single rule from the original rules directory
    # Use SigmaRule.from_yaml() for original Sigma rules (not SigmaRuleOCSFLite.load())
    with open("rules/network/zeek/zeek_http_webdav_put_request.yml", 'r') as f:
        rule = SigmaRule.from_yaml(f.read())
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert_rule(rule)
    
    # Should get at least one query back
    assert len(queries) > 0
    assert isinstance(queries[0], str)
    
    print(f"Converted 1 rule into {len(queries)} query/queries")
    print(f"Query: {queries[0]}")


def test_multiple_rules_conversion():
    """Test converting multiple rules from inline YAML."""
    # Create collection from inline YAML (much faster than file I/O)
    sigma_rules = SigmaCollection.from_yaml(SIMPLE_RULE)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the collection
    queries = backend.convert(sigma_rules)
    
    # Should get queries back
    assert len(queries) > 0
    assert all(isinstance(q, str) for q in queries)
    
    print(f"Converted {len(sigma_rules.rules)} rule(s) into {len(queries)} query/queries")


def test_rule_with_yaml_output():
    """Test YAML output format for Databricks backend."""
    # Use inline YAML for speed
    sigma_rules = SigmaCollection.from_yaml(SIMPLE_RULE)
    
    # Initialize backend with lakewatch pipeline and YAML output format
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert using default format
    queries = backend.convert(sigma_rules, output_format="default")
    
    assert len(queries) > 0
    print(f"YAML Output: {queries[0]}")


def test_simple_rule_with_exact_matches():
    """Test rule conversion with exact value matches (no wildcards)."""
    rule_yaml = """
title: Exact Match Test
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'notepad.exe'
        User: 'admin'
    condition: selection
"""
    
    sigma_rules = SigmaCollection.from_yaml(rule_yaml)
    backend = DatabricksBackend(lakewatch_pipeline())
    queries = backend.convert(sigma_rules)
    
    assert len(queries) > 0
    query = queries[0]
    
    # Should use = operator for exact matches and time BETWEEN clause
    # lowercase comparison used for case-insensitive matching
    assert "lower(" in query and "= lower(" in query
    assert "time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24 HOUR AND CURRENT_TIMESTAMP() AND (" in query
    print(f"Query with exact matches: {query}")


def test_rule_with_modifiers():
    """Test rule conversion with Sigma field modifiers."""
    # Use inline YAML with modifiers
    sigma_rules = SigmaCollection.from_yaml(RULE_WITH_MODIFIERS)
    backend = DatabricksBackend(lakewatch_pipeline())
    queries = backend.convert(sigma_rules)
    
    assert len(queries) > 0
    query = queries[0]
    
    # Should use Databricks functions for modifiers and time BETWEEN clause
    # |endswith -> endswith()
    # |contains -> contains()
    assert "endswith(" in query or "contains(" in query
    assert "time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24 HOUR AND CURRENT_TIMESTAMP() AND (" in query
    print(f"Query with modifiers:\n{query}")


def test_rule_with_table_attribute():
    """Test that table custom attribute is correctly set by the pipeline."""
    # Create collection from inline YAML
    sigma_rules = SigmaCollection.from_yaml(PROCESS_CREATION_RULE)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(sigma_rules)
    
    # Check custom attributes
    rule = sigma_rules.rules[0]
    print("Custom Attributes:")
    print("-" * 80)
    if hasattr(rule, 'custom_attributes') and rule.custom_attributes:
        for attr_name, attr_value in rule.custom_attributes.items():
            print(f"  {attr_name}: {attr_value}")
        
        # Assertions
        assert 'table' in rule.custom_attributes, "Table attribute should be set"
        table_value = rule.custom_attributes['table']
        
        # process_creation category should map to process_activity
        assert table_value == 'process_activity', \
            f"Expected table='process_activity', got '{table_value}'"
        
        print(f"\n✓ Table attribute correctly set to '{table_value}'!\n")
    else:
        print("  No custom attributes found")
        assert False, "Custom attributes should be set by pipeline"
    print("-" * 80)


def test_rule_with_activity_id_in_where_clause():
    """Test that activity_id is added to SQL WHERE clause via AddConditionTransformation."""
    # Use inline YAML to create a complete rule
    rule_yaml = """
title: Test Rule with Activity ID
id: e20b5b14-ce93-4230-88af-981983ef6e74
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\QuickAssist.exe'
    condition: selection
"""
    
    # Create collection from inline YAML
    sigma_rules = SigmaCollection.from_yaml(rule_yaml)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(sigma_rules)
    
    # Should have at least one query
    assert len(queries) > 0, "Should have generated at least one query"
    
    query = queries[0]
    
    # Verify activity_id = 1 appears in WHERE clause
    # The backend adds case-insensitive comparison: lower(activity_id) = lower('1')
    assert "activity_id" in query and "'1'" in query, \
        f"Expected activity_id condition in query:\n{query}"
    
    # More specifically, check for the exact format
    assert "lower(activity_id) = lower('1')" in query or \
           'lower(activity_id) = lower("1")' in query, \
        f"Expected lowercase activity_id condition in query:\n{query}"
    
    # Verify time BETWEEN clause
    assert "time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24 HOUR AND CURRENT_TIMESTAMP() AND (" in query
    
    print(f"\n✓ Query contains activity_id = '1' condition:\n{query}")


def test_rule_with_config_attributes():
    """Test that configuration custom attributes are correctly set by the pipeline."""
    sigma_rules = SigmaCollection.from_yaml(SIMPLE_RULE)
    backend = DatabricksBackend(lakewatch_pipeline())
    backend.convert(sigma_rules)
    
    rule = sigma_rules.rules[0]
    
    # Verify all config attributes are set
    assert 'time_column' in rule.custom_attributes
    assert rule.custom_attributes['time_column'] == 'time'
    
    assert 'catalog' in rule.custom_attributes
    assert rule.custom_attributes['catalog'] == 'lakewatch'
    
    assert 'schema' in rule.custom_attributes
    assert rule.custom_attributes['schema'] == 'gold'
    
    print(f"\n✓ Configuration attributes set:")
    print(f"  time_column: {rule.custom_attributes['time_column']}")
    print(f"  catalog: {rule.custom_attributes['catalog']}")
    print(f"  schema: {rule.custom_attributes['schema']}")


def test_backend_config_overrides():
    """Test that backend can override configuration via kwargs."""
    # Test with defaults
    backend_default = DatabricksBackend(lakewatch_pipeline())
    assert backend_default.time_column == "time"
    assert backend_default.catalog == "lakewatch"
    assert backend_default.schema == "gold"
    assert backend_default.time_filter == "24 HOUR"
    
    # Test with overrides
    backend_custom = DatabricksBackend(
        lakewatch_pipeline(), 
        time_column="event_timestamp",
        catalog="my_catalog",
        schema="silver",
        time_filter="1 HOUR"
    )
    assert backend_custom.time_column == "event_timestamp"
    assert backend_custom.catalog == "my_catalog"
    assert backend_custom.schema == "silver"
    assert backend_custom.time_filter == "1 HOUR"
    

    
    print(f"\n✓ Default configuration:")
    print(f"  time_column: {backend_default.time_column}")
    print(f"  catalog: {backend_default.catalog}")
    print(f"  schema: {backend_default.schema}")
    print(f"  time_filter: {backend_default.time_filter}")
    print(f"\n✓ Override configuration:")
    print(f"  time_column: {backend_custom.time_column}")
    print(f"  catalog: {backend_custom.catalog}")
    print(f"  schema: {backend_custom.schema}")
    print(f"  time_filter: {backend_custom.time_filter}")


def test_rule_with_time_filter_enabled():
    """Test that time filtering is applied when time_filter is set."""
    sigma_rules = SigmaCollection.from_yaml(SIMPLE_RULE)
    backend = DatabricksBackend(lakewatch_pipeline(), time_filter="24 HOUR")
    queries = backend.convert(sigma_rules)
    
    query = queries[0]
    
    # Verify BETWEEN syntax present
    assert "time BETWEEN" in query
    assert "CURRENT_TIMESTAMP() - INTERVAL 24 HOUR" in query
    assert "AND CURRENT_TIMESTAMP()" in query
    
    # Verify detection logic is wrapped in parentheses
    assert "AND (" in query and query.count("(") >= 2
    
    print(f"\n✓ Time filter applied:\n{query}")


def test_rule_with_custom_time_window():
    """Test custom time windows (minutes, days)."""
    sigma_rules = SigmaCollection.from_yaml(SIMPLE_RULE)
    
    # Test 30 minute window
    backend_30min = DatabricksBackend(lakewatch_pipeline(), time_filter="30 MINUTE")
    query_30min = backend_30min.convert(sigma_rules)[0]
    assert "INTERVAL 30 MINUTE" in query_30min
    
    # Test 7 day window
    backend_7day = DatabricksBackend(lakewatch_pipeline(), time_filter="7 DAY")
    query_7day = backend_7day.convert(sigma_rules)[0]
    assert "INTERVAL 7 DAY" in query_7day
    
    print(f"\n✓ Custom time windows working:")
    print(f"  30 MINUTE: {query_30min[:100]}...")
    print(f"  7 DAY: {query_7day[:100]}...")
