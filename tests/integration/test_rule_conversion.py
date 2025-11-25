"""
Test file for converting Sigma rules using DatabricksBackend and lakewatch_pipeline.
All tests use inline YAML for speed and reliability.
"""

from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.lakewatch import lakewatch_pipeline
from sigma.collection import SigmaCollection


# Sample Sigma rules as YAML strings
PROCESS_CREATION_RULE = """
title: CrackMapExec Execution Test
id: 48d91a3a-2363-43ba-a456-ca71ac3da5c2
status: test
description: Test rule for process creation with modifiers
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\crackmapexec.exe'
        CommandLine|contains:
            - ' -M pe_inject '
            - ' -o LHOST='
    condition: selection
level: high
"""

SIMPLE_PROCESS_RULE = """
title: Simple Process Rule
id: 11111111-1111-1111-1111-111111111111
status: test
description: Simple test rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        Image: C:\\Windows\\System32\\cmd.exe
    condition: selection
"""

NETWORK_CONNECTION_RULE = """
title: Network Connection Test
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 443
        DestinationIp: 192.168.1.1
    condition: selection
"""


def test_single_rule_conversion_from_file():
    """
    Test converting a single Sigma rule using DatabricksBackend with lakewatch_pipeline.
    Uses inline YAML for reliability and speed.
    """
    print(f"\n{'='*80}")
    print(f"Testing rule: CrackMapExec Execution Test")
    print(f"Rule ID: 48d91a3a-2363-43ba-a456-ca71ac3da5c2")
    print(f"{'='*80}\n")
    
    # Create SigmaCollection from inline YAML
    collection = SigmaCollection.from_yaml(PROCESS_CREATION_RULE)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(collection)
    
    # Display custom attributes set by the pipeline
    print(f"\nCustom Attributes Set by Pipeline:")
    print("-" * 80)
    for rule in collection.rules:
        if hasattr(rule, 'custom_attributes') and rule.custom_attributes:
            for attr_name, attr_value in rule.custom_attributes.items():
                print(f"  {attr_name}: {attr_value}")
        else:
            print("  No custom attributes found")
    print("-" * 80)
    
    # Display the converted queries
    print(f"\nNumber of queries generated: {len(queries)}")
    print(f"\nConverted SQL query:")
    print("-" * 80)
    for idx, query in enumerate(queries, 1):
        print(f"Query {idx}:")
        print(query)
        print("-" * 80)
    
    # Basic assertions
    assert len(queries) > 0, "No queries were generated"
    assert all(isinstance(q, str) for q in queries), "All queries should be strings"
    
    # Check that the query contains SQL-like syntax
    for query in queries:
        assert len(query) > 0, "Query should not be empty"
    
    print("\n✓ Test passed successfully!\n")
    

def test_multiple_rules_conversion():
    """
    Test converting multiple rules in a batch.
    Uses inline YAML for reliability and speed.
    """
    # Define 3 test rules inline
    test_rules = [
        ("CrackMapExec Execution Test", PROCESS_CREATION_RULE),
        ("Simple Process Rule", SIMPLE_PROCESS_RULE),
        ("Network Connection Test", NETWORK_CONNECTION_RULE)
    ]
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    print(f"\n{'='*80}")
    print(f"Testing conversion of {len(test_rules)} rules")
    print(f"{'='*80}\n")
    
    for rule_name, rule_yaml in test_rules:
        print(f"Converting: {rule_name}")
        
        # Create collection and convert
        collection = SigmaCollection.from_yaml(rule_yaml)
        queries = backend.convert(collection)
        
        print(f"  → Generated {len(queries)} query/queries")
        
        # Basic assertions
        assert len(queries) > 0, f"No queries generated for {rule_name}"
        
    print(f"\n✓ Successfully converted {len(test_rules)} rules!\n")


def test_rule_with_yaml_output():
    """
    Test converting a rule and outputting in detection YAML format.
    Uses inline YAML for reliability and speed.
    """
    # Create collection from inline YAML
    sigma_rules = SigmaCollection.from_yaml(PROCESS_CREATION_RULE)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(sigma_rules)
    
    # Generate detection YAML output
    final_queries = [
        backend.finalize_query_detection_yaml(rule, query, idx, None)
        for idx, (rule, query) in enumerate(zip(sigma_rules.rules, queries))
    ]
    
    yaml_output = backend.finalize_output_detection_yaml(final_queries)
    
    print(f"\n{'='*80}")
    print("Detection YAML Output:")
    print(f"{'='*80}")
    print(yaml_output)
    print(f"{'='*80}\n")
    
    # Assertions
    assert yaml_output is not None, "YAML output should not be None"
    assert len(yaml_output) > 0, "YAML output should not be empty"
    assert "detections:" in yaml_output, "YAML should contain detections section"
    
    print("✓ YAML output generated successfully!\n")


def test_rule_with_dbsql_output():
    """
    Test converting a rule and outputting in Databricks SQL format.
    Uses inline YAML for reliability and speed.
    """
    # Create collection from inline YAML
    sigma_rules = SigmaCollection.from_yaml(PROCESS_CREATION_RULE)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(sigma_rules)
    
    # Generate Databricks SQL output
    final_queries = [
        backend.finalize_query_dbsql(rule, query, idx, None)
        for idx, (rule, query) in enumerate(zip(sigma_rules.rules, queries))
    ]
    
    sql_output = backend.finalize_output_dbsql(final_queries)
    
    print(f"\n{'='*80}")
    print("Databricks SQL Output:")
    print(f"{'='*80}")
    print(sql_output)
    print(f"{'='*80}\n")
    
    # Assertions
    assert sql_output is not None, "SQL output should not be None"
    assert len(sql_output) > 0, "SQL output should not be empty"
    
    print("✓ Databricks SQL output generated successfully!\n")


def test_simple_rule_with_exact_matches():
    """
    Test a simple rule with exact field matches (no modifiers)
    This should produce cleaner SQL with = operators
    """
    simple_yaml = """
title: Simple Test Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        EventID: 4688
        Image: C:\\Windows\\System32\\cmd.exe
        User: administrator
    condition: sel
"""
    
    print(f"\n{'='*80}")
    print("Testing simple rule with exact matches (no modifiers)")
    print(f"{'='*80}\n")
    
    # Create collection
    collection = SigmaCollection.from_yaml(simple_yaml)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(collection)
    
    # Display custom attributes
    print("Custom Attributes:")
    print("-" * 80)
    for rule in collection.rules:
        if hasattr(rule, 'custom_attributes') and rule.custom_attributes:
            for attr_name, attr_value in rule.custom_attributes.items():
                print(f"  {attr_name}: {attr_value}")
        else:
            print("  No custom attributes found")
    print("-" * 80)
    
    print("\nConverted SQL query:")
    print("-" * 80)
    for query in queries:
        print(query)
    print("-" * 80)
    
    # This should use simple = operators, not function calls
    assert len(queries) > 0
    assert "=" in queries[0], "Should contain equality operators"
    
    print("\n✓ Simple rule produces clean SQL with = operators!\n")


def test_rule_with_modifiers():
    """
    Test a rule with field modifiers like |contains and |endswith
    This produces function calls instead of simple equality
    """
    complex_yaml = """
title: Rule With Modifiers
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: sel
"""
    
    print(f"\n{'='*80}")
    print("Testing rule with field modifiers (|endswith, |contains)")
    print(f"{'='*80}\n")
    
    # Create collection
    collection = SigmaCollection.from_yaml(complex_yaml)
    
    # Initialize backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert the rule
    queries = backend.convert(collection)
    
    # Display custom attributes
    print("Custom Attributes:")
    print("-" * 80)
    for rule in collection.rules:
        if hasattr(rule, 'custom_attributes') and rule.custom_attributes:
            for attr_name, attr_value in rule.custom_attributes.items():
                print(f"  {attr_name}: {attr_value}")
        else:
            print("  No custom attributes found")
    print("-" * 80)
    
    print("\nConverted SQL query:")
    print("-" * 80)
    for query in queries:
        print(query)
    print("-" * 80)
    
    # This should use function calls
    assert len(queries) > 0
    assert "endswith(" in queries[0], "Should contain endswith() function"
    assert "contains(" in queries[0], "Should contain contains() function"
    
    print("\n✓ Rule with modifiers produces Databricks function calls!\n")


def test_rule_with_table_attribute():
    """
    Test that table attribute is set correctly by the pipeline.
    
    The lakewatch pipeline should automatically assign the correct OCSF
    table (event class) based on the rule's logsource and/or rule ID.
    Uses inline YAML for reliability and speed.
    """
    print(f"\n{'='*80}")
    print("Testing table attribute assignment")
    print(f"Rule: CrackMapExec Execution Test")
    print(f"{'='*80}\n")
    
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
