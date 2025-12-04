from sigma.collection import SigmaCollection
from sigma.backends.databricks.lakewatch_rule import (
    Rule, build_objective_from_sigma_metadata
)


def test_build_objective_with_all_metadata():
    """Test objective building with fields, falsepositives, and references."""
    rule_yaml = """
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
fields:
    - CommandLine
    - Image
    - User
falsepositives:
    - Administrative activity
    - Legitimate software updates
references:
    - https://example.com/article
    - https://attack.mitre.org/techniques/T1059/
level: high
    """
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    objective = build_objective_from_sigma_metadata(rule)
    
    assert objective is not None
    assert "Examine fields: CommandLine, Image, User" in objective
    assert "False positives:" in objective
    assert "1. Administrative activity" in objective
    assert "2. Legitimate software updates" in objective
    assert "References:" in objective
    assert "https://example.com/article" in objective


def test_build_objective_fields_only():
    """Test objective with only fields metadata."""
    rule_yaml = """
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
fields:
    - CommandLine
    - Image
level: high
    """
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    objective = build_objective_from_sigma_metadata(rule)
    
    assert objective == "Examine fields: CommandLine, Image"


def test_build_objective_no_metadata():
    """Test objective when no metadata present."""
    rule_yaml = """
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
level: high
    """
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    objective = build_objective_from_sigma_metadata(rule)
    
    assert objective is None


def test_from_sigma_rule_includes_objective():
    """Test that from_sigma_rule() includes objective in output."""
    rule_yaml = """
title: Test Detection Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: malicious.exe
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Legitimate use case
references:
    - https://example.com
level: high
    """
    collection = SigmaCollection.from_yaml(rule_yaml)
    rule = collection.rules[0]
    
    lakewatch_rule = Rule.from_sigma_rule(
        rule, 
        query="SELECT * FROM table WHERE CommandLine = 'malicious.exe'"
    )
    
    assert lakewatch_rule.spec.metadata.objective is not None
    assert "Examine fields: CommandLine" in lakewatch_rule.spec.metadata.objective
    assert "False positive: Legitimate use case" in lakewatch_rule.spec.metadata.objective
    assert "Reference: https://example.com" in lakewatch_rule.spec.metadata.objective

