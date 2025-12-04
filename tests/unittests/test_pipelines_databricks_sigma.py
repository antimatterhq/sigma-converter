from sigma.backends.databricks import DatabricksBackend
from sigma.collection import SigmaCollection


# Test case-sensitive string matching
def test_case_sensitive_match():
    yaml_str = """
        title: Case Sensitive Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                field|cased: SensitiveValue
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    assert "field = 'SensitiveValue'" in result[0]
    assert "lower(" not in result[0] or "LOWER(" not in result[0]


# Test case-insensitive string matching (default)
def test_case_insensitive_match():
    yaml_str = """
        title: Case Insensitive Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                field: value
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    assert "lower(field) = lower('value')" in result[0] or "lower(`field`) = lower('value')" in result[0]


# Test case-insensitive startswith (using Databricks startswith function)
def test_case_insensitive_startswith():
    yaml_str = """
        title: Startswith Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                field|startswith: 'prefix'
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    # Should use startswith function with lower()
    assert "startswith(lower(" in result[0]


# Test case-insensitive contains (using Databricks contains function)
def test_case_insensitive_contains():
    yaml_str = """
        title: Contains Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                field|contains: 'middle'
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    # Should use contains function with lower()
    assert "contains(lower(" in result[0]


# Test OR-to-IN optimization
def test_or_to_in_optimization():
    yaml_str = """
        title: OR to IN Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                field:
                    - value1
                    - value2
                    - value3
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    # Should use IN clause instead of multiple ORs
    assert " in (" in result[0].lower()
    assert "'value1'" in result[0]
    assert "'value2'" in result[0]
    assert "'value3'" in result[0]


# Test default to SELECT * when no fields specified
def test_default_select_all():
    yaml_str = """
        title: No Fields Test
        status: test
        logsource:
            product: windows
            service: security
        detection:
            sel:
                EventID: 4624
            condition: sel
    """
    backend = DatabricksBackend()
    result = backend.convert(SigmaCollection.from_yaml(yaml_str))
    # Should default to SELECT *
    assert "SELECT * FROM" in result[0]
