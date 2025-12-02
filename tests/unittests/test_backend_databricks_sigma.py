import pytest
from sigma.collection import SigmaCollection
from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.sql_validator import verify_databricks_sql


@pytest.fixture
def databricks_sigma_backend():
    return DatabricksBackend()


@pytest.fixture
def databricks_sigma_backend_no_validation():
    """Backend with validation mocked out for SQL generation testing."""
    backend = DatabricksBackend()
    
    def mock_convert(rule, output_format=None, **kwargs):
        # Call the grandparent's convert (TextQueryBackend) to bypass our validation
        from sigma.conversion.base import TextQueryBackend
        return TextQueryBackend.convert(backend, rule, output_format, **kwargs)
    
    backend.convert = mock_convert
    return backend

def test_databricks_sql_validation():
    # passed on valid SQL
    sql_1 = """SELECT * FROM test WHERE event_id = 123 AND lower(image) = lower('test.exe') AND lower(test_field) = lower('test')"""

    assert len(verify_databricks_sql(sql_1)) == 0

    # fails when passed invalid function name
    sql_invalid_function = """SELECT * \
               FROM test \
               WHERE event_id = 123 \
                 AND lowerx(image) = lower('test.exe') \
                 AND lower(test_field) = lower('test')"""

    assert len(verify_databricks_sql(sql_invalid_function)) > 0

    # passed on partial SQL
    sql_partial = """event_id = 123 AND lower(image) = lower('test.exe') AND lower(test_field) = lower('test')"""

    assert len(verify_databricks_sql(sql_partial)) == 0

    # passed on partial SQL
    sql_partial_invalid = """event_id = 123 AND lowerxxx(image) = lower('test.exe') AND lower(test_field) = lower('test')"""

    assert len(verify_databricks_sql(sql_partial_invalid)) > 0


def test_databricks_sigma_and_expression(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """),
        output_format="default"
    ) == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(fieldA) = lower('valuea') AND lower(fieldB) = lower('valueb'))"]


def test_databricks_sigma_or_expression(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(fieldA) = lower('valuea') OR lower(fieldB) = lower('valueb'))"]


def test_databricks_sigma_match_with_dot_string(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value.A
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(fieldA) = lower('value.a') OR lower(fieldB) = lower('valueb'))"]


def test_databricks_sigma_and_or_expression(databricks_sigma_backend_no_validation: DatabricksBackend):
    # Note: OR-to-IN optimization is enabled, so this converts to IN expressions
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND ((lower(LOWER(fieldA)) in ('valuea1', 'valuea2')) AND "
          "(lower(LOWER(fieldB)) in ('valueb1', 'valueb2')))"]


def test_databricks_sigma_or_and_expression(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(fieldA) = lower('valuea1') AND lower(fieldB) = lower('valueb1') OR lower(fieldA) = lower('valuea2') "
          "AND lower(fieldB) = lower('valueb2'))"]


def test_databricks_sigma_in_expression(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(fieldA) = lower('valuea') OR lower(fieldA) = lower('valueb') OR "
          "startswith(lower(fieldA), lower('valuec')))"]


def test_databricks_sigma_regex_query(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (fieldA rlike 'foo.*bar' AND lower(fieldB) = lower('foo'))"]


def test_databricks_sigma_regex_query_flags(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re|i: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (fieldA rlike '(?i)foo.*bar' AND lower(fieldB) = lower('foo'))"]


def test_databricks_sigma_field_name_with_whitespace(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(`field name`) = lower('value'))"]


def test_databricks_sigma_field_name_with_period(databricks_sigma_backend_no_validation: DatabricksBackend):
    assert databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    responseElements.publiclyAccessible:
                        - value1
                condition: sel
        """)
    , output_format="default") == ["SELECT * FROM None WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24h AND CURRENT_TIMESTAMP() AND (lower(responseElements.publiclyAccessible) = lower('value1'))"]


# CIDR matching tests

def test_databricks_cidr_slash_8(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR match for /8 subnet (Class A network)."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    IpAddress|cidr: 10.0.0.0/8
                condition: sel
        """)
    , output_format="default")
    # Network: 10.0.0.0 = 167772160, Mask: 0xFF000000 = 4278190080
    assert "& 4278190080) = 167772160 /* CIDR: 10.0.0.0/8 */" in result[0]
    assert "CAST(split(IpAddress, '\\\\.')[0] AS BIGINT)" in result[0]


def test_databricks_cidr_slash_24(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR match for /24 subnet (Class C network)."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    IpAddress|cidr: 192.168.1.0/24
                condition: sel
        """)
    , output_format="default")
    # Network: 192.168.1.0 = 3232235776, Mask: 0xFFFFFF00 = 4294967040
    assert "& 4294967040) = 3232235776 /* CIDR: 192.168.1.0/24 */" in result[0]


def test_databricks_cidr_slash_32(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR match for /32 (single host)."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    IpAddress|cidr: 127.0.0.1/32
                condition: sel
        """)
    , output_format="default")
    # Network: 127.0.0.1 = 2130706433, Mask: 0xFFFFFFFF = 4294967295
    assert "& 4294967295) = 2130706433 /* CIDR: 127.0.0.1/32 */" in result[0]


def test_databricks_cidr_multiple_values(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR match with multiple CIDR values (OR logic)."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    IpAddress|cidr:
                        - 10.0.0.0/8
                        - 172.16.0.0/12
                        - 192.168.0.0/16
                condition: sel
        """)
    , output_format="default")
    # Should contain OR-connected comparisons
    assert " OR " in result[0]
    # Check for all three networks
    assert "167772160" in result[0]  # 10.0.0.0
    assert "2886729728" in result[0]  # 172.16.0.0
    assert "3232235520" in result[0]  # 192.168.0.0


def test_databricks_cidr_private_ranges(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR with all RFC1918 private IP ranges."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                filter:
                    SourceIp|cidr:
                        - 10.0.0.0/8
                        - 172.16.0.0/12
                        - 192.168.0.0/16
                        - 127.0.0.0/8
                condition: not filter
        """)
    , output_format="default")
    # Should contain multiple OR conditions
    assert result[0].count(" OR ") == 3  # 4 conditions = 3 ORs
    assert "NOT (" in result[0]


def test_databricks_cidr_slash_0(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test CIDR match for /0 (all IPs)."""
    result = databricks_sigma_backend_no_validation.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    IpAddress|cidr: 0.0.0.0/0
                condition: sel
        """)
    , output_format="default")
    # Network: 0.0.0.0 = 0, Mask: 0x00000000 = 0
    assert "& 0) = 0 /* CIDR: 0.0.0.0/0 */" in result[0]


def test_databricks_cidr_ipv6_rejection(databricks_sigma_backend_no_validation: DatabricksBackend):
    """Test that IPv6 CIDR raises NotImplementedError."""
    with pytest.raises(NotImplementedError, match="IPv6 CIDR matching is not supported"):
        databricks_sigma_backend_no_validation.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        IpAddress|cidr: fe80::/10
                    condition: sel
            """)
        , output_format="default")


def test_databricks_cidr_invalid_prefix_length(databricks_sigma_backend: DatabricksBackend):
    """Test that invalid prefix length raises error during parsing."""
    # Note: Invalid CIDR is caught during YAML parsing by pySigma, not during conversion
    from sigma.exceptions import SigmaTypeError
    with pytest.raises(SigmaTypeError, match="Invalid CIDR expression"):
        databricks_sigma_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        IpAddress|cidr: 192.168.1.0/33
                    condition: sel
            """)
        , output_format="default")


def test_backend_validation_skips_unmapped_table(databricks_sigma_backend: DatabricksBackend):
    """Test that backend skips rules without table mappings."""
    rule_yaml = """
    title: Unmapped Rule
    id: 12345678-1234-1234-1234-123456789abc
    logsource:
        product: unknown_product
        service: unknown_service
    detection:
        selection:
            field: value
        condition: selection
    """
    
    collection = SigmaCollection.from_yaml(rule_yaml)
    
    # Should return summary message (no warnings emitted)
    result = databricks_sigma_backend.convert(collection)
    
    assert len(result) == 1
    assert "Validation Summary" in result[0]
    assert "All 1 rule(s) skipped" in result[0]


def test_backend_validation_accepts_valid_table(databricks_sigma_backend: DatabricksBackend):
    """Test that backend accepts rules with valid table mappings."""
    rule_yaml = """
    title: Valid Rule
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
    
    # Manually set valid table
    rule.custom_attributes['table'] = 'process_activity'
    
    # Should convert without warnings
    result = databricks_sigma_backend.convert(collection)
    
    # Should generate SQL
    assert len(result) == 1
    assert "process_activity" in result[0]


def test_backend_validation_mixed_collection(databricks_sigma_backend: DatabricksBackend):
    """Test that backend converts only valid rules from mixed collection."""
    # Create two rules - one valid, one invalid
    yaml_content = """
title: Valid Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: test
detection:
    selection:
        field: value
    condition: selection
---
title: Invalid Rule
id: 87654321-4321-4321-4321-cba987654321
logsource:
    product: unknown
detection:
    selection:
        field: value
    condition: selection
"""
    
    collection = SigmaCollection.from_yaml(yaml_content)
    
    # Set valid table on first rule only
    collection.rules[0].custom_attributes['table'] = 'process_activity'
    
    # Should convert the valid one (no warnings emitted)
    result = databricks_sigma_backend.convert(collection)
    
    # Only one rule should be converted
    assert len(result) == 1
    assert "process_activity" in result[0]


def test_backend_validation_correlation_with_unmapped_reference(databricks_sigma_backend: DatabricksBackend):
    """Test that correlation rules with unmapped references fail appropriately."""
    yaml_content = """
title: Unmapped Detection
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: unknown_product
detection:
    selection:
        field: value
    condition: selection
---
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
    
    collection = SigmaCollection.from_yaml(yaml_content)
    
    # The detection rule has no table mapping, so it will be filtered out.
    # When the correlation rule tries to resolve references, it will fail
    # because the referenced rule is no longer in the collection.
    from sigma.exceptions import SigmaRuleNotFoundError
    
    # No warnings emitted, but should raise error about missing rule
    with pytest.raises(SigmaRuleNotFoundError, match="Rule '12345678-1234-1234-1234-123456789abc' not found"):
        result = databricks_sigma_backend.convert(collection)


def test_sql_validation_valid_sql(databricks_sigma_backend: DatabricksBackend):
    """Test that valid SQL passes through without SQL validation warnings."""
    rule_yaml = """
    title: Valid SQL Rule
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
    rule.custom_attributes['table'] = 'process_activity'
    
    # Should convert without SQL validation warnings (only OCSF mapping validation if any)
    result = databricks_sigma_backend.convert(collection, output_format="default")
    
    # Should generate valid SQL
    assert len(result) == 1
    assert "process_activity" in result[0]
    assert "SELECT" in result[0]


def test_sql_validation_only_default_format(databricks_sigma_backend: DatabricksBackend):
    """Test that SQL validation only runs for 'default' format, not 'lakewatch'."""
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
    rule.custom_attributes['table'] = 'process_activity'
    
    # Convert with lakewatch format - should not validate SQL
    # (No SQL validation warnings expected, only format-specific processing)
    result = databricks_sigma_backend.convert(collection, output_format="lakewatch")
    
    # Should return JSON format
    assert len(result) == 1
    # Lakewatch format returns JSON strings
    assert isinstance(result[0], str)
    # Should contain JSON structure indicators for lakewatch format
    assert '"name"' in result[0] or '"metadata"' in result[0]


