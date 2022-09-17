import pytest
from sigma.collection import SigmaCollection
from sigma.backends.databricks import DatabricksBackend

@pytest.fixture
def databricks_sigma_backend():
    return DatabricksBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_databricks_sigma_and_expression(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
        """)
    ) == ["fieldA='valueA' AND fieldB='valueB'"]

def test_databricks_sigma_or_expression(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["fieldA='valueA' OR fieldB='valueB'"]

def test_databricks_sigma_and_or_expression(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["(fieldA in ('valueA1', 'valueA2')) AND (fieldB in ('valueB1', 'valueB2'))"]

def test_databricks_sigma_or_and_expression(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["fieldA='valueA1' AND fieldB='valueB1' OR fieldA='valueA2' AND fieldB='valueB2'"]

def test_databricks_sigma_in_expression(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["fieldA='valueA' OR fieldA='valueB' OR startswith(fieldA, 'valueC')"]

def test_databricks_sigma_regex_query(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["fieldA rlike 'foo.*bar' AND fieldB='foo'"]

def test_databricks_sigma_cidr_query(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['cidrmatch(field, 192.168.0.0/16)']

def test_databricks_sigma_field_name_with_whitespace(databricks_sigma_backend : DatabricksBackend):
    assert databricks_sigma_backend.convert(
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
    ) == ["`field name`='value'"]

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.



def test_databricks_sigma_format1_output(databricks_sigma_backend : DatabricksBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass

def test_databricks_sigma_format2_output(databricks_sigma_backend : DatabricksBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass


