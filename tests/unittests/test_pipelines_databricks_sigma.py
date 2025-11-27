from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.databricks import snake_case
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

YAML_STR = """
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    EventID: 123
                    Image: test.exe
                    TestField: test
                condition: sel
            fields:
                - EventID
                - TestField
        """


def test_snake_case_fields_conversion():
    rule = snake_case().apply(SigmaRule.from_yaml(YAML_STR))
    assert rule.fields == ["event_id", "test_field"]


def test_snake_case_detection_conversion():
    rule = DatabricksBackend(snake_case()).convert(
        SigmaCollection.from_yaml(YAML_STR))
    assert rule == ["SELECT * FROM lakewatch.gold.<UNMAPPED_TABLE> WHERE time BETWEEN CURRENT_TIMESTAMP() - INTERVAL 24 HOUR AND CURRENT_TIMESTAMP() AND (event_id = 123 AND lower(image) = lower('test.exe') AND lower(test_field) = lower('test'))"]
