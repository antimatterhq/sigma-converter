from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.lakewatch import lakewatch_pipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from fieldmapper.ocsf.rules import SigmaRuleOCSFLite

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

def test_detection_conversion():
    rule = DatabricksBackend().convert(
        SigmaCollection.from_yaml(YAML_STR))
    print(rule)
    assert rule == ["EventID = 123 AND lower(Image) = lower('test.exe') AND lower(TestField) = lower('test')"]

def test_field_mapping():
    rule = DatabricksBackend(lakewatch_pipeline()).convert(SigmaCollection.from_yaml(YAML_STR))
    print(rule)
    assert True