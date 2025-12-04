"""
Tests for unmapped field export functionality.
"""
from unittest.mock import Mock
from fieldmapper.ocsf.rules import (
    SigmaRuleOCSFLite, 
    DetectionFieldMapping, 
    OCSFLite
)

class TestUnmappedFieldExport:
    """Test that unmapped fields export correctly as '<UNMAPPED>' string."""
    
    def _create_test_rule_with_unmapped(self):
        """Create a test rule with both mapped and unmapped fields."""
        rule = Mock(spec=SigmaRuleOCSFLite)
        rule.id = "test-id"
        rule.title = "Test Rule"
        rule.name = None 
        rule.author = None  
        rule.status = "test"
        rule.level = "medium"
        rule.description = None  
        rule.fields = [] 
        rule.falsepositives = [] 
        rule.references = [] 
        rule.tags = [] 
        rule.date = None 
        rule.modified = None 
        rule.custom_attributes = {} 
        
        # Mock logsource
        rule.logsource = Mock()
        rule.logsource.category = "process_creation"
        rule.logsource.product = "windows"
        rule.logsource.service = None
        
        # Mock detection
        rule.detection = Mock()
        
        # Set up OCSF mapping
        rule.ocsflite = OCSFLite(
            class_name="process_activity",
            detection_fields=[
                DetectionFieldMapping(
                    source_field="CommandLine",
                    target_table="process_activity",
                    target_field="process.cmd_line",
                    mapped_at="2025-01-01T00:00:00Z"
                ),
                DetectionFieldMapping(
                    source_field="UnknownField",
                    target_table="process_activity",
                    target_field="<UNMAPPED>",
                    mapped_at="2025-01-01T00:00:00Z"
                ),
            ]
        )
        
        # Bind the real to_export_dict method
        rule.to_export_dict = lambda full=False: SigmaRuleOCSFLite.to_export_dict(rule, full=full)
        
        return rule
    
    def test_unmapped_field_stored_as_string(self):
        """Test that unmapped fields store '<UNMAPPED>' as a string."""
        rule = self._create_test_rule_with_unmapped()
        
        unmapped_mapping = rule.ocsflite.detection_fields[1]
        
        assert unmapped_mapping.target_field == "<UNMAPPED>"
        assert isinstance(unmapped_mapping.target_field, str)
        assert unmapped_mapping.target_table == "process_activity"
    
    
    def test_unmapped_field_default_export(self):
        """Test that unmapped fields export as '<UNMAPPED>' in default mode."""
        rule = self._create_test_rule_with_unmapped()
        
        export_dict = rule.to_export_dict(full=False)
        
        field_mappings = export_dict['field_mappings']
        
        # Mapped field should have table.field format
        assert field_mappings['CommandLine'] == "process_activity.process.cmd_line"
        
        # Unmapped field should be '<UNMAPPED>' string
        assert field_mappings['UnknownField'] == "<UNMAPPED>"
        assert isinstance(field_mappings['UnknownField'], str)
    
    def test_multiple_unmapped_fields(self):
        """Test handling of multiple unmapped fields."""
        rule = Mock(spec=SigmaRuleOCSFLite)
        rule.id = "test-multiple-unmapped"
        rule.title = "Test Multiple Unmapped"
        rule.name = None  
        rule.author = None  
        rule.status = "test"
        rule.level = "medium"
        rule.description = None
        rule.fields = []
        rule.falsepositives = []
        rule.references = []
        rule.tags = []
        rule.date = None
        rule.modified = None
        rule.custom_attributes = {}
        rule.ocsflite = OCSFLite(
            class_name="network_activity",
            detection_fields=[
                DetectionFieldMapping(
                    source_field="Field1",
                    target_table="network_activity",
                    target_field="<UNMAPPED>",
                    mapped_at="2025-01-01T00:00:00Z"
                ),
                DetectionFieldMapping(
                    source_field="Field2",
                    target_table="network_activity",
                    target_field="<UNMAPPED>",
                    mapped_at="2025-01-01T00:00:00Z"
                ),
                DetectionFieldMapping(
                    source_field="SourceIp",
                    target_table="network_activity",
                    target_field="src_endpoint.ip",
                    mapped_at="2025-01-01T00:00:00Z"
                ),
            ]
        )
        
        # Bind the real to_export_dict method
        rule.to_export_dict = lambda full=False: SigmaRuleOCSFLite.to_export_dict(rule, full=full)
        
        export_dict = rule.to_export_dict(full=False)
        field_mappings = export_dict['field_mappings']
        
        assert field_mappings['Field1'] == "<UNMAPPED>"
        assert field_mappings['Field2'] == "<UNMAPPED>"
        assert field_mappings['SourceIp'] == "network_activity.src_endpoint.ip"

