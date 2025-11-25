"""
Tests for unmapped field export functionality.
"""
import yaml
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock
from fieldmapper.ocsf.rules import (
    SigmaRuleOCSFLite, 
    DetectionFieldMapping, 
    OCSFLite
)
from fieldmapper.ocsf.export_utils import export_rule_to_file


class TestUnmappedFieldExport:
    """Test that unmapped fields export correctly as '<UNMAPPED>' string."""
    
    def _create_test_rule_with_unmapped(self):
        """Create a test rule with both mapped and unmapped fields."""
        rule = Mock(spec=SigmaRuleOCSFLite)
        rule.id = "test-id"
        rule.title = "Test Rule"
        rule.status = "test"
        rule.level = "medium"
        
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
    
    def test_unmapped_field_full_export(self):
        """Test that unmapped fields export as '<UNMAPPED>' in full mode."""
        rule = self._create_test_rule_with_unmapped()
        
        export_dict = rule.to_export_dict(full=True)
        
        # Check the OCSF mapping section
        ocsf_mapping = export_dict['ocsf_mapping']
        detection_fields = ocsf_mapping['detection_fields']
        
        # Find the unmapped field
        unmapped_field = None
        for field in detection_fields:
            if field['source_field'] == 'UnknownField':
                unmapped_field = field
                break
        
        assert unmapped_field is not None
        assert unmapped_field['target_field'] == "<UNMAPPED>"
        assert unmapped_field['target_table'] == "process_activity"
        assert unmapped_field['mapped_at'] == "2025-01-01T00:00:00Z"
    
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

