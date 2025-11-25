"""
Tests for export functionality.
"""
import json
import yaml
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock
from fieldmapper.ocsf.rules import (
    SigmaRuleOCSFLite, 
    FieldMapping, 
    LogSourceMapping, 
    DetectionFieldMapping, 
    OCSFLite
)
from fieldmapper.ocsf.export_utils import export_rule_to_file, export_rules


class TestDataclassToDict:
    """Test to_dict() methods on dataclasses."""
    
    def test_field_mapping_to_dict(self):
        """Test FieldMapping.to_dict()."""
        mapping = FieldMapping(
            source_field="category",
            source_value="process_creation",
            mapped_at="2025-01-01T00:00:00Z"
        )
        
        result = mapping.to_dict()
        
        assert result == {
            'source_field': 'category',
            'source_value': 'process_creation',
            'mapped_at': '2025-01-01T00:00:00Z'
        }
    
    def test_logsource_mapping_to_dict(self):
        """Test LogSourceMapping.to_dict()."""
        mapping = LogSourceMapping(
            category=FieldMapping("category", "process_creation"),
            product=FieldMapping("product", "windows")
        )
        
        result = mapping.to_dict()
        
        assert 'category' in result
        assert 'product' in result
        assert 'service' not in result  # service is None
        assert result['category']['source_field'] == 'category'
        assert result['product']['source_field'] == 'product'
    
    def test_detection_field_mapping_to_dict(self):
        """Test DetectionFieldMapping.to_dict()."""
        mapping = DetectionFieldMapping(
            source_field="EventID",
            target_table="process_activity",
            target_field="metadata.event_code",
            mapped_at="2025-01-01T00:00:00Z"
        )
        
        result = mapping.to_dict()
        
        assert result == {
            'source_field': 'EventID',
            'target_table': 'process_activity',
            'target_field': 'metadata.event_code',
            'mapped_at': '2025-01-01T00:00:00Z'
        }
    
    def test_ocsflite_to_dict(self):
        """Test OCSFLite.to_dict()."""
        ocsf = OCSFLite(
            class_name="system/process_activity",
            logsource=LogSourceMapping(
                category=FieldMapping("category", "process_creation")
            ),
            detection_fields=[
                DetectionFieldMapping("EventID", "process_activity", "metadata.event_code"),
                DetectionFieldMapping("CommandLine", "process_activity", "process.cmd_line")
            ]
        )
        
        result = ocsf.to_dict()
        
        assert result['class_name'] == "system/process_activity"
        assert 'logsource' in result
        assert len(result['detection_fields']) == 2
        assert result['detection_fields'][0]['source_field'] == 'EventID'


class TestRuleExportDict:
    """Test SigmaRuleOCSFLite.to_export_dict()."""
    
    @pytest.fixture
    def mock_rule(self):
        """Create a mock rule with mappings."""
        rule = Mock(spec=SigmaRuleOCSFLite)
        rule.id = "test-rule-123"
        rule.title = "Test Process Creation"
        rule.status = "stable"
        rule.level = "high"
        rule.description = "Test description"
        rule.author = "Test Author"
        rule.date = "2025-01-01"
        rule.modified = "2025-01-02"
        rule.tags = ["attack.t1059", "attack.execution"]
        rule.references = ["https://example.com"]
        rule.source_filename = "test_rule.yml"
        
        # Mock logsource
        rule.logsource = Mock()
        rule.logsource.category = "process_creation"
        rule.logsource.product = "windows"
        rule.logsource.service = None
        
        # Mock OCSF mappings
        rule.ocsflite = OCSFLite(
            class_name="system/process_activity",
            detection_fields=[
                DetectionFieldMapping("EventID", "process_activity", "metadata.event_code"),
                DetectionFieldMapping("CommandLine", "process_activity", "process.cmd_line")
            ]
        )
        
        # Bind the real to_export_dict method
        rule.to_export_dict = lambda full=False: SigmaRuleOCSFLite.to_export_dict(rule, full=full)
        
        return rule
    
    def test_default_export_format(self, mock_rule):
        """Test default export (field mappings only)."""
        result = mock_rule.to_export_dict(full=False)
        
        assert 'event_class' in result
        assert 'field_mappings' in result
        assert result['event_class'] == "system/process_activity"
        assert 'EventID' in result['field_mappings']
        assert 'CommandLine' in result['field_mappings']
        assert result['field_mappings']['EventID'] == "process_activity.metadata.event_code"
        assert result['field_mappings']['CommandLine'] == "process_activity.process.cmd_line"
        
        # Should NOT contain full rule details
        assert 'id' not in result
        assert 'title' not in result
    
    def test_full_export_format(self, mock_rule):
        """Test full export (all rule details)."""
        result = mock_rule.to_export_dict(full=True)
        
        # Should contain rule metadata
        assert result['id'] == "test-rule-123"
        assert result['title'] == "Test Process Creation"
        assert result['status'] == "stable"
        assert result['level'] == "high"
        assert result['description'] == "Test description"
        assert result['author'] == "Test Author"
        
        # Should contain OCSF mappings
        assert 'ocsf_mapping' in result
        assert result['ocsf_mapping']['class_name'] == "system/process_activity"
    
    def test_unmapped_fields_in_export(self, mock_rule):
        """Test export with unmapped fields (None values)."""
        # Add an unmapped field
        mock_rule.ocsflite.detection_fields.append(
            DetectionFieldMapping("UnknownField", None, None)
        )
        
        result = mock_rule.to_export_dict(full=False)
        
        assert 'UnknownField' in result['field_mappings']
        assert result['field_mappings']['UnknownField'] is None


class TestExportRuleToFile:
    """Test export_rule_to_file() function."""
    
    @pytest.fixture
    def mock_rule(self):
        """Create a mock rule for export testing."""
        rule = Mock(spec=SigmaRuleOCSFLite)
        rule.id = "test-export-rule"
        rule.title = "Export Test Rule"
        rule.source_filename = "export_test.yml"
        rule.ocsflite = OCSFLite(
            class_name="system/process_activity",
            detection_fields=[
                DetectionFieldMapping("EventID", "process_activity", "metadata.event_code")
            ]
        )
        rule.to_export_dict = lambda full=False: {
            'event_class': 'system/process_activity',
            'field_mappings': {'EventID': 'process_activity.metadata.event_code'}
        }
        return rule
    
    def test_export_yaml_default(self, mock_rule):
        """Test exporting to YAML with default settings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            result_path = export_rule_to_file(mock_rule, output_dir, format='yaml', full=False)
            
            assert result_path.exists()
            assert result_path.suffix == '.yml'
            assert result_path.name == 'export_test.yml'
            
            # Verify YAML content
            with open(result_path, 'r') as f:
                data = yaml.safe_load(f)
            
            assert data['event_class'] == 'system/process_activity'
            assert 'EventID' in data['field_mappings']
    
    def test_export_json(self, mock_rule):
        """Test exporting to JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            result_path = export_rule_to_file(mock_rule, output_dir, format='json', full=False)
            
            assert result_path.exists()
            assert result_path.suffix == '.json'
            assert result_path.name == 'export_test.json'
            
            # Verify JSON content
            with open(result_path, 'r') as f:
                data = json.load(f)
            
            assert data['event_class'] == 'system/process_activity'
    
    def test_export_without_source_filename(self, mock_rule):
        """Test export when rule has no source_filename (fallback to ID)."""
        mock_rule.source_filename = None
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            result_path = export_rule_to_file(mock_rule, output_dir, format='yaml', full=False)
            
            assert result_path.exists()
            assert 'test-export-rule' in result_path.name


class TestExportRules:
    """Test export_rules() function."""
    
    @pytest.fixture
    def mock_rules(self):
        """Create multiple mock rules."""
        rules = []
        for i in range(3):
            rule = Mock(spec=SigmaRuleOCSFLite)
            rule.id = f"rule-{i}"
            rule.title = f"Test Rule {i}"
            rule.source_filename = f"test_rule_{i}.yml"
            rule.ocsflite = OCSFLite(
                class_name="system/process_activity",
                detection_fields=[
                    DetectionFieldMapping("EventID", "process_activity", "metadata.event_code")
                ]
            )
            rule.to_export_dict = lambda full=False: {
                'event_class': 'system/process_activity',
                'field_mappings': {'EventID': 'process_activity.metadata.event_code'}
            }
            rules.append(rule)
        return rules
    
    def test_export_multiple_rules_yaml(self, mock_rules):
        """Test exporting multiple rules to YAML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exported_files = export_rules(mock_rules, tmpdir, format='yaml', full=False)
            
            assert len(exported_files) == 3
            for file_path in exported_files:
                assert file_path.exists()
                assert file_path.suffix == '.yml'
    
    def test_export_multiple_rules_json(self, mock_rules):
        """Test exporting multiple rules to JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exported_files = export_rules(mock_rules, tmpdir, format='json', full=False)
            
            assert len(exported_files) == 3
            for file_path in exported_files:
                assert file_path.exists()
                assert file_path.suffix == '.json'
    
    def test_export_creates_directory(self, mock_rules):
        """Test that export creates output directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "new" / "nested" / "directory"
            
            exported_files = export_rules(mock_rules, str(output_dir), format='yaml', full=False)
            
            assert output_dir.exists()
            assert len(exported_files) == 3
    
    def test_export_handles_errors_gracefully(self):
        """Test that export continues even if one rule fails."""
        # Create one good rule and one that will fail
        good_rule = Mock(spec=SigmaRuleOCSFLite)
        good_rule.title = "Good Rule"
        good_rule.source_filename = "good.yml"
        good_rule.to_export_dict = lambda full=False: {'event_class': 'test'}
        
        bad_rule = Mock(spec=SigmaRuleOCSFLite)
        bad_rule.title = "Bad Rule"
        bad_rule.source_filename = "bad.yml"
        bad_rule.to_export_dict = Mock(side_effect=Exception("Export failed"))
        
        with tempfile.TemporaryDirectory() as tmpdir:
            exported_files = export_rules([good_rule, bad_rule], tmpdir, format='yaml', full=False)
            
            # Should export the good rule despite the bad one failing
            assert len(exported_files) == 1
            assert exported_files[0].name == 'good.yml'


class TestCompleteRuleExport:
    """Test that full export includes both original rule and OCSF mappings."""
    
    def test_full_export_includes_original_and_mappings(self):
        """Test that full export includes both original SigmaRule fields and OCSF mappings."""
        from sigma.rule import SigmaRule
        from fieldmapper.ocsf.rules import SigmaRuleOCSFLite, DetectionFieldMapping
        
        # Create a real Sigma rule from YAML
        yaml_str = '''
title: Test Process Creation
id: 12345678-1234-1234-1234-123456789012
status: test
level: medium
description: Test rule for export
author: Test Author
date: 2024/01/01
modified: 2024/01/02
tags:
  - attack.t1059
references:
  - https://example.com
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'test'
  condition: selection
fields:
  - CommandLine
  - User
falsepositives:
  - Unknown
'''
        
        sigma_rule = SigmaRule.from_yaml(yaml_str)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, source_filename="test.yml")
        
        # Add some OCSF mappings
        ocsf_rule.ocsflite.class_name = "system/process_activity"
        ocsf_rule.ocsflite.detection_fields = [
            DetectionFieldMapping("EventID", "process_activity", "metadata.event_code"),
            DetectionFieldMapping("CommandLine", "process_activity", "process.cmd_line")
        ]
        
        # Export with full=True
        result = ocsf_rule.to_export_dict(full=True)
        
        # Verify original SigmaRule fields are present
        assert 'id' in result
        assert result['title'] == 'Test Process Creation'
        assert 'status' in result
        assert 'level' in result
        assert result['description'] == 'Test rule for export'
        assert result['author'] == 'Test Author'
        assert 'date' in result
        assert 'modified' in result
        assert 'tags' in result
        assert 'references' in result
        assert 'fields' in result
        assert 'falsepositives' in result
        
        # Verify original logsource is present (from YAML)
        assert 'logsource' in result
        assert result['logsource']['category'] == 'process_creation'
        assert result['logsource']['product'] == 'windows'
        
        # Verify original detection is present (from YAML)
        assert 'detection' in result
        assert 'condition' in result['detection']
        # Detection should have the selection from the YAML
        assert 'selection' in result['detection'] or 'detections' in result['detection']
        
        # Verify OCSF mappings are present (our additions)
        assert 'ocsf_mapping' in result
        assert result['ocsf_mapping']['class_name'] == 'system/process_activity'
        assert 'detection_fields' in result['ocsf_mapping']
        assert len(result['ocsf_mapping']['detection_fields']) == 2
    
    def test_full_export_includes_additional_attributes(self):
        """Test that full export includes additional SigmaRule attributes like falsepositives, license, etc."""
        from sigma.rule import SigmaRule
        from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
        
        yaml_str = '''
title: Test Rule with Extras
id: 87654321-4321-4321-4321-210987654321
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    dst_port: 443
  condition: selection
falsepositives:
  - Legitimate HTTPS traffic
  - Corporate proxies
license: MIT
'''
        
        sigma_rule = SigmaRule.from_yaml(yaml_str)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        
        result = ocsf_rule.to_export_dict(full=True)
        
        # Verify additional attributes are included
        assert 'falsepositives' in result
        assert len(result['falsepositives']) == 2
        assert 'Legitimate HTTPS traffic' in result['falsepositives']
        
        assert 'license' in result
        assert result['license'] == 'MIT'
    
    def test_logsource_mappings_no_target_value(self):
        """Verify logsource mappings don't have target_value (class_name is the target)."""
        from sigma.rule import SigmaRule
        from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
        
        yaml_str = '''
title: Test Rule for Logsource
id: 12345678-1234-1234-1234-123456789012
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
'''
        
        sigma_rule = SigmaRule.from_yaml(yaml_str)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        ocsf_rule.create_logsource_mappings()
        
        result = ocsf_rule.to_export_dict(full=True)
        
        # Verify logsource mappings exist
        assert 'ocsf_mapping' in result
        assert 'logsource' in result['ocsf_mapping']
        
        logsource = result['ocsf_mapping']['logsource']
        assert 'category' in logsource
        assert logsource['category']['source_field'] == 'category'
        assert logsource['category']['source_value'] == 'process_creation'
        
        # Verify no target_value field exists
        assert 'target_value' not in logsource['category']
        
        # Verify mapped_at field exists (may be null if not yet mapped by AI)
        assert 'mapped_at' in logsource['category']
        
        # Same for product
        assert 'product' in logsource
        assert 'target_value' not in logsource['product']
        assert 'mapped_at' in logsource['product']
    
    def test_timestamps_after_ai_mapping(self):
        """Verify both logsource and detection field mappings get timestamps after AI mapping."""
        from sigma.rule import SigmaRule
        from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
        from unittest.mock import Mock
        from datetime import datetime
        
        yaml_str = '''
title: Test Timestamp Rule
id: 87654321-4321-4321-4321-210987654321
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
    CommandLine: test
  condition: selection
'''
        
        sigma_rule = SigmaRule.from_yaml(yaml_str)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        
        # Create a mock AI mapper
        mock_mapper = Mock()
        mock_mapper.map_to_event_class.return_value = "system/process_activity"
        mock_mapper.map_detection_fields.return_value = {
            'EventID': 'metadata.event_code',
            'CommandLine': 'process.cmd_line'
        }
        
        # Call populate_mappings_with_ai
        ocsf_rule.populate_mappings_with_ai(mock_mapper)
        
        # Verify logsource mappings have timestamps
        assert ocsf_rule.ocsflite.logsource is not None
        assert ocsf_rule.ocsflite.logsource.category is not None
        assert ocsf_rule.ocsflite.logsource.category.mapped_at is not None
        
        # Verify it's a valid ISO timestamp
        datetime.fromisoformat(ocsf_rule.ocsflite.logsource.category.mapped_at)
        
        # Verify detection field mappings have timestamps
        assert len(ocsf_rule.ocsflite.detection_fields) > 0
        for field_mapping in ocsf_rule.ocsflite.detection_fields:
            if field_mapping.target_field:  # Only mapped fields should have timestamps
                assert field_mapping.mapped_at is not None
                # Verify it's a valid ISO timestamp
                datetime.fromisoformat(field_mapping.mapped_at)


class TestYAMLJSONIntegration:
    """Integration tests for YAML/JSON export."""
    
    def test_yaml_roundtrip(self):
        """Test that exported YAML can be read back correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create a mock rule
            rule = Mock(spec=SigmaRuleOCSFLite)
            rule.source_filename = "roundtrip_test.yml"
            rule.to_export_dict = lambda full=False: {
                'event_class': 'system/process_activity',
                'field_mappings': {
                    'EventID': 'process_activity.metadata.event_code',
                    'CommandLine': 'process_activity.process.cmd_line'
                }
            }
            
            # Export
            file_path = export_rule_to_file(rule, output_dir, format='yaml', full=False)
            
            # Read back
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
            
            assert data['event_class'] == 'system/process_activity'
            assert len(data['field_mappings']) == 2
            assert data['field_mappings']['EventID'] == 'process_activity.metadata.event_code'
    
    def test_json_roundtrip(self):
        """Test that exported JSON can be read back correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Create a mock rule
            rule = Mock(spec=SigmaRuleOCSFLite)
            rule.source_filename = "roundtrip_test.yml"
            rule.to_export_dict = lambda full=False: {
                'event_class': 'system/process_activity',
                'field_mappings': {
                    'EventID': 'process_activity.metadata.event_code',
                    'CommandLine': 'process_activity.process.cmd_line'
                }
            }
            
            # Export
            file_path = export_rule_to_file(rule, output_dir, format='json', full=False)
            
            # Read back
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            assert data['event_class'] == 'system/process_activity'
            assert len(data['field_mappings']) == 2
            assert data['field_mappings']['EventID'] == 'process_activity.metadata.event_code'
    
    def test_tags_exported_as_strings(self):
        """Verify tags are exported as simple strings, not Python objects."""
        from sigma.rule import SigmaRule
        from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
        
        yaml_str = '''
title: Test Tags Export
id: 12345678-1234-1234-1234-123456789012
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
tags:
  - attack.execution
  - attack.t1059
'''
        
        sigma_rule = SigmaRule.from_yaml(yaml_str)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        
        result = ocsf_rule.to_export_dict(full=True)
        
        # Verify tags are simple strings
        assert 'tags' in result
        assert isinstance(result['tags'], list)
        for tag in result['tags']:
            assert isinstance(tag, str)
            assert '!!python' not in str(tag)  # No Python object serialization

