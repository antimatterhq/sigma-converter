"""
Tests for the analyze_mappings module.
"""

import pytest
from pathlib import Path
from fieldmapper.ocsf.analyze_mappings import (
    MappingStatistics,
    RuleMappingAnalysis,
    classify_mapping_status,
    analyze_rule,
    analyze_directory,
    generate_report
)


class TestClassifyMappingStatus:
    """Test classify_mapping_status function."""
    
    def test_unmapped_null_class_name(self):
        """Test rule with null class_name is unmapped."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test1",
            rule_title="Test Rule",
            class_name=None,
            total_detection_fields=5,
            mapped_detection_fields=3,
            unmapped_detection_fields=2,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "unmapped"
    
    def test_unmapped_null_string_class_name(self):
        """Test rule with 'null' string class_name is unmapped."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test2",
            rule_title="Test Rule",
            class_name="null",
            total_detection_fields=5,
            mapped_detection_fields=0,
            unmapped_detection_fields=5,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "unmapped"
    
    def test_complete_no_fields(self):
        """Test rule with class_name but no fields is complete."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test3",
            rule_title="Test Rule",
            class_name="process_activity",
            total_detection_fields=0,
            mapped_detection_fields=0,
            unmapped_detection_fields=0,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "complete"
    
    def test_complete_all_fields_mapped(self):
        """Test rule with all fields mapped is complete."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test4",
            rule_title="Test Rule",
            class_name="process_activity",
            total_detection_fields=5,
            mapped_detection_fields=5,
            unmapped_detection_fields=0,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "complete"
    
    def test_partial_some_fields_mapped(self):
        """Test rule with some fields mapped is partial."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test5",
            rule_title="Test Rule",
            class_name="process_activity",
            total_detection_fields=5,
            mapped_detection_fields=3,
            unmapped_detection_fields=2,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "partial"
    
    def test_unmapped_no_fields_mapped(self):
        """Test rule with class_name but no fields mapped is unmapped."""
        analysis = RuleMappingAnalysis(
            filename="test_rule.yml",
            rule_id="test6",
            rule_title="Test Rule",
            class_name="process_activity",
            total_detection_fields=5,
            mapped_detection_fields=0,
            unmapped_detection_fields=5,
            mapping_status=""
        )
        
        status = classify_mapping_status(analysis)
        assert status == "unmapped"


class TestAnalyzeRule:
    """Test analyze_rule function."""
    
    def test_analyze_completely_mapped_rule(self, tmp_path):
        """Test analyzing a completely mapped rule."""
        # Create a test YAML file
        yaml_content = """
id: test-123
title: Test Completely Mapped Rule
ocsf_mapping:
  class_name: process_activity
  detection_fields:
    - source_field: Image
      target_table: process_activity
      target_field: actor.process.name
    - source_field: CommandLine
      target_table: process_activity
      target_field: actor.process.cmd_line
"""
        rule_file = tmp_path / "test_complete.yml"
        rule_file.write_text(yaml_content)
        
        analysis = analyze_rule(rule_file)
        
        assert analysis is not None
        assert analysis.rule_id == "test-123"
        assert analysis.rule_title == "Test Completely Mapped Rule"
        assert analysis.class_name == "process_activity"
        assert analysis.total_detection_fields == 2
        assert analysis.mapped_detection_fields == 2
        assert analysis.unmapped_detection_fields == 0
        assert analysis.mapping_status == "complete"
    
    def test_analyze_partially_mapped_rule(self, tmp_path):
        """Test analyzing a partially mapped rule."""
        yaml_content = """
id: test-456
title: Test Partially Mapped Rule
ocsf_mapping:
  class_name: file_activity
  detection_fields:
    - source_field: TargetFilename
      target_table: file_activity
      target_field: file.name
    - source_field: User
      target_table: null
      target_field: null
"""
        rule_file = tmp_path / "test_partial.yml"
        rule_file.write_text(yaml_content)
        
        analysis = analyze_rule(rule_file)
        
        assert analysis is not None
        assert analysis.class_name == "file_activity"
        assert analysis.total_detection_fields == 2
        assert analysis.mapped_detection_fields == 1
        assert analysis.unmapped_detection_fields == 1
        assert analysis.mapping_status == "partial"
    
    def test_analyze_unmapped_rule(self, tmp_path):
        """Test analyzing a completely unmapped rule."""
        yaml_content = """
id: test-789
title: Test Unmapped Rule
ocsf_mapping:
  class_name: null
  detection_fields:
    - source_field: Field1
      target_table: null
      target_field: null
    - source_field: Field2
      target_table: null
      target_field: null
"""
        rule_file = tmp_path / "test_unmapped.yml"
        rule_file.write_text(yaml_content)
        
        analysis = analyze_rule(rule_file)
        
        assert analysis is not None
        assert analysis.class_name is None or analysis.class_name == "null"
        assert analysis.total_detection_fields == 2
        assert analysis.mapped_detection_fields == 0
        assert analysis.unmapped_detection_fields == 2
        assert analysis.mapping_status == "unmapped"
    
    def test_analyze_rule_no_detection_fields(self, tmp_path):
        """Test analyzing a rule with no detection fields."""
        yaml_content = """
id: test-999
title: Test No Fields Rule
ocsf_mapping:
  class_name: process_activity
  detection_fields: []
"""
        rule_file = tmp_path / "test_nofields.yml"
        rule_file.write_text(yaml_content)
        
        analysis = analyze_rule(rule_file)
        
        assert analysis is not None
        assert analysis.total_detection_fields == 0
        assert analysis.mapping_status == "complete"
    
    def test_analyze_invalid_yaml(self, tmp_path):
        """Test analyzing an invalid YAML file."""
        yaml_content = "{ invalid yaml content"
        rule_file = tmp_path / "invalid.yml"
        rule_file.write_text(yaml_content)
        
        analysis = analyze_rule(rule_file)
        
        assert analysis is None
    
    def test_analyze_nonexistent_file(self):
        """Test analyzing a file that doesn't exist."""
        analysis = analyze_rule(Path("/nonexistent/file.yml"))
        
        assert analysis is None


class TestAnalyzeDirectory:
    """Test analyze_directory function."""
    
    def test_analyze_directory_with_multiple_rules(self, tmp_path):
        """Test analyzing a directory with multiple rules."""
        # Create completely mapped rule
        complete_yaml = """
id: complete-1
title: Complete Rule
ocsf_mapping:
  class_name: process_activity
  detection_fields:
    - source_field: Image
      target_table: process_activity
      target_field: actor.process.name
"""
        (tmp_path / "complete.yml").write_text(complete_yaml)
        
        # Create partially mapped rule
        partial_yaml = """
id: partial-1
title: Partial Rule
ocsf_mapping:
  class_name: file_activity
  detection_fields:
    - source_field: Field1
      target_table: file_activity
      target_field: file.name
    - source_field: Field2
      target_table: null
      target_field: null
"""
        (tmp_path / "partial.yml").write_text(partial_yaml)
        
        # Create unmapped rule
        unmapped_yaml = """
id: unmapped-1
title: Unmapped Rule
ocsf_mapping:
  class_name: null
  detection_fields:
    - source_field: Field1
      target_table: null
      target_field: null
"""
        (tmp_path / "unmapped.yml").write_text(unmapped_yaml)
        
        stats, analyses = analyze_directory(tmp_path)
        
        assert stats.total_rules == 3
        assert stats.completely_mapped == 1
        assert stats.partially_mapped == 1
        assert stats.completely_unmapped == 1
        assert stats.total_fields == 4
        assert stats.mapped_fields == 2
        assert stats.unmapped_fields == 2
        assert len(analyses) == 3
        
        # Check event class distribution
        assert stats.event_classes.get("process_activity") == 1
        assert stats.event_classes.get("file_activity") == 1
    
    def test_analyze_empty_directory(self, tmp_path):
        """Test analyzing an empty directory."""
        stats, analyses = analyze_directory(tmp_path)
        
        assert stats.total_rules == 0
        assert stats.completely_mapped == 0
        assert stats.partially_mapped == 0
        assert stats.completely_unmapped == 0
        assert len(analyses) == 0
    
    def test_analyze_nonexistent_directory(self):
        """Test analyzing a directory that doesn't exist."""
        with pytest.raises(FileNotFoundError):
            analyze_directory(Path("/nonexistent/directory"))


class TestGenerateReport:
    """Test generate_report function."""
    
    def test_generate_report_with_rules(self):
        """Test generating a report with rules."""
        stats = MappingStatistics(
            total_rules=100,
            completely_mapped=50,
            partially_mapped=30,
            completely_unmapped=20,
            no_event_class=10,
            total_fields=500,
            mapped_fields=400,
            unmapped_fields=100,
            event_classes={
                "process_activity": 30,
                "file_activity": 20,
                "network_activity": 15
            },
            unmapped_field_counts={
                "UnknownField1": 15,
                "UnknownField2": 10,
                "UnknownField3": 8
            }
        )
        
        analyses = [
            RuleMappingAnalysis(
                filename=f"rule-{i}.yml",
                rule_id=f"rule-{i}",
                rule_title=f"Rule {i}",
                class_name="process_activity",
                total_detection_fields=5,
                mapped_detection_fields=5,
                unmapped_detection_fields=0,
                mapping_status="complete"
            )
            for i in range(100)
        ]
        
        report = generate_report(stats, analyses)
        
        assert "Mapping Statistics Report" in report
        assert "Total Rules: 100" in report
        assert "Completely Mapped: 50 (50.0%)" in report
        assert "Partially Mapped: 30 (30.0%)" in report
        assert "Completely Unmapped: 20 (20.0%)" in report
        assert "Rules Without Event Class: 10 (10.0%)" in report
        assert "Total Fields: 500" in report
        assert "Mapped: 400 (80.0%)" in report
        assert "Unmapped: 100 (20.0%)" in report
        assert "Top Event Classes:" in report
        assert "process_activity: 30" in report
        assert "file_activity: 20" in report
        assert "network_activity: 15" in report
        assert "Top 20 Unmapped Fields:" in report
        assert "UnknownField1: 15 rules" in report
        assert "UnknownField2: 10 rules" in report
        assert "UnknownField3: 8 rules" in report
    
    def test_generate_report_empty(self):
        """Test generating a report with no rules."""
        stats = MappingStatistics(
            total_rules=0,
            completely_mapped=0,
            partially_mapped=0,
            completely_unmapped=0,
            no_event_class=0,
            total_fields=0,
            mapped_fields=0,
            unmapped_fields=0,
            event_classes={},
            unmapped_field_counts={}
        )
        
        report = generate_report(stats, [])
        
        assert "Mapping Statistics Report" in report
        assert "Total Rules: 0" in report
        assert "%" not in report  # No percentages for empty stats

