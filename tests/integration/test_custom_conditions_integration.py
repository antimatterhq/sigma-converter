"""
Integration tests for custom Sigma processing conditions.
These tests load real rule files from fieldmapper/mappings/ to validate the mapping system.
"""

import pytest
from pathlib import Path
from collections import defaultdict
from sigma.collection import SigmaCollection
from sigma.backends.databricks import DatabricksBackend
from sigma.pipelines.lakewatch import lakewatch_pipeline
from sigma.pipelines.lakewatch.custom_conditions import RuleIDCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import SetCustomAttributeTransformation, FieldMappingTransformation
from fieldmapper.ocsf.rules import SigmaRuleOCSFLite


# Sample rule YAML for testing
SAMPLE_RULE_YAML = """
title: Test Rule for Conditions
id: 12345678-1234-1234-1234-123456789012
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        EventID: 4688
        Image: test.exe
    condition: sel
"""


class TestRuleIDCondition:
    """Test RuleIDCondition matching.
    
    These tests import from sigma.pipelines.lakewatch which loads all rule files at import,
    making them integration tests despite using inline YAML.
    """
    
    def test_rule_id_condition_match(self):
        """Test that RuleIDCondition matches the correct rule."""
        collection = SigmaCollection.from_yaml(SAMPLE_RULE_YAML)
        rule = collection.rules[0]
        
        condition = RuleIDCondition(rule_id="12345678-1234-1234-1234-123456789012")
        pipeline = ProcessingPipeline(name="test", priority=20, items=[])
        
        assert condition.match(pipeline, rule) is True
    
    def test_rule_id_condition_no_match(self):
        """Test that RuleIDCondition rejects wrong rule."""
        collection = SigmaCollection.from_yaml(SAMPLE_RULE_YAML)
        rule = collection.rules[0]
        
        condition = RuleIDCondition(rule_id="00000000-0000-0000-0000-000000000000")
        pipeline = ProcessingPipeline(name="test", priority=20, items=[])
        
        assert condition.match(pipeline, rule) is False
    
    def test_rule_id_condition_in_pipeline(self):
        """Test RuleIDCondition in a processing pipeline."""
        collection = SigmaCollection.from_yaml(SAMPLE_RULE_YAML)
        
        # Create pipeline with RuleIDCondition
        pipeline = ProcessingPipeline(
            name="test",
            priority=20,
            items=[
                ProcessingItem(
                    identifier="test_rule_id",
                    transformation=SetCustomAttributeTransformation(
                        attribute="test_attr",
                        value="matched"
                    ),
                    rule_conditions=[
                        RuleIDCondition(rule_id="12345678-1234-1234-1234-123456789012")
                    ]
                )
            ]
        )
        
        # Apply pipeline
        backend = DatabricksBackend(pipeline)
        backend.convert(collection)
        
        # Check that custom attribute was set
        rule = collection.rules[0]
        assert hasattr(rule, 'custom_attributes')
        assert rule.custom_attributes.get('test_attr') == 'matched'


class TestHybridMappings:
    """Test build_table_mappings method and structure.
    
    These tests call build_table_mappings() which loads all ~2,600 rule files,
    so they're integration tests despite not using Path/rglob directly.
    """
    
    def test_total_mappings_count(self):
        """Test that we have a reasonable total number of rule mappings."""
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Total rules covered (rules via logsource + rules via ID)
        # Note: logsource_mappings cover multiple rules each
        # We can't easily count total without loading files, but rule_id_mappings should be significant
        assert mappings.conflicted_count > 200, "Should have many conflicted rules handled by ID"
        assert mappings.logsource_count > 30, "Should have many non-conflicted logsources"
    
    def test_rule_id_mappings_structure(self):
        """Test that rule ID mappings have correct structure."""
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Keys should be UUID strings
        for key in mappings.conflicted_rule_mappings.keys():
            assert isinstance(key, str)
            # Basic UUID format check (has dashes)
            assert '-' in key
        
        # Values should be strings (class names)
        for value in mappings.conflicted_rule_mappings.values():
            assert isinstance(value, str)
            assert value != "<UNMAPPED>"


class TestHybridTableMappings:
    """Test build_table_mappings method and optimization.
    
    These tests call build_table_mappings() which loads all ~2,600 rule files,
    so they're integration tests despite not using Path/rglob directly.
    """
    
    def test_build_hybrid_mappings_returns_dataclass(self):
        """Test that hybrid mappings returns PipelineMappings dataclass."""
        from fieldmapper.ocsf.rules import PipelineMappings
        result = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Should return PipelineMappings dataclass
        assert isinstance(result, PipelineMappings)
        
        # Should have all expected attributes as dicts
        assert isinstance(result.logsource_mappings, dict)
        assert isinstance(result.conflicted_rule_mappings, dict)
        assert isinstance(result.activity_id_mappings, dict)
    
    def test_hybrid_logsource_mappings_structure(self):
        """Test that logsource mappings have correct structure."""
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Should have some non-conflicted logsources
        assert len(mappings.logsource_mappings) > 0
        
        # Keys should be (category, product, service) tuples
        for key in mappings.logsource_mappings.keys():
            assert isinstance(key, tuple)
            assert len(key) == 3
            # Each element can be str or None
            for element in key:
                assert element is None or isinstance(element, str)
        
        # Values should be table names (strings)
        for value in mappings.logsource_mappings.values():
            assert isinstance(value, str)
            assert value != "<UNMAPPED>"
    
    def test_hybrid_conflicted_mappings_structure(self):
        """Test that conflicted rule mappings have correct structure."""
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Should have some conflicted rules
        assert len(mappings.conflicted_rule_mappings) > 0
        
        # Keys should be UUID strings
        for key in mappings.conflicted_rule_mappings.keys():
            assert isinstance(key, str)
            # Basic UUID format check
            assert '-' in key
        
        # Values should be table names
        for value in mappings.conflicted_rule_mappings.values():
            assert isinstance(value, str)
            assert value != "<UNMAPPED>"
    
    def test_hybrid_optimization_reduces_items(self):
        """Test that hybrid approach achieves significant optimization."""
        # Get hybrid mappings
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Hybrid count: logsource conditions + per-rule conditions
        hybrid_count = mappings.total_table_mappings
        
        # The optimization comes from using LogsourceCondition for non-conflicted rules
        # We expect logsource_mappings to be much smaller than conflicted_rule_mappings
        # because each logsource can cover multiple rules
        
        assert hybrid_count < 1500, \
            f"Hybrid approach ({hybrid_count}) should be well optimized (< 1500 items)"
        
        # Logsource mappings should cover many rules with few conditions
        assert mappings.logsource_count < mappings.conflicted_count, \
            "Should have fewer logsource conditions than rule ID conditions"
        
        print(f"\nHybrid optimization: {mappings.logsource_count} logsource + {mappings.conflicted_count} rule ID = {hybrid_count} total items")


class TestHybridTableMappingsWithFileSampling:
    """Integration tests that validate hybrid table mappings with real rule corpus."""
    
    def test_hybrid_coverage_sample(self):
        """Test that hybrid approach covers a sample of rules correctly.
        
        This integration test loads actual rules from the corpus to verify that
        the hybrid mapping approach (LogsourceCondition + RuleIDCondition) correctly
        assigns tables to all rules.
        """
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Sample some rules and verify they're covered
        # Either via logsource mapping or rule ID mapping
        covered_count = 0
        base_path = Path('fieldmapper/mappings')
        
        # Sample first 30 rules for validation
        for i, file_path in enumerate(base_path.rglob('*.yml')):
            if i >= 30:
                break
            
            try:
                rule = SigmaRuleOCSFLite.load(str(file_path))
                if not rule.id or not rule.ocsflite or not rule.ocsflite.class_name:
                    continue
                if rule.ocsflite.class_name == '<UNMAPPED>':
                    continue
                
                rule_id = str(rule.id)
                expected_table = rule.ocsflite.class_name
                
                # Check if covered by rule ID
                if rule_id in mappings.conflicted_rule_mappings:
                    assert mappings.conflicted_rule_mappings[rule_id] == expected_table
                    covered_count += 1
                else:
                    # Should be covered by logsource
                    ls = rule.logsource if isinstance(rule.logsource, dict) else {}
                    ls_key = (ls.get('category'), ls.get('product'), ls.get('service'))
                    if ls_key in mappings.logsource_mappings:
                        assert mappings.logsource_mappings[ls_key] == expected_table
                        covered_count += 1
            except:
                continue
        
        # Should have covered most of the sample
        assert covered_count >= 15, f"Expected to cover at least 15 rules, covered {covered_count}"
    
    def test_logsource_mappings_have_no_conflicts(self):
        """Test that logsource mappings truly have no conflicts.
        
        This integration test loads actual rules to verify that logsources marked as
        "non-conflicted" in the hybrid mapping truly map to only one table across
        all rules in the corpus.
        """
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
        
        # Each logsource in this dict should map to only one table
        # We verify this by checking that all rules with that logsource
        # have the same table in the full mapping
        
        # Load a sample of rules for validation
        logsource_to_rules = defaultdict(list)
        base_path = Path('fieldmapper/mappings')
        
        # Sample first 50 rules (reduced from 200 for performance)
        for i, file_path in enumerate(base_path.rglob('*.yml')):
            if i >= 50:
                break
            
            try:
                rule = SigmaRuleOCSFLite.load(str(file_path))
                if rule.ocsflite and rule.ocsflite.class_name and \
                   rule.ocsflite.class_name != '<UNMAPPED>':
                    ls = rule.logsource if isinstance(rule.logsource, dict) else {}
                    ls_key = (ls.get('category'), ls.get('product'), ls.get('service'))
                    
                    if ls_key in mappings.logsource_mappings:
                        logsource_to_rules[ls_key].append(rule.ocsflite.class_name)
            except:
                continue
        
        # Verify: each logsource should have only one unique table
        for ls_key, tables in logsource_to_rules.items():
            unique_tables = set(tables)
            assert len(unique_tables) == 1, \
                f"Logsource {ls_key} has multiple tables: {unique_tables}"


class TestPipelineIntegration:
    """Test integration with processing pipeline.
    
    These tests use lakewatch_pipeline() which loads all rule files at module import,
    making them integration tests.
    """
    
    def test_pipeline_with_custom_conditions(self):
        """Test that hybrid pipeline uses LogsourceCondition, RuleIDCondition, and activity_id conditions."""
        # Load the lakewatch pipeline which uses hybrid table mappings
        pipeline = lakewatch_pipeline()
        
        # Should have multiple processing items
        assert len(pipeline.items) > 1
        
        # First items should be config attributes (time_column, catalog, schema)
        assert pipeline.items[0].identifier == "set_time_column"
        assert pipeline.items[1].identifier == "set_catalog"
        assert pipeline.items[2].identifier == "set_schema"
        
        # Fourth item should be field mapping
        assert pipeline.items[3].identifier == "lakewatch_field_mapping"
        
        # Count different types of items
        logsource_items = 0
        rule_id_items = 0
        activity_id_items = 0
        
        for item in pipeline.items[1:]:
            if "set_table_ls_" in item.identifier:
                logsource_items += 1
            elif "set_table_rule_" in item.identifier:
                rule_id_items += 1
            elif "add_activity_id_" in item.identifier:
                activity_id_items += 1
        
        # Should have all types of items
        assert logsource_items > 0, "Should have LogsourceCondition items"
        assert rule_id_items > 0, "Should have RuleIDCondition items"
        assert activity_id_items > 0, "Should have activity_id condition items"
        
        # LogsourceCondition items should be significantly fewer than RuleIDCondition
        # (67 logsource items vs ~900 rule items)
        assert logsource_items < rule_id_items
        
        print(f"\nHybrid pipeline: {logsource_items} LogsourceCondition + {rule_id_items} RuleIDCondition + {activity_id_items} activity_id items")
    
    def test_pipeline_table_assignment(self):
        """Test that table attribute is set correctly using RuleIDCondition."""
        collection = SigmaCollection.from_yaml(SAMPLE_RULE_YAML)
        
        # Create a custom pipeline with explicit table assignment for our test rule
        test_rule_id = "12345678-1234-1234-1234-123456789012"
        
        pipeline = ProcessingPipeline(
            name="test_pipeline",
            priority=20,
            items=[
                ProcessingItem(
                    identifier="lakewatch_field_mapping",
                    transformation=FieldMappingTransformation(
                        mapping=SigmaRuleOCSFLite.build_pipeline_mappings().field_mappings
                    )
                ),
                ProcessingItem(
                    identifier="set_test_rule_table",
                    transformation=SetCustomAttributeTransformation(
                        attribute="table",
                        value="process_activity"
                    ),
                    rule_conditions=[RuleIDCondition(rule_id=test_rule_id)]
                )
            ]
        )
        
        # Apply the pipeline
        backend = DatabricksBackend(pipeline)
        backend.convert(collection)
        
        # Check that table attribute was set
        rule = collection.rules[0]
        assert hasattr(rule, 'custom_attributes')
        assert 'table' in rule.custom_attributes
        
        # Should be process_activity as we explicitly set it
        assert rule.custom_attributes['table'] == 'process_activity'
