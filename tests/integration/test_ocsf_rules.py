import pytest
from pathlib import Path
import tempfile
from sigma.rule import SigmaRule

from fieldmapper.ocsf.rules import OCSFLite, SigmaRuleOCSFLite, load_sigma_rules


# Sample Sigma rule YAML for testing
SAMPLE_SIGMA_RULE = """
title: Test Windows Logon
id: 12345678-1234-1234-1234-123456789012
status: test
description: A test rule for Windows logon
author: Test Author
date: 2024/01/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
level: medium
tags:
    - attack.initial_access
    - attack.t1078
"""


class TestOCSFLite:
    """Tests for the OCSFLite dataclass."""
    
    def test_ocsflite_creation(self):
        """Test creating an OCSFLite object."""
        ocsf = OCSFLite()
        assert ocsf.class_name is None
    
    def test_ocsflite_with_class_name(self):
        """Test creating an OCSFLite object with a class name."""
        ocsf = OCSFLite(class_name="Network Activity")
        assert ocsf.class_name == "Network Activity"


class TestSigmaRuleOCSFLite:
    """Tests for the SigmaRuleOCSFLite class."""
    
    def test_from_sigma_rule(self):
        """Test converting a SigmaRule to SigmaRuleOCSFLite."""
        # Create a SigmaRule from YAML
        sigma_rule = SigmaRule.from_yaml(SAMPLE_SIGMA_RULE)
        
        # Convert to SigmaRuleOCSFLite
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        
        # Verify it's the right type
        assert isinstance(ocsf_rule, SigmaRuleOCSFLite)
        assert isinstance(ocsf_rule, SigmaRule)
        
        # Verify all original attributes are preserved
        assert ocsf_rule.title == "Test Windows Logon"
        assert str(ocsf_rule.id) == "12345678-1234-1234-1234-123456789012"
        assert ocsf_rule.author == "Test Author"
        assert str(ocsf_rule.level) == "medium"
        
        # Verify the ocsflite attribute exists and is initialized
        assert hasattr(ocsf_rule, 'ocsflite')
        assert isinstance(ocsf_rule.ocsflite, OCSFLite)
        assert ocsf_rule.ocsflite.class_name is None
    
    def test_ocsflite_attribute_modification(self):
        """Test that we can modify the ocsflite attribute."""
        sigma_rule = SigmaRule.from_yaml(SAMPLE_SIGMA_RULE)
        ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule)
        
        # Modify the ocsflite attribute
        ocsf_rule.ocsflite.class_name = "Authentication"
        assert ocsf_rule.ocsflite.class_name == "Authentication"


class TestLoadSigmaRules:
    """Tests for the load_sigma_rules function."""
    
    def test_load_sigma_rules_with_valid_path(self, tmp_path):
        """Test loading Sigma rules from a valid directory."""
        # Create a temporary directory structure
        test_dir = tmp_path / "rules" / "network" / "firewall"
        test_dir.mkdir(parents=True)
        
        # Create a test YAML file
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(SAMPLE_SIGMA_RULE)
        
        # Temporarily modify PATHS
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/network/firewall"]
        
        try:
            # Load rules
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            
            # Verify
            assert len(loaded_rules) == 1
            assert isinstance(loaded_rules[0], SigmaRuleOCSFLite)
            assert loaded_rules[0].title == "Test Windows Logon"
            assert hasattr(loaded_rules[0], 'ocsflite')
        finally:
            # Restore original PATHS
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_multiple_files(self, tmp_path):
        """Test loading multiple Sigma rules from a directory."""
        # Create test directory
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        # Create multiple test files
        for i in range(3):
            test_file = test_dir / f"test_rule_{i}.yml"
            rule_yaml = SAMPLE_SIGMA_RULE.replace(
                "12345678-1234-1234-1234-123456789012",
                f"12345678-1234-1234-1234-12345678901{i}"
            ).replace("Test Windows Logon", f"Test Rule {i}")
            test_file.write_text(rule_yaml)
        
        # Temporarily modify PATHS
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            
            assert len(loaded_rules) == 3
            assert all(isinstance(r, SigmaRuleOCSFLite) for r in loaded_rules)
            assert all(hasattr(r, 'ocsflite') for r in loaded_rules)
        finally:
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_recursive(self, tmp_path):
        """Test that load_sigma_rules recursively scans subdirectories."""
        # Create nested directory structure
        test_dir = tmp_path / "rules" / "network"
        subdir1 = test_dir / "firewall"
        subdir2 = test_dir / "dns"
        subdir1.mkdir(parents=True)
        subdir2.mkdir(parents=True)
        
        # Create files in different subdirectories
        (subdir1 / "rule1.yml").write_text(SAMPLE_SIGMA_RULE)
        (subdir2 / "rule2.yml").write_text(
            SAMPLE_SIGMA_RULE.replace("Test Windows Logon", "DNS Rule")
        )
        
        # Temporarily modify PATHS to search from parent directory
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/network"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            
            # Should find both rules recursively
            assert len(loaded_rules) == 2
        finally:
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_yaml_and_yml_extensions(self, tmp_path):
        """Test loading both .yml and .yaml files."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        # Create files with different extensions
        (test_dir / "rule1.yml").write_text(SAMPLE_SIGMA_RULE)
        (test_dir / "rule2.yaml").write_text(
            SAMPLE_SIGMA_RULE.replace("Test Windows Logon", "YAML Rule")
        )
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            assert len(loaded_rules) == 2
        finally:
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_nonexistent_path(self, tmp_path, capsys):
        """Test handling of nonexistent paths."""
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["nonexistent/path"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            
            # Should return empty list and print warning
            assert len(loaded_rules) == 0
            captured = capsys.readouterr()
            assert "Warning: Path does not exist" in captured.out
        finally:
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_handles_invalid_yaml(self, tmp_path, capsys):
        """Test that invalid YAML files are handled gracefully."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        # Create an invalid YAML file
        (test_dir / "invalid.yml").write_text("this is not valid sigma yaml")
        
        # Create a valid file too
        (test_dir / "valid.yml").write_text(SAMPLE_SIGMA_RULE)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            
            # Should load the valid one and skip the invalid one
            assert len(loaded_rules) == 1
            captured = capsys.readouterr()
            assert "Error loading" in captured.out
        finally:
            rules.PATHS = original_paths
    
    def test_load_sigma_rules_empty_directory(self, tmp_path):
        """Test loading from an empty directory."""
        test_dir = tmp_path / "rules" / "empty"
        test_dir.mkdir(parents=True)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/empty"]
        
        try:
            loaded_rules = load_sigma_rules(base_path=str(tmp_path))
            assert len(loaded_rules) == 0
        finally:
            rules.PATHS = original_paths


class TestMappingDataclasses:
    """Tests for the mapping dataclasses."""
    
    def test_field_mapping_creation(self):
        """Test creating a FieldMapping object."""
        from fieldmapper.ocsf.rules import FieldMapping
        
        mapping = FieldMapping(
            source_field="category",
            source_value="firewall"
        )
        
        assert mapping.source_field == "category"
        assert mapping.source_value == "firewall"
        assert mapping.mapped_at is None
    
    def test_logsource_mapping_creation(self):
        """Test creating a LogSourceMapping object."""
        from fieldmapper.ocsf.rules import LogSourceMapping, FieldMapping
        
        mapping = LogSourceMapping(
            category=FieldMapping("category", "firewall"),
            product=FieldMapping("product", "cisco")
        )
        
        assert mapping.category is not None
        assert mapping.category.source_value == "firewall"
        assert mapping.product is not None
        assert mapping.product.source_value == "cisco"
        assert mapping.service is None
    
    def test_detection_field_mapping_creation(self):
        """Test creating a DetectionFieldMapping object (without source_value)."""
        from fieldmapper.ocsf.rules import DetectionFieldMapping
        
        mapping = DetectionFieldMapping(
            source_field="dst_port",
            target_table="network",
            target_field="dst_port"
        )
        
        assert mapping.source_field == "dst_port"
        assert mapping.target_table == "network"
        assert mapping.target_field == "dst_port"
        assert mapping.mapped_at is None
    
    def test_ocsflite_with_mappings(self):
        """Test OCSFLite dataclass with mapping fields."""
        from fieldmapper.ocsf.rules import OCSFLite, LogSourceMapping, DetectionFieldMapping, FieldMapping
        
        ocsf = OCSFLite(
            class_name="Network Activity",
            logsource=LogSourceMapping(
                category=FieldMapping("category", "firewall")
            ),
            detection_fields=[
                DetectionFieldMapping("dst_port", "network", "dst_port")
            ]
        )
        
        assert ocsf.class_name == "Network Activity"
        assert ocsf.logsource is not None
        assert ocsf.logsource.category.source_value == "firewall"
        assert len(ocsf.detection_fields) == 1
        assert ocsf.detection_fields[0].source_field == "dst_port"


class TestCreateMappingsMethods:
    """Tests for create_logsource_mappings and create_detection_mappings methods."""
    
    def test_create_logsource_mappings(self, tmp_path):
        """Test create_logsource_mappings method."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(SAMPLE_SIGMA_RULE)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_logsource_mappings=True,
                initialize_detection_mappings=False
            )
            
            assert len(loaded_rules) == 1
            rule = loaded_rules[0]
            
            # Check logsource mappings
            assert rule.ocsflite.logsource is not None
            assert rule.ocsflite.logsource.product is not None
            assert rule.ocsflite.logsource.product.source_field == "product"
            assert rule.ocsflite.logsource.product.source_value == "windows"
            
            assert rule.ocsflite.logsource.service is not None
            assert rule.ocsflite.logsource.service.source_value == "security"
            
            # Detection mappings should not be initialized
            assert rule.ocsflite.detection_fields is None
        finally:
            rules.PATHS = original_paths
    
    def test_create_detection_mappings(self, tmp_path):
        """Test create_detection_mappings method."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(SAMPLE_SIGMA_RULE)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_logsource_mappings=False,
                initialize_detection_mappings=True
            )
            
            assert len(loaded_rules) == 1
            rule = loaded_rules[0]
            
            # Check detection mappings
            assert rule.ocsflite.detection_fields is not None
            assert len(rule.ocsflite.detection_fields) > 0
            
            # Find the EventID field
            event_id_mapping = next(
                (m for m in rule.ocsflite.detection_fields if m.source_field == "EventID"),
                None
            )
            assert event_id_mapping is not None
            assert event_id_mapping.source_field == "EventID"
            assert event_id_mapping.target_table is None  # Not yet mapped
            assert event_id_mapping.target_field is None  # Not yet mapped
            
            # Logsource mappings should not be initialized
            assert rule.ocsflite.logsource is None
        finally:
            rules.PATHS = original_paths
    
    def test_both_mappings_initialized(self, tmp_path):
        """Test initializing both logsource and detection mappings."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(SAMPLE_SIGMA_RULE)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_logsource_mappings=True,
                initialize_detection_mappings=True
            )
            
            assert len(loaded_rules) == 1
            rule = loaded_rules[0]
            
            # Both should be initialized
            assert rule.ocsflite.logsource is not None
            assert rule.ocsflite.detection_fields is not None
        finally:
            rules.PATHS = original_paths
    
    def test_detection_mappings_unique_fields(self, tmp_path):
        """Test that detection mappings only include unique fields."""
        # Create a rule with duplicate fields
        duplicate_rule = """
title: Test Duplicate Fields
id: 12345678-1234-1234-1234-123456789012
status: test
description: Test
logsource:
    product: windows
detection:
    selection1:
        EventID: 4624
    selection2:
        EventID: 4625
    selection3:
        ComputerName: test
    condition: selection1 or selection2 or selection3
"""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(duplicate_rule)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_detection_mappings=True
            )
            
            rule = loaded_rules[0]
            
            # Should only have 2 unique fields (EventID, ComputerName)
            assert len(rule.ocsflite.detection_fields) == 2
            field_names = {m.source_field for m in rule.ocsflite.detection_fields}
            assert "EventID" in field_names
            assert "ComputerName" in field_names
        finally:
            rules.PATHS = original_paths
    
    def test_detection_mappings_list_style(self, tmp_path):
        """Test detection mappings with list-style (field modifiers)."""
        rule_yaml = """
title: Test List Style
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: windows
detection:
    selection:
        - Image|endswith: '\\\\example.exe'
        - Description|contains: 'Test'
    condition: selection
"""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(rule_yaml)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_detection_mappings=True
            )
            
            rule = loaded_rules[0]
            
            # Should extract both fields (Image, Description)
            assert rule.ocsflite.detection_fields is not None
            assert len(rule.ocsflite.detection_fields) == 2
            
            field_names = {m.source_field for m in rule.ocsflite.detection_fields}
            assert "Image" in field_names
            assert "Description" in field_names
            
            # Verify field modifiers are stripped (fields should not contain |endswith or |contains)
            for mapping in rule.ocsflite.detection_fields:
                assert "|" not in mapping.source_field
        finally:
            rules.PATHS = original_paths
    
    def test_detection_mappings_mixed_styles(self, tmp_path):
        """Test detection with both list and dict styles."""
        rule_yaml = """
title: Test Mixed Styles
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: windows
detection:
    selection1:
        - Image|endswith: '.exe'
        - CommandLine|contains: 'powershell'
    selection2:
        EventID: 4688
        ParentProcessName: 'cmd.exe'
    condition: selection1 and selection2
"""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "test_rule.yml"
        test_file.write_text(rule_yaml)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_detection_mappings=True
            )
            
            rule = loaded_rules[0]
            
            # Should extract all 4 fields from both styles
            assert rule.ocsflite.detection_fields is not None
            assert len(rule.ocsflite.detection_fields) == 4
            
            field_names = {m.source_field for m in rule.ocsflite.detection_fields}
            assert "Image" in field_names
            assert "CommandLine" in field_names
            assert "EventID" in field_names
            assert "ParentProcessName" in field_names
        finally:
            rules.PATHS = original_paths
    
    def test_detection_mappings_keyword_only(self, tmp_path):
        """Test create_detection_mappings with keyword-only detection (no fields)."""
        test_dir = tmp_path / "rules" / "test"
        test_dir.mkdir(parents=True)
        
        # Create a keyword-only detection rule (like Apache segfault)
        keyword_rule = """
title: Test Keyword Detection
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: test
description: Test rule with keyword-only detection
logsource:
    service: apache
detection:
    keywords:
        - 'exit signal Segmentation Fault'
    condition: keywords
level: high
"""
        
        test_file = test_dir / "test_keyword_rule.yml"
        test_file.write_text(keyword_rule)
        
        from fieldmapper.ocsf import rules
        original_paths = rules.PATHS
        rules.PATHS = ["rules/test"]
        
        try:
            loaded_rules = load_sigma_rules(
                base_path=str(tmp_path),
                initialize_logsource_mappings=False,
                initialize_detection_mappings=True
            )
            
            assert len(loaded_rules) == 1
            rule = loaded_rules[0]
            
            # Detection fields should be an empty list, not None
            assert rule.ocsflite.detection_fields is not None
            assert isinstance(rule.ocsflite.detection_fields, list)
            assert len(rule.ocsflite.detection_fields) == 0
        finally:
            rules.PATHS = original_paths


class TestMappingCache:
    """Tests for the MappingCache class."""
    
    def test_cache_initialization(self, tmp_path):
        """Test cache initialization."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        assert cache._cache["logsource"] == {}
        assert cache._cache["detection_fields"] == {}
    
    def test_logsource_cache_operations(self, tmp_path):
        """Test logsource cache get/set operations."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Set a mapping
        cache.set_logsource_mapping("cat:firewall", {"event_class": "Network Activity"})
        
        # Get the mapping
        result = cache.get_logsource_mapping("cat:firewall")
        assert result == {"event_class": "Network Activity"}
        
        # Non-existent key
        result = cache.get_logsource_mapping("cat:process_creation")
        assert result is None
    
    def test_detection_field_cache_operations(self, tmp_path):
        """Test detection field cache get/set operations."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Set a mapping (event_class, field_name, mapping_dict)
        cache.set_detection_field_mapping("network_activity", "dst_port", {"target_field": "dst_endpoint.port"})
        
        # Get the mapping
        result = cache.get_detection_field_mapping("network_activity", "dst_port")
        assert result == {"target_field": "dst_endpoint.port"}
        
        # Non-existent key
        result = cache.get_detection_field_mapping("network_activity", "nonexistent")
        assert result is None
    
    def test_detection_field_cache_with_context(self, tmp_path):
        """Test detection field cache."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Set mapping for Image in process_activity context
        cache.set_detection_field_mapping("process_activity", "Image", {"target_field": "process.name"})
        
        
        # Set mapping for Image in file_activity context (different target!)
        cache.set_detection_field_mapping("file_activity", "Image", {"target_field": "actor.process.name"})
        
        
        # Get mapping for process_activity context
        result = cache.get_detection_field_mapping("process_activity", "Image")
        assert result == {"target_field": "process.name"}

        # Get mapping for file_activity context (should be different!)
        result = cache.get_detection_field_mapping("file_activity", "Image")
        assert result == {"target_field": "actor.process.name"}
    
    def test_cache_persistence(self, tmp_path):
        """Test that cache persists across instances."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        
        # Create cache and add mapping
        cache1 = MappingCache(cache_file=str(cache_file))
        cache1.set_logsource_mapping("cat:firewall", {"event_class": "Network Activity"})
        
        # Create new instance and verify mapping exists
        cache2 = MappingCache(cache_file=str(cache_file))
        result = cache2.get_logsource_mapping("cat:firewall")
        assert result == {"event_class": "Network Activity"}
    
    def test_cache_clear_all(self, tmp_path):
        """Test clearing all cached mappings."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Add mappings
        cache.set_logsource_mapping("cat:firewall", {"event_class": "Network Activity"})
        cache.set_detection_field_mapping("network_activity", "dst_port", {"target_field": "dst_endpoint.port"})
        
        # Clear all
        cache.clear()
        
        assert cache.get_logsource_mapping("cat:firewall") is None
        assert cache.get_detection_field_mapping("network_activity", "dst_port") is None
    
    def test_cache_clear_specific_type(self, tmp_path):
        """Test clearing specific mapping type."""
        from fieldmapper.ocsf.ai_mapper import MappingCache, MappingType
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Add mappings
        cache.set_logsource_mapping("cat:firewall", {"event_class": "Network Activity"})
        cache.set_detection_field_mapping("network_activity", "dst_port", {"target_field": "dst_endpoint.port"})
        
        # Clear only logsource
        cache.clear(MappingType.LOGSOURCE)
        
        assert cache.get_logsource_mapping("cat:firewall") is None
        assert cache.get_detection_field_mapping("network_activity", "dst_port") is not None
    
    def test_cache_key_generation(self, tmp_path):
        """Test that cache uses context-aware keys (event_class:field_name for detection, composite for logsource)."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Detection field caching uses event_class:field_name as key
        cache.set_detection_field_mapping("process_activity", "CommandLine", {"target_field": "process.cmd_line"})
        result = cache.get_detection_field_mapping("process_activity", "CommandLine")
        assert result == {"target_field": "process.cmd_line"}
        
        # Logsource caching uses composite string keys
        cache.set_logsource_mapping("CommandLine,ParentImage", {"event_class": "system/process_activity"})
        result = cache.get_logsource_mapping("CommandLine,ParentImage")
        assert result == {"event_class": "system/process_activity"}
    
    def test_cache_stats(self, tmp_path):
        """Test cache statistics."""
        from fieldmapper.ocsf.ai_mapper import MappingCache
        
        cache_file = tmp_path / "test_cache.json"
        cache = MappingCache(cache_file=str(cache_file))
        
        # Add mappings
        cache.set_logsource_mapping("cat:firewall", {"event_class": "Network Activity"})
        cache.set_logsource_mapping("cat:process_creation", {"event_class": "Process Activity"})
        cache.set_detection_field_mapping("network_activity", "dst_port", {"target_field": "dst_endpoint.port"})
        
        stats = cache.get_stats()
        assert stats["logsource_mappings"] == 2
        assert stats["detection_field_mappings"] == 1


class TestMappingContext:
    """Tests for MappingContext class."""
    
    def test_mapping_context_creation(self):
        """Test creating a MappingContext object."""
        from fieldmapper.ocsf.ai_mapper import MappingContext
        
        # New API uses title as required field, logsource via private fields
        context = MappingContext(
            title="Test Rule",
            tags=["attack.t1078"],
            detection_field_names=["dst_port", "action"],
            _logsource_category="firewall",
            _logsource_product="cisco"
        )
        
        assert context.logsource["category"] == "firewall"
        assert context.logsource["product"] == "cisco"
        assert context.title == "Test Rule"
        assert len(context.tags) == 1
        assert len(context.detection_field_names) == 2
    
    def test_mapping_context_from_sigma_rule(self):
        """Test creating MappingContext from a SigmaRuleOCSFLite."""
        from fieldmapper.ocsf.ai_mapper import MappingContext
        from fieldmapper.ocsf.rules import load_sigma_rules
        
        # Load a test rule
        rules = load_sigma_rules(
            filename='net_firewall_cleartext_protocols.yml',
            initialize_detection_mappings=True
        )
        
        if rules:
            rule = rules[0]
            context = MappingContext.from_sigma_rule(rule)
            
            assert context.title == rule.title
            assert context.logsource["category"] == "firewall"
            assert len(context.detection_field_names) > 0


class TestFactoryMethodsAndProperties:
    """Tests for factory methods and convenience properties."""
    
    @pytest.fixture
    def sample_full_export(self):
        """Sample full export format."""
        return {
            'id': '12345678-1234-1234-1234-123456789012',
            'title': 'Suspicious Command Line',
            'status': 'test',
            'level': 'high',
            'description': 'Test rule',
            'author': 'Test Author',
            'date': '2024/01/01',
            'tags': ['attack.execution', 'attack.t1059'],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': 'powershell'
                },
                'condition': 'selection'
            },
            'ocsf_mapping': {
                'class_name': 'system/process_activity',
                'logsource': {
                    'category': {
                        'source_field': 'category',
                        'source_value': 'process_creation',
                        'mapped_at': '2024-01-01T12:00:00Z'
                    },
                    'product': {
                        'source_field': 'product',
                        'source_value': 'windows',
                        'mapped_at': '2024-01-01T12:00:00Z'
                    }
                },
                'detection_fields': [
                    {
                        'source_field': 'CommandLine',
                        'target_table': 'process_activity',
                        'target_field': 'process.cmd_line',
                        'mapped_at': '2024-01-01T12:00:00Z'
                    },
                    {
                        'source_field': 'Image',
                        'target_table': 'process_activity',
                        'target_field': 'process.name',
                        'mapped_at': '2024-01-01T12:00:00Z'
                    },
                    {
                        'source_field': 'UnknownField',
                        'target_table': 'process_activity',
                        'target_field': '<UNMAPPED>',
                        'mapped_at': '2024-01-01T12:00:00Z'
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_condensed_export(self):
        """Sample condensed export format."""
        return {
            'event_class': 'system/process_activity',
            'field_mappings': {
                'CommandLine': 'process_activity.process.cmd_line',
                'Image': 'process_activity.process.name',
                'UnknownField': '<UNMAPPED>'
            }
        }
    
    @pytest.fixture
    def temp_mapping_dir(self, sample_full_export):
        """Create temporary directory with sample mapping files."""
        import yaml
        import json
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create directory structure
            subdir = tmpdir_path / "windows" / "process_creation"
            subdir.mkdir(parents=True, exist_ok=True)
            
            # Write YAML file
            yaml_file = subdir / "test_rule.yml"
            with open(yaml_file, 'w') as f:
                yaml.dump(sample_full_export, f)
            
            # Write JSON file
            json_file = subdir / "test_rule_json.json"
            with open(json_file, 'w') as f:
                json.dump(sample_full_export, f)
            
            yield tmpdir_path
    
    # Factory Method Tests
    
    def test_from_mapping_dict_full_format(self, sample_full_export):
        """Test creating instance from full export format."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export, 'test_rule.yml')
        
        # Check basic attributes
        assert rule.title == 'Suspicious Command Line'
        assert rule.id == '12345678-1234-1234-1234-123456789012'
        assert rule.source_filename == 'test_rule.yml'
        
        # Check OCSF mapping
        assert rule.ocsflite.class_name == 'system/process_activity'
        assert len(rule.ocsflite.detection_fields) == 3
        
        # Check logsource
        assert rule.ocsflite.logsource.category.source_value == 'process_creation'
        assert rule.ocsflite.logsource.product.source_value == 'windows'
    
    def test_from_mapping_dict_condensed_format(self, sample_condensed_export):
        """Test creating instance from condensed export format."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_condensed_export, 'test_rule.yml')
        
        # Check OCSF mapping
        assert rule.ocsflite.class_name == 'system/process_activity'
        assert len(rule.ocsflite.detection_fields) == 3
        
        # Check field mappings were parsed
        field_names = [m.source_field for m in rule.ocsflite.detection_fields]
        assert 'CommandLine' in field_names
        assert 'Image' in field_names
        assert 'UnknownField' in field_names
        
        # Check mapping details
        cmd_mapping = next(m for m in rule.ocsflite.detection_fields if m.source_field == 'CommandLine')
        assert cmd_mapping.target_table == 'process_activity'
        assert cmd_mapping.target_field == 'process.cmd_line'
        
        unmapped = next(m for m in rule.ocsflite.detection_fields if m.source_field == 'UnknownField')
        assert unmapped.target_field == '<UNMAPPED>'
    
    def test_load_by_full_path_yaml(self, temp_mapping_dir):
        """Test loading by full path (YAML)."""
        yaml_file = temp_mapping_dir / "windows" / "process_creation" / "test_rule.yml"
        rule = SigmaRuleOCSFLite.load(str(yaml_file))
        
        assert rule.title == 'Suspicious Command Line'
        assert rule.ocsflite.class_name == 'system/process_activity'
    
    def test_load_by_full_path_json(self, temp_mapping_dir):
        """Test loading by full path (JSON)."""
        json_file = temp_mapping_dir / "windows" / "process_creation" / "test_rule_json.json"
        rule = SigmaRuleOCSFLite.load(str(json_file))
        
        assert rule.title == 'Suspicious Command Line'
        assert rule.ocsflite.class_name == 'system/process_activity'
    
    def test_load_by_name_search(self, temp_mapping_dir):
        """Test loading by rule name with recursive search."""
        rule = SigmaRuleOCSFLite.load("test_rule.yml", base_dir=str(temp_mapping_dir))
        
        assert rule.title == 'Suspicious Command Line'
        assert rule.ocsflite.class_name == 'system/process_activity'
    
    def test_load_by_name_without_extension(self, temp_mapping_dir):
        """Test loading by rule name without file extension."""
        rule = SigmaRuleOCSFLite.load("test_rule", base_dir=str(temp_mapping_dir))
        
        assert rule.title == 'Suspicious Command Line'
    
    def test_load_file_not_found(self):
        """Test load raises error for missing file."""
        with pytest.raises(FileNotFoundError):
            SigmaRuleOCSFLite.load("nonexistent_rule.yml")
    
    def test_load_base_dir_not_found(self):
        """Test load raises error for missing base directory."""
        with pytest.raises(FileNotFoundError):
            SigmaRuleOCSFLite.load("test_rule.yml", base_dir="nonexistent_dir")
    
    # Property Tests
    
    def test_ocsf_category_property(self, sample_full_export):
        """Test ocsf_category property."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.ocsf_category == 'system/process_activity'
    
    def test_ocsf_category_none(self):
        """Test ocsf_category returns None when not mapped."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.ocsf_category is None
    
    def test_gold_table_property(self, sample_full_export):
        """Test gold_table property extracts table name."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.gold_table == 'process_activity'
    
    def test_gold_table_none(self):
        """Test gold_table returns None when not mapped."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.gold_table is None
    
    def test_detection_fields_property(self, sample_full_export):
        """Test detection_fields property returns field names."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        fields = rule.detection_fields
        
        assert len(fields) == 3
        assert 'CommandLine' in fields
        assert 'Image' in fields
        assert 'UnknownField' in fields
    
    def test_detection_fields_empty(self):
        """Test detection_fields returns empty list when no fields."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.detection_fields == []
    
    def test_is_mapped_true(self, sample_full_export):
        """Test is_mapped returns True when mapped."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.is_mapped is True
    
    def test_is_mapped_false_none(self):
        """Test is_mapped returns False when class_name is None."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.is_mapped is False
    
    def test_is_mapped_false_unmapped(self):
        """Test is_mapped returns False when explicitly unmapped."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite(class_name="<UNMAPPED>")
        assert rule.is_mapped is False
    
    def test_has_field_mappings_true(self, sample_full_export):
        """Test has_field_mappings returns True when fields exist."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.has_field_mappings is True
    
    def test_has_field_mappings_false(self):
        """Test has_field_mappings returns False when no fields."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.has_field_mappings is False
    
    # Method Tests
    
    def test_gold_table_field_mapped(self, sample_full_export):
        """Test gold_table_field returns correct path for mapped field."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        
        assert rule.gold_table_field('CommandLine') == 'process_activity.process.cmd_line'
        assert rule.gold_table_field('Image') == 'process_activity.process.name'
    
    def test_gold_table_field_unmapped(self, sample_full_export):
        """Test gold_table_field returns None for unmapped field."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.gold_table_field('UnknownField') is None
    
    def test_gold_table_field_not_found(self, sample_full_export):
        """Test gold_table_field returns None for non-existent field."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        assert rule.gold_table_field('NonExistentField') is None
    
    def test_gold_table_field_no_mappings(self):
        """Test gold_table_field returns None when no mappings exist."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.gold_table_field('AnyField') is None
    
    def test_get_field_mappings(self, sample_full_export):
        """Test get_field_mappings returns all mappings."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        mappings = rule.get_field_mappings()
        
        assert len(mappings) == 3
        assert mappings['CommandLine'] == 'process_activity.process.cmd_line'
        assert mappings['Image'] == 'process_activity.process.name'
        assert mappings['UnknownField'] is None
    
    def test_get_field_mappings_empty(self):
        """Test get_field_mappings returns empty dict when no mappings."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.get_field_mappings() == {}
    
    def test_unmapped_fields(self, sample_full_export):
        """Test unmapped_fields returns list of unmapped fields."""
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_full_export)
        unmapped = rule.unmapped_fields()
        
        assert len(unmapped) == 1
        assert 'UnknownField' in unmapped
    
    def test_unmapped_fields_none(self, sample_condensed_export):
        """Test unmapped_fields handles None target_field."""
        # Modify sample to have None value
        sample_condensed_export['field_mappings']['NullField'] = None
        
        rule = SigmaRuleOCSFLite.from_mapping_dict(sample_condensed_export)
        unmapped = rule.unmapped_fields()
        
        assert 'NullField' in unmapped
        assert 'UnknownField' in unmapped
    
    def test_unmapped_fields_empty(self):
        """Test unmapped_fields returns empty list when no fields."""
        rule = SigmaRuleOCSFLite.__new__(SigmaRuleOCSFLite)
        rule.ocsflite = OCSFLite()
        assert rule.unmapped_fields() == []
    
    # Integration Test
    
    def test_full_workflow(self, temp_mapping_dir):
        """Test complete workflow: load -> access properties -> use methods."""
        # Load rule
        rule = SigmaRuleOCSFLite.load("test_rule", base_dir=str(temp_mapping_dir))
        
        # Check it's mapped
        assert rule.is_mapped
        assert rule.has_field_mappings
        
        # Access properties
        assert rule.ocsf_category == 'system/process_activity'
        assert rule.gold_table == 'process_activity'
        assert len(rule.detection_fields) == 3
        
        # Use methods
        for field in rule.detection_fields:
            ocsf_field = rule.gold_table_field(field)
            # Field is either mapped or None
            if field == 'UnknownField':
                assert ocsf_field is None
            else:
                assert ocsf_field is not None
                assert 'process_activity.' in ocsf_field
        
        # Check mappings dict
        mappings = rule.get_field_mappings()
        assert len(mappings) == 3
        
        # Check unmapped
        unmapped = rule.unmapped_fields()
        assert len(unmapped) == 1


class TestPipelineMappingsFieldMappings:
    """Tests for field_mappings attribute in build_pipeline_mappings()."""
    
    def test_build_from_directory(self, tmp_path):
        """Test building field mapping dict from directory of rules."""
        # Create test mapping files
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        
        # Rule 1: process_creation
        rule1 = mappings_dir / "rule1.yml"
        rule1.write_text("""
title: Test Rule 1
id: 12345678-1234-1234-1234-123456789012
status: test
description: Test process creation rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        Image: test.exe
        CommandLine: test
    condition: selection
ocsf_mapping:
    event_class: process_activity
    detection_fields:
        - source_field: EventID
          target_table: process_activity
          target_field: event_id
        - source_field: Image
          target_table: process_activity
          target_field: process.name
        - source_field: CommandLine
          target_table: process_activity
          target_field: process.cmd_line
""")
        
        # Rule 2: network activity (EventID maps to same, Image to different)
        rule2 = mappings_dir / "rule2.yml"
        rule2.write_text("""
title: Test Rule 2
id: 22345678-1234-1234-1234-123456789012
status: test
description: Test network activity rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 3
        Image: test.exe
        DestinationIp: 1.1.1.1
    condition: selection
ocsf_mapping:
    event_class: network_activity
    detection_fields:
        - source_field: EventID
          target_table: network_activity
          target_field: event_id
        - source_field: Image
          target_table: network_activity
          target_field: actor.process.name
        - source_field: DestinationIp
          target_table: network_activity
          target_field: dst_endpoint.ip
""")
        
        # Build pipeline mappings
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        
        # Both rules have same logsource (windows, security) but different tables, so they're conflicted
        # Check conflicted_rule_field_mappings for both rules
        rule1_id = "12345678-1234-1234-1234-123456789012"
        rule2_id = "22345678-1234-1234-1234-123456789012"
        
        # Rule 1 mappings (process_activity)
        assert rule1_id in mappings.conflicted_rule_field_mappings
        rule1_mappings = mappings.conflicted_rule_field_mappings[rule1_id]
        assert "EventID" in rule1_mappings
        assert rule1_mappings["EventID"] == "event_id"
        assert "Image" in rule1_mappings
        assert rule1_mappings["Image"] == "process.name"
        assert "CommandLine" in rule1_mappings
        assert rule1_mappings["CommandLine"] == "process.cmd_line"
        
        # Rule 2 mappings (network_activity)
        assert rule2_id in mappings.conflicted_rule_field_mappings
        rule2_mappings = mappings.conflicted_rule_field_mappings[rule2_id]
        assert "EventID" in rule2_mappings
        assert rule2_mappings["EventID"] == "event_id"
        assert "Image" in rule2_mappings
        assert rule2_mappings["Image"] == "actor.process.name"
        assert "DestinationIp" in rule2_mappings
        assert rule2_mappings["DestinationIp"] == "dst_endpoint.ip"
    
    def test_build_skips_unmapped_fields(self, tmp_path):
        """Test that unmapped fields are excluded."""
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        
        rule = mappings_dir / "rule.yml"
        rule.write_text("""
title: Test Rule
id: 32345678-1234-1234-1234-123456789012
status: test
description: Test rule with unmapped field
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        UnmappedField: test
    condition: selection
ocsf_mapping:
    event_class: process_activity
    detection_fields:
        - source_field: EventID
          target_table: process_activity
          target_field: event_id
        - source_field: UnmappedField
          target_table: null
          target_field: <UNMAPPED>
""")
        
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        
        # Rule has logsource (None, windows, None) - check logsource_field_mappings
        # Since there's only one rule with this logsource, it's non-conflicted
        logsource_key = (None, "windows", None)
        assert logsource_key in mappings.logsource_field_mappings
        result = mappings.logsource_field_mappings[logsource_key]
        assert "EventID" in result
        assert result["EventID"] == "event_id"
        # Check unmapped field is not in mappings
        assert "UnmappedField" not in result
    
    def test_build_empty_directory(self, tmp_path):
        """Test with empty directory."""
        mappings_dir = tmp_path / "empty"
        mappings_dir.mkdir()
        
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        
        # Empty directory should result in empty mappings
        assert mappings.logsource_field_mappings == {}
        assert mappings.conflicted_rule_field_mappings == {}
    
    def test_build_nonexistent_directory(self):
        """Test with non-existent directory."""
        with pytest.raises(FileNotFoundError):
            SigmaRuleOCSFLite.build_pipeline_mappings("/nonexistent/path")
    
    def test_build_returns_table_specific_mappings(self, tmp_path):
        """Test that results are table-specific with consistent structure."""
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        
        # Create rules with different tables
        for i, (table, field) in enumerate([("table_a", "FieldA"), ("table_b", "FieldB"), ("table_a", "FieldC")]):
            rule = mappings_dir / f"rule{i}.yml"
            rule.write_text(f"""
title: Test Rule {i}
id: {i}2345678-1234-1234-1234-123456789012
status: test
description: Test rule {i}
logsource:
    product: test
detection:
    selection:
        {field}: value
    condition: selection
ocsf_mapping:
    event_class: {table}
    detection_fields:
        - source_field: {field}
          target_table: {table}
          target_field: target.{field.lower()}
""")
        
        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        
        # All rules have same logsource (test, None, None) but different tables, so they're conflicted
        # Check conflicted_rule_field_mappings for each rule
        rule0_id = "02345678-1234-1234-1234-123456789012"
        rule1_id = "12345678-1234-1234-1234-123456789012"
        rule2_id = "22345678-1234-1234-1234-123456789012"
        
        # Rule 0: table_a, FieldA
        assert rule0_id in mappings.conflicted_rule_field_mappings
        assert "FieldA" in mappings.conflicted_rule_field_mappings[rule0_id]
        assert mappings.conflicted_rule_field_mappings[rule0_id]["FieldA"] == "target.fielda"
        
        # Rule 1: table_b, FieldB
        assert rule1_id in mappings.conflicted_rule_field_mappings
        assert "FieldB" in mappings.conflicted_rule_field_mappings[rule1_id]
        assert mappings.conflicted_rule_field_mappings[rule1_id]["FieldB"] == "target.fieldb"
        
        # Rule 2: table_a, FieldC
        assert rule2_id in mappings.conflicted_rule_field_mappings
        assert "FieldC" in mappings.conflicted_rule_field_mappings[rule2_id]
        assert mappings.conflicted_rule_field_mappings[rule2_id]["FieldC"] == "target.fieldc"


class TestPipelineMappingsFieldTypes:
    """Tests for field type mappings generated from the OCSF schema."""

    def test_build_field_types_from_schema(self, tmp_path):
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()

        rule = mappings_dir / "rule.yml"
        rule.write_text("""
title: Type Mapping Rule
id: 62345678-1234-1234-1234-123456789012
status: test
description: Rule with type-mapped fields
logsource:
    product: windows
detection:
    selection:
        ProcessId: 123
        CommandLine: test
        Time: "2024-01-01T00:00:00Z"
        Tags: Admin
        UnknownField: foo
    condition: selection
ocsf_mapping:
    event_class: process_activity
    detection_fields:
        - source_field: ProcessId
          target_table: process_activity
          target_field: process.pid
        - source_field: CommandLine
          target_table: process_activity
          target_field: process.cmd_line
        - source_field: Time
          target_table: process_activity
          target_field: time
        - source_field: Tags
          target_table: process_activity
          target_field: metadata.tags
        - source_field: UnknownField
          target_table: process_activity
          target_field: unknown.field
""")

        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        logsource_key = (None, "windows", None)

        assert logsource_key in mappings.logsource_field_type_mappings
        field_types = mappings.logsource_field_type_mappings[logsource_key]

        assert field_types["process.pid"] == "INT"
        assert field_types["process.cmd_line"] == "STRING"
        assert field_types["time"] == "TIMESTAMP"
        assert field_types["metadata.tags"] == "VARIANT"
        assert "unknown.field" not in field_types

    def test_build_field_types_normalizes_and_arrays(self, tmp_path):
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()

        rule_ssh = mappings_dir / "rule_ssh.yml"
        rule_ssh.write_text("""
title: SSH Type Rule
id: 72345678-1234-1234-1234-123456789012
status: test
logsource:
    product: ssh
    service: auth
detection:
    selection:
        TypeUid: 1
    condition: selection
ocsf_mapping:
    event_class: ssh_activity
    detection_fields:
        - source_field: TypeUid
          target_table: ssh_activity
          target_field: type_uid
""")

        rule_dns = mappings_dir / "rule_dns.yml"
        rule_dns.write_text("""
title: DNS Array Rule
id: 82345678-1234-1234-1234-123456789012
status: test
logsource:
    product: dns
    service: resolver
detection:
    selection:
        Flags: test
        FlagIds: 1
    condition: selection
ocsf_mapping:
    event_class: dns_activity
    detection_fields:
        - source_field: Flags
          target_table: dns_activity
          target_field: answers.flags
        - source_field: FlagIds
          target_table: dns_activity
          target_field: answers.flag_ids
""")

        rule_vuln = mappings_dir / "rule_vuln.yml"
        rule_vuln.write_text("""
title: Vulnerability Array Rule
id: 92345678-1234-1234-1234-123456789012
status: test
logsource:
    product: vuln
    service: scanner
detection:
    selection:
        Related: abc
    condition: selection
ocsf_mapping:
    event_class: vulnerability_finding
    detection_fields:
        - source_field: Related
          target_table: vulnerability_finding
          target_field: finding_info.analytic.related_analytics
""")

        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))

        key_ssh = (None, "ssh", "auth")
        key_dns = (None, "dns", "resolver")
        key_vuln = (None, "vuln", "scanner")

        assert mappings.logsource_field_type_mappings[key_ssh]["type_uid"] == "BIGINT"
        assert mappings.logsource_field_type_mappings[key_dns]["answers.flags"] == "ARRAY<STRING>"
        assert mappings.logsource_field_type_mappings[key_dns]["answers.flag_ids"] == "ARRAY<INT>"
        assert mappings.logsource_field_type_mappings[key_vuln]["finding_info.analytic.related_analytics"] == "ARRAY<VARIANT>"

    def test_build_field_parent_info_arrays(self, tmp_path):
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()

        rule = mappings_dir / "rule_auth.yml"
        rule.write_text("""
title: Auth Array Parent Rule
id: a2345678-1234-1234-1234-123456789012
status: test
logsource:
    product: m365
    service: threat_management
detection:
    selection:
        Status: success
    condition: selection
ocsf_mapping:
    event_class: authentication
    detection_fields:
        - source_field: Status
          target_table: authentication
          target_field: actor.authorizations.decision
""")

        mappings = SigmaRuleOCSFLite.build_pipeline_mappings(str(mappings_dir))
        key_auth = (None, "m365", "threat_management")
        parent_info = mappings.logsource_field_parent_mappings[key_auth]["actor.authorizations.decision"]
        assert parent_info["parent_path"] == "actor.authorizations"
        assert parent_info["parent_type"] == "ARRAY<STRUCT>"
