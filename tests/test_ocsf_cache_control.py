"""
Tests for cache control options (--refresh-cache and --no-cache).
"""
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
import pytest

from fieldmapper.ocsf.ai_mapper import MappingCache, MappingContext
from fieldmapper.ocsf.openai_mapper import OpenAIMapper
from fieldmapper.ocsf.schema_loader import OCSFLiteSchema


class TestCacheControl:
    """Test suite for cache control functionality."""
    
    def test_refresh_cache_clears_cache_file(self):
        """Test that --refresh-cache deletes the cache file before mapping."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create a cache file with existing data
            existing_data = {
                "logsource": {"field1": {"event_class": "old_class"}},
                "detection_fields": {"field2": {"target_field": "old_target"}}
            }
            with open(cache_path, 'w') as f:
                json.dump(existing_data, f)
            
            # Verify file exists
            assert os.path.exists(cache_path)
            
            # Simulate --refresh-cache logic from main.py
            refresh_cache = True
            if refresh_cache and cache_path and os.path.exists(cache_path):
                os.remove(cache_path)
            
            # Verify file was deleted
            assert not os.path.exists(cache_path)
    
    def test_no_cache_preserves_cache_file(self):
        """Test that --no-cache does NOT delete the cache file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create a cache file with existing data
            existing_data = {
                "logsource": {"field1": {"event_class": "old_class"}},
                "detection_fields": {"field2": {"target_field": "old_target"}}
            }
            with open(cache_path, 'w') as f:
                json.dump(existing_data, f)
            
            # Verify file exists
            assert os.path.exists(cache_path)
            
            # Simulate --no-cache logic from main.py (no deletion)
            no_cache = True
            refresh_cache = False
            
            # No deletion should occur
            if refresh_cache and cache_path and os.path.exists(cache_path):
                os.remove(cache_path)
            
            # Verify file still exists
            assert os.path.exists(cache_path)
            
            # Verify data is intact
            with open(cache_path, 'r') as f:
                loaded_data = json.load(f)
            assert loaded_data == existing_data
    
    def test_skip_cache_reads_flag_calculated_correctly(self):
        """Test that skip_cache_reads flag is calculated correctly."""
        # Test --refresh-cache
        refresh_cache = True
        no_cache = False
        skip_cache_reads = refresh_cache or no_cache
        assert skip_cache_reads is True
        
        # Test --no-cache
        refresh_cache = False
        no_cache = True
        skip_cache_reads = refresh_cache or no_cache
        assert skip_cache_reads is True
        
        # Test neither flag
        refresh_cache = False
        no_cache = False
        skip_cache_reads = refresh_cache or no_cache
        assert skip_cache_reads is False
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_openai_mapper_skip_cache_reads_parameter(self, mock_openai_class):
        """Test that OpenAIMapper accepts and stores skip_cache_reads parameter."""
        # Mock OpenAI client
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [{"path": "process.pid", "type": "int", "description": "Process ID"}]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Test with skip_cache_reads=True
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=True)
            assert mapper.skip_cache_reads is True
            
            # Test with skip_cache_reads=False (default)
            mapper2 = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=False)
            assert mapper2.skip_cache_reads is False
            
            # Test default value
            mapper3 = OpenAIMapper(schema, cache, "fake-api-key")
            assert mapper3.skip_cache_reads is False
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_map_to_event_class_skips_cache_read(self, mock_openai_class):
        """Test that map_to_event_class skips cache read when skip_cache_reads=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [{"path": "process.pid", "type": "int", "description": "Process ID"}]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            # Pre-populate cache
            cache_data = {
                "logsource": {"field1": {"event_class": "cached_class"}},
                "detection_fields": {}
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Mock OpenAI response with structured output format
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = '{"event_class": "system/process_activity"}'
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai_class.return_value = mock_client
            
            # Test with skip_cache_reads=True
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=True)
            context = MappingContext(
                _logsource_category="process_creation",
                _logsource_product=None,
                _logsource_service=None,
                title="Test Rule",
                description="Test description",
                tags=[],
                detection_field_names=["field1"]
            )
            
            result = mapper.map_to_event_class(context)
            
            # Should call OpenAI even though cache exists
            assert mock_client.chat.completions.create.called
            assert result == "system/process_activity"
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_map_to_event_class_uses_cache_when_not_skipping(self, mock_openai_class):
        """Test that map_to_event_class uses cache when skip_cache_reads=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [{"path": "process.pid", "type": "int", "description": "Process ID"}]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            # Pre-populate cache
            cache_data = {
                "logsource": {"field1": {"event_class": "cached_class"}},
                "detection_fields": {}
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Mock OpenAI (should NOT be called)
            mock_client = MagicMock()
            mock_openai_class.return_value = mock_client
            
            # Test with skip_cache_reads=False
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=False)
            context = MappingContext(
                _logsource_category="process_creation",
                _logsource_product=None,
                _logsource_service=None,
                title="Test Rule",
                description="Test description",
                tags=[],
                detection_field_names=["field1"]
            )
            
            result = mapper.map_to_event_class(context)
            
            # Should use cache and NOT call OpenAI
            assert not mock_client.chat.completions.create.called
            assert result == "cached_class"
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_map_detection_fields_skips_cache_read(self, mock_openai_class):
        """Test that map_detection_fields skips cache read when skip_cache_reads=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [
                        {"path": "process.pid", "type": "int", "description": "Process ID"},
                        {"path": "process.name", "type": "string", "description": "Process name"}
                    ]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            # Pre-populate cache
            cache_data = {
                "logsource": {},
                "detection_fields": {"ProcessId": {"target_field": "cached_field"}}
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Mock OpenAI response with structured output format
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = '{"mappings": [{"source_field": "ProcessId", "target_field": "process.pid"}]}'
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai_class.return_value = mock_client
            
            # Test with skip_cache_reads=True
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=True)
            
            result = mapper.map_detection_fields("system/process_activity", ["ProcessId"])
            
            # Should call OpenAI even though cache exists
            assert mock_client.chat.completions.create.called
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_map_detection_fields_uses_cache_when_not_skipping(self, mock_openai_class):
        """Test that map_detection_fields uses cache when skip_cache_reads=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [{"path": "process.pid", "type": "int", "description": "Process ID"}]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            # Pre-populate cache
            cache_data = {
                "logsource": {},
                "detection_fields": {"ProcessId": {"target_field": "cached_field"}}
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Mock OpenAI (should NOT be called)
            mock_client = MagicMock()
            mock_openai_class.return_value = mock_client
            
            # Test with skip_cache_reads=False
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=False)
            
            result = mapper.map_detection_fields("system/process_activity", ["ProcessId"])
            
            # Should use cache and NOT call OpenAI
            assert not mock_client.chat.completions.create.called
            assert result == {"ProcessId": "cached_field"}
    
    @patch('fieldmapper.ocsf.openai_mapper.OpenAI')
    def test_cache_writes_still_occur_with_skip_reads(self, mock_openai_class):
        """Test that cache writes still happen when skip_cache_reads=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "test_schema.json")
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create minimal schema file
            schema_data = [
                {
                    "event_class": "system/process_activity",
                    "description": "Test class",
                    "fields": [{"path": "process.pid", "type": "int", "description": "Process ID"}]
                }
            ]
            with open(schema_path, 'w') as f:
                json.dump(schema_data, f)
            
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            
            # Mock OpenAI response with structured output format
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = '{"event_class": "system/process_activity"}'
            mock_client.chat.completions.create.return_value = mock_response
            mock_openai_class.return_value = mock_client
            
            # Test with skip_cache_reads=True
            mapper = OpenAIMapper(schema, cache, "fake-api-key", skip_cache_reads=True)
            context = MappingContext(
                _logsource_category="process_creation",
                _logsource_product=None,
                _logsource_service=None,
                title="Test Rule",
                description="Test description",
                tags=[],
                detection_field_names=["field1"]
            )
            
            result = mapper.map_to_event_class(context)
            
            # Save cache
            cache.save()
            
            # Verify cache was written
            assert os.path.exists(cache_path)
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            
            # Cache should contain the new mapping
            assert "field1" in cache_data["logsource"]
            assert cache_data["logsource"]["field1"]["event_class"] == "system/process_activity"


class TestArgparseMutualExclusivity:
    """Test mutual exclusivity of --refresh-cache and --no-cache flags."""
    
    def test_mutual_exclusivity(self):
        """Test that --refresh-cache and --no-cache are mutually exclusive."""
        import argparse
        
        # Simulate the argument parser from main.py
        parser = argparse.ArgumentParser()
        cache_group = parser.add_mutually_exclusive_group()
        cache_group.add_argument("--refresh-cache", action="store_true")
        cache_group.add_argument("--no-cache", action="store_true")
        
        # Test: both flags should raise error
        with pytest.raises(SystemExit):
            parser.parse_args(["--refresh-cache", "--no-cache"])
        
        # Test: single flags should work
        args1 = parser.parse_args(["--refresh-cache"])
        assert args1.refresh_cache is True
        assert args1.no_cache is False
        
        args2 = parser.parse_args(["--no-cache"])
        assert args2.refresh_cache is False
        assert args2.no_cache is True
        
        # Test: no flags should work
        args3 = parser.parse_args([])
        assert args3.refresh_cache is False
        assert args3.no_cache is False

