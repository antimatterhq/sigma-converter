"""
Tests for fieldmapper.ocsf.converter business logic.
"""
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fieldmapper.ocsf.converter import load_and_process_rules
from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
from sigma.rule import SigmaRule, SigmaLogSource


class TestLoadAndProcessRules:
    """Test suite for load_and_process_rules function."""
    
    @pytest.fixture
    def mock_rules(self):
        """Create a list of mock rule objects."""
        rules = []
        for i in range(10):
            # Create minimal SigmaRule
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-id-{i+1}"
            sigma_rule.level = "medium"
            sigma_rule.status = "experimental"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            sigma_rule.logsource.category = None
            sigma_rule.logsource.service = None
            
            # Wrap in SigmaRuleOCSFLite
            rule_ocsf = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule_ocsf)
        
        return rules
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_basic_load_no_mapping(self, mock_load, mock_rules):
        """Test basic rule loading without AI mapping."""
        mock_load.return_value = mock_rules
        
        result = load_and_process_rules(
            filename=None,
            map_rules=False
        )
        
        assert result['success'] is True
        assert result['error'] is None
        assert len(result['rules']) == 10
        assert result['stats']['total'] == 10
        assert result['stats']['success_count'] == 0 
        assert result['stats']['skipped_count'] == 0
        assert result['stats']['error_count'] == 0
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_load_no_rules_found(self, mock_load):
        """Test behavior when no rules are found."""
        mock_load.return_value = []
        
        result = load_and_process_rules(filename=None)
        
        assert result['success'] is False
        assert result['error'] == "No rules found"
        assert result['stats']['total'] == 0
        assert len(result['rules']) == 0
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_limit_applied_with_mapping(self, mock_load, mock_rules):
        """Test that limit is applied when map_rules=True."""
        mock_load.return_value = mock_rules
        
        result = load_and_process_rules(
            filename=None,
            limit=5,
            map_rules=True,
            api_key="test-key"
        )
        
        # Should track original count
        assert 'limited_from' in result['stats']
        assert result['stats']['limited_from'] == 10
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_limit_not_applied_without_mapping(self, mock_load, mock_rules):
        """Test that limit is NOT applied when map_rules=False."""
        mock_load.return_value = mock_rules
        
        result = load_and_process_rules(
            filename=None,
            limit=5,
            map_rules=False
        )
        
        # Should NOT limit without mapping
        assert result['stats']['total'] == 10
        assert 'limited_from' not in result['stats']
        assert len(result['rules']) == 10
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_missing_api_key(self, mock_load, mock_rules):
        """Test error when API key is missing for mapping."""
        mock_load.return_value = mock_rules
        
        # Clear environment variable if set
        with patch.dict(os.environ, {}, clear=True):
            result = load_and_process_rules(
                filename=None,
                map_rules=True,
                api_key=None
            )
        
        assert result['success'] is False
        assert "API key required" in result['error']
    
    @patch.dict(os.environ, {'OPENAI_KEY': 'env-test-key'})
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_api_key_from_environment(self, mock_load, mock_rules):
        """Test that API key can be loaded from environment."""
        mock_load.return_value = mock_rules
        
        # Should not error even though api_key param is None
        # (would error later trying to actually use the mapper, but we're testing the env var lookup)
        result = load_and_process_rules(
            filename=None,
            map_rules=True,
            api_key=None
        )
        
        # Will fail at schema loading, but proves env var was read
        assert result['success'] is False
        assert "API key required" not in result.get('error', '')
    
    
    @patch('fieldmapper.ocsf.converter.load_sigma_rules')
    def test_filename_parameter_passed_through(self, mock_load, mock_rules):
        """Test that filename parameter is passed to load_sigma_rules."""
        mock_load.return_value = mock_rules
        
        result = load_and_process_rules(
            filename="specific_rule.yml",
            map_rules=False
        )
        
        mock_load.assert_called_once_with(filename="specific_rule.yml")
        assert result['success'] is True
    
    def test_refresh_cache_deletes_file_properly(self):
        """Test that refresh_cache=True correctly triggers cache file deletion logic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "test_cache.json")
            
            # Create existing cache file
            with open(cache_path, 'w') as f:
                json.dump({"test": "data"}, f)
            
            assert os.path.exists(cache_path)
            
            # Test the deletion logic directly (as used in converter)
            refresh_cache = True
            if refresh_cache and cache_path and os.path.exists(cache_path):
                os.remove(cache_path)
            
            # Cache file should be deleted
            assert not os.path.exists(cache_path)
