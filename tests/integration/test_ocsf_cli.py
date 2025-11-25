"""
Tests for fieldmapper.ocsf.cli CLI layer and display functions.
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fieldmapper.ocsf.cli import print_separator, print_rule_details, print_summary, main
from fieldmapper.ocsf.rules import SigmaRuleOCSFLite, OCSFLite
from sigma.rule import SigmaRule, SigmaLogSource


class TestDisplayFunctions:
    """Test suite for display/print functions."""
    
    @pytest.fixture
    def mock_rule(self):
        """Create a mock rule for display testing."""
        sigma_rule = MagicMock(spec=SigmaRule)
        sigma_rule.title = "Test Rule"
        sigma_rule.id = "test-id-123"
        sigma_rule.level = "high"
        sigma_rule.status = "stable"
        sigma_rule.author = "Test Author"
        sigma_rule.date = "2024-01-01"
        sigma_rule.modified = "2024-01-15"
        sigma_rule.description = "Test description"
        sigma_rule.tags = ["attack.t1234", "attack.execution"]
        sigma_rule.references = ["https://example.com"]
        sigma_rule.fields = ["ProcessName", "CommandLine"]
        
        sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
        sigma_rule.logsource.category = "process_creation"
        sigma_rule.logsource.product = "windows"
        sigma_rule.logsource.service = None
        
        sigma_rule.detection = MagicMock()
        sigma_rule.detection.detections = {"selection": {}, "condition": {}}
        sigma_rule.detection.condition = "selection"
        
        rule_ocsf = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, "test.yml")
        return rule_ocsf
    
    def test_print_separator(self, capsys):
        """Test print_separator function."""
        print_separator()
        captured = capsys.readouterr()
        assert captured.out == "=" * 80 + "\n"
        
        print_separator(char="-", length=40)
        captured = capsys.readouterr()
        assert captured.out == "-" * 40 + "\n"
    
    def test_print_rule_details(self, capsys, mock_rule):
        """Test print_rule_details function outputs expected content."""
        print_rule_details(mock_rule, index=1)
        captured = capsys.readouterr()
        
        # Verify key information is present
        assert "RULE #1" in captured.out
        assert "Test Rule" in captured.out
        assert "test-id-123" in captured.out
        assert "high" in captured.out
        assert "stable" in captured.out
        assert "Test Author" in captured.out
        assert "process_creation" in captured.out
        assert "windows" in captured.out
    
    def test_print_rule_details_without_index(self, capsys, mock_rule):
        """Test print_rule_details without index parameter."""
        print_rule_details(mock_rule)
        captured = capsys.readouterr()
        
        # Should not have RULE # header
        assert "RULE #" not in captured.out
        assert "Test Rule" in captured.out
    
    def test_print_summary_empty_rules(self, capsys):
        """Test print_summary with empty rules list."""
        print_summary([])
        captured = capsys.readouterr()
        
        assert "0 Rules Loaded" in captured.out
        assert "No rules were loaded" in captured.out
    
    def test_print_summary_with_rules(self, capsys, mock_rule):
        """Test print_summary with rules list."""
        rules = [mock_rule, mock_rule]
        print_summary(rules)
        captured = capsys.readouterr()
        
        assert "2 Rules Loaded" in captured.out
        assert "Test Rule" in captured.out
        assert "Statistics:" in captured.out
        assert "By Log Source:" in captured.out


class TestCLIMain:
    """Test suite for CLI main entry point."""
    
    @pytest.fixture
    def mock_successful_result(self):
        """Mock successful converter result."""
        return {
            'success': True,
            'error': None,
            'rules': [],
            'stats': {
                'total': 5,
                'success_count': 4,
                'skipped_count': 1,
                'error_count': 0,
                'output_dir': None,
                'cache_path': '.mapping_cache.json'
            }
        }
    
    @pytest.fixture
    def mock_error_result(self):
        """Mock error converter result."""
        return {
            'success': False,
            'error': 'Test error message',
            'rules': [],
            'stats': {
                'total': 0,
                'success_count': 0,
                'skipped_count': 0,
                'error_count': 0
            }
        }
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_help_flag(self, mock_converter):
        """Test that --help flag works."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['cli.py', '--help']):
                main()
        
        # --help causes SystemExit with code 0
        assert exc_info.value.code == 0
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_basic_invocation(self, mock_converter, mock_successful_result, capsys):
        """Test basic CLI invocation without mapping."""
        # Create a mock rule
        sigma_rule = MagicMock(spec=SigmaRule)
        sigma_rule.title = "Test Rule"
        sigma_rule.id = "test-123"
        sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
        sigma_rule.logsource.product = "test"
        rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, "test.yml")
        
        result = mock_successful_result.copy()
        result['rules'] = [rule]
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py']):
            main()
        
        captured = capsys.readouterr()
        assert "Loading Sigma rules" in captured.out
        assert "Loaded 5 rule(s)" in captured.out
        
        # Verify converter was called
        mock_converter.assert_called_once()
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_handles_error_result(self, mock_converter, mock_error_result, capsys):
        """Test that main handles error results properly."""
        mock_converter.return_value = mock_error_result
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['cli.py']):
                main()
        
        captured = capsys.readouterr()
        assert "Error: Test error message" in captured.out
        assert exc_info.value.code == 1
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_with_error_hint(self, mock_converter, capsys):
        """Test that error hints are displayed."""
        result = {
            'success': False,
            'error': 'Schema not found',
            'error_hint': 'Run schema generator first',
            'rules': [],
            'stats': {'total': 0}
        }
        mock_converter.return_value = result
        
        with pytest.raises(SystemExit):
            with patch('sys.argv', ['cli.py']):
                main()
        
        captured = capsys.readouterr()
        assert "Error: Schema not found" in captured.out
        assert "Run schema generator first" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_output_requires_map(self, mock_converter, capsys):
        """Test that --output flag requires --map."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['cli.py', '--output', 'outdir']):
                main()
        
        captured = capsys.readouterr()
        assert "Error: --output requires --map flag" in captured.out
        assert exc_info.value.code == 1
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_with_mapping_displays_progress(self, mock_converter, capsys):
        """Test that mapping progress is displayed."""
        # Create mock rules
        rules = []
        for i in range(3):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'error': None,
            'rules': rules,
            'stats': {
                'total': 3,
                'success_count': 3,
                'skipped_count': 0,
                'error_count': 0,
                'cache_path': '.mapping_cache.json'
            }
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--api-key', 'test-key']):
            main()
        
        captured = capsys.readouterr()
        assert "Mapping 3 rules using AI" in captured.out
        assert "[1/3] Test Rule 1" in captured.out
        assert "[2/3] Test Rule 2" in captured.out
        assert "[3/3] Test Rule 3" in captured.out
        assert "Mapping complete!" in captured.out
        assert "Successful: 3/3" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_displays_skipped_count(self, mock_converter, capsys):
        """Test that skipped rules count is displayed."""
        # Create mock rules
        rules = []
        for i in range(5):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'rules': rules,
            'stats': {
                'total': 5,
                'success_count': 3,
                'skipped_count': 2,
                'error_count': 0,
                'cache_path': '.mapping_cache.json'
            }
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--api-key', 'test-key']):
            main()
        
        captured = capsys.readouterr()
        assert "Skipped: 2 (keyword-based detection)" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_displays_error_count(self, mock_converter, capsys):
        """Test that error count and details are displayed."""
        # Create mock rules
        rules = []
        for i in range(5):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'rules': rules,
            'stats': {
                'total': 5,
                'success_count': 3,
                'skipped_count': 0,
                'error_count': 2,
                'cache_path': '.mapping_cache.json'
            },
            'rule_errors': [
                {'rule': 'Rule 1', 'error': 'Mapping failed'},
                {'rule': 'Rule 2', 'error': 'Invalid field'}
            ]
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--api-key', 'test-key']):
            main()
        
        captured = capsys.readouterr()
        assert "Errors: 2" in captured.out
        assert "Rule 1: Mapping failed" in captured.out
        assert "Rule 2: Invalid field" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_with_limit_displays_info(self, mock_converter, capsys):
        """Test that limit information is displayed."""
        # Create mock rules
        rules = []
        for i in range(5):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'rules': rules,
            'stats': {
                'total': 5,
                'limited_from': 20,
                'success_count': 5,
                'skipped_count': 0,
                'error_count': 0,
                'cache_path': '.mapping_cache.json'
            }
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--limit', '5', '--api-key', 'test-key']):
            main()
        
        captured = capsys.readouterr()
        assert "Limiting to first 5 rules" in captured.out
        assert "out of 20 total" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_with_export_displays_info(self, mock_converter, capsys):
        """Test that export information is displayed."""
        # Create mock rules
        rules = []
        for i in range(3):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'rules': rules,
            'stats': {
                'total': 3,
                'success_count': 3,
                'skipped_count': 0,
                'error_count': 0,
                'output_dir': '/tmp/output',
                'cache_path': '.mapping_cache.json'
            }
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--api-key', 'test-key', '--output', '/tmp/output']):
            main()
        
        captured = capsys.readouterr()
        assert "Exporting rules to /tmp/output" in captured.out
        assert "format: YAML" in captured.out
        assert "Exported to: /tmp/output" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_with_json_export(self, mock_converter, capsys):
        """Test that JSON export format is shown."""
        # Create mock rules
        rules = []
        for i in range(3):
            sigma_rule = MagicMock(spec=SigmaRule)
            sigma_rule.title = f"Test Rule {i+1}"
            sigma_rule.id = f"test-{i+1}"
            sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
            sigma_rule.logsource.product = "test"
            rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, f"test_{i+1}.yml")
            rules.append(rule)
        
        result = {
            'success': True,
            'rules': rules,
            'stats': {
                'total': 3,
                'success_count': 3,
                'skipped_count': 0,
                'error_count': 0,
                'output_dir': '/tmp/output',
                'cache_path': '.mapping_cache.json'
            }
        }
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--map', '--api-key', 'test-key', '--output', '/tmp/output', '--json']):
            main()
        
        captured = capsys.readouterr()
        assert "format: JSON" in captured.out
    
    @patch('fieldmapper.ocsf.analyze_mappings.analyze_directory')
    @patch('fieldmapper.ocsf.analyze_mappings.generate_report')
    def test_main_analyze_mode(self, mock_generate_report, mock_analyze, capsys):
        """Test --analyze mode."""
        mock_analyze.return_value = ({}, [])
        mock_generate_report.return_value = "Test report"
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['cli.py', '--analyze', '/tmp/mappings']):
                main()
        
        captured = capsys.readouterr()
        assert "Test report" in captured.out
        assert exc_info.value.code == 0
    
    @patch('fieldmapper.ocsf.analyze_mappings.analyze_directory')
    def test_main_analyze_mode_file_not_found(self, mock_analyze, capsys):
        """Test --analyze mode with missing directory."""
        mock_analyze.side_effect = FileNotFoundError("Directory not found")
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['cli.py', '--analyze', '/nonexistent']):
                main()
        
        captured = capsys.readouterr()
        assert "Error: Directory not found" in captured.out
        assert exc_info.value.code == 1
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_details_flag(self, mock_converter, mock_successful_result, capsys):
        """Test --details flag triggers detailed output."""
        # Create a mock rule with all required attributes
        sigma_rule = MagicMock(spec=SigmaRule)
        sigma_rule.title = "Detailed Test Rule"
        sigma_rule.id = "detail-123"
        sigma_rule.level = "high"
        sigma_rule.status = "stable"
        sigma_rule.author = "Test Author"
        sigma_rule.date = "2024-01-01"
        sigma_rule.modified = "2024-01-15"
        sigma_rule.description = "Test description"
        sigma_rule.tags = ["attack.t1234"]
        sigma_rule.references = ["https://example.com"]
        sigma_rule.fields = ["Field1"]
        sigma_rule.logsource = MagicMock(spec=SigmaLogSource)
        sigma_rule.logsource.product = "test"
        sigma_rule.logsource.category = None
        sigma_rule.logsource.service = None
        sigma_rule.detection = MagicMock()
        sigma_rule.detection.detections = {"selection": {}}
        sigma_rule.detection.condition = "selection"
        
        rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, "test.yml")
        
        result = mock_successful_result.copy()
        result['rules'] = [rule]
        mock_converter.return_value = result
        
        with patch('sys.argv', ['cli.py', '--details']):
            main()
        
        captured = capsys.readouterr()
        # Should show detailed rule information
        assert "Detailed Test Rule" in captured.out
        assert "detail-123" in captured.out
    
    @patch('fieldmapper.ocsf.cli.load_and_process_rules')
    def test_main_passes_all_parameters(self, mock_converter, mock_successful_result):
        """Test that all CLI parameters are passed to converter."""
        mock_converter.return_value = mock_successful_result
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'cli.py',
                '--map',
                '--api-key', 'test-key',
                '--schema', 'custom_schema.json',
                '--cache', 'custom_cache.json',
                '--debug-prompt',
                '--refresh-cache',
                '--output', '/tmp/out',
                '--full',
                '--json',
                '--limit', '10'
            ]):
                main()
        
        assert exc_info.value.code == 0
        
        # Verify converter was called with correct parameters
        mock_converter.assert_called_once()
        call_kwargs = mock_converter.call_args[1]
        assert call_kwargs['map_rules'] is True
        assert call_kwargs['api_key'] == 'test-key'
        assert call_kwargs['schema_path'] == 'custom_schema.json'
        assert call_kwargs['cache_path'] == 'custom_cache.json'
        assert call_kwargs['debug_prompts'] is True
        assert call_kwargs['refresh_cache'] is True
        assert call_kwargs['output_dir'] == '/tmp/out'
        assert call_kwargs['full_export'] is True
        assert call_kwargs['json_format'] is True
        assert call_kwargs['limit'] == 10
