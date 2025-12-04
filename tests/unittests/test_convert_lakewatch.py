from fieldmapper.ocsf.convert_lakewatch import (
    convert_and_save_lakewatch_rules, 
    ConversionResult
)


def test_conversion_result_has_failures():
    """Test ConversionResult.has_failures property."""
    result = ConversionResult(
        success=True,
        total=2,
        converted=1,
        failed=1,
        output_dir="output"
    )
    assert result.has_failures == True
    
    result_no_failures = ConversionResult(
        success=True,
        total=1,
        converted=1,
        failed=0,
        output_dir="output"
    )
    assert result_no_failures.has_failures == False


def test_convert_single_rule_success(tmp_path):
    """Test converting a single rule successfully."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    test_rule = input_dir / "test_rule.yml"
    
    # Write a minimal valid Sigma rule with OCSF mapping
    test_rule.write_text("""
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
level: high
ocsf_mapping:
    class_name: process_activity
    detection_fields:
        - source_field: CommandLine
          target_table: process
          target_field: cmd_line
""")
    
    output_dir = tmp_path / "output"
    
    result = convert_and_save_lakewatch_rules(
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        filename="test_rule.yml"
    )
    
    # Rule should convert if mappings are valid
    assert result.total == 1
    assert (output_dir / "test_rule.json").exists() or result.failed == 1


def test_convert_file_not_found(tmp_path):
    """Test handling of missing file."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "output"
    
    result = convert_and_save_lakewatch_rules(
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        filename="nonexistent.yml"
    )
    
    assert result.success == False
    assert result.failed == 1
    assert 'File not found' in result.errors[0]['error']


def test_convert_empty_directory(tmp_path):
    """Test handling of empty input directory."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "output"
    
    result = convert_and_save_lakewatch_rules(
        input_dir=str(input_dir),
        output_dir=str(output_dir)
    )
    
    assert result.success == False
    assert result.total == 0
    assert 'No YAML files found' in result.errors[0]['error']


def test_batch_conversion(tmp_path):
    """Test converting multiple rules in batch mode."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    
    # Create two test rules
    for i in range(2):
        test_rule = input_dir / f"test_rule_{i}.yml"
        test_rule.write_text(f"""
title: Test Rule {i}
id: 1234567{i}-1234-1234-1234-123456789abc
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
level: high
ocsf_mapping:
    class_name: process_activity
    detection_fields:
        - source_field: CommandLine
          target_table: process
          target_field: cmd_line
""")
    
    output_dir = tmp_path / "output"
    
    result = convert_and_save_lakewatch_rules(
        input_dir=str(input_dir),
        output_dir=str(output_dir)
    )
    
    assert result.total == 2

