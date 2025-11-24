"""
Utility functions for exporting Sigma rules to YAML/JSON files.
"""
import json
import yaml
from pathlib import Path
from typing import List
from fieldmapper.ocsf.rules import SigmaRuleOCSFLite


# Custom YAML dumper to match Sigma formatting conventions
class SigmaYAMLDumper(yaml.SafeDumper):
    """Custom YAML dumper that formats output to match Sigma rule conventions."""
    
    def increase_indent(self, flow=False, indentless=False):
        # Force indentation for list items to match Sigma format
        return super().increase_indent(flow, False)
    
    def represent_none(self, _):
        return self.represent_scalar('tag:yaml.org,2002:null', 'null')

SigmaYAMLDumper.add_representer(type(None), SigmaYAMLDumper.represent_none)


def export_rule_to_file(
    rule: SigmaRuleOCSFLite, 
    output_dir: Path, 
    format: str = 'yaml', 
    full: bool = False
) -> Path:
    """
    Export a single rule to a YAML or JSON file.
    
    Args:
        rule: The rule to export
        output_dir: Directory to write the file to
        format: 'yaml' or 'json'
        full: If False (default), export only field mappings. If True, export full rule details.
    
    Returns:
        Path to the written file
    """
    # Ensure output_dir is a Path object
    output_dir = Path(output_dir)
    
    # Get the export dictionary
    export_data = rule.to_export_dict(full=full)
    
    # Determine output filename (keep original name, change extension)
    if rule.source_filename:
        # Use the original filename with swapped extension
        base_name = Path(rule.source_filename).stem
    else:
        # Fallback to rule ID or title
        base_name = str(rule.id) if rule.id else rule.title.replace(' ', '_').lower()
    
    # Set extension based on format
    extension = '.json' if format == 'json' else '.yml'
    output_file = output_dir / f"{base_name}{extension}"
    
    # Write to file
    with open(output_file, 'w') as f:
        if format == 'json':
            json.dump(export_data, f, indent=2, default=str)
        else:
            yaml.dump(
                export_data, 
                f, 
                Dumper=SigmaYAMLDumper,
                default_flow_style=False, 
                indent=4,
                sort_keys=False,
                allow_unicode=True
            )
    
    return output_file


def export_rules(
    rules: List[SigmaRuleOCSFLite],
    output_dir: str,
    format: str = 'yaml',
    full: bool = False
) -> List[Path]:
    """
    Export multiple rules to individual files in a directory.
    
    Args:
        rules: List of rules to export
        output_dir: Directory to write files to (created if doesn't exist)
        format: 'yaml' or 'json'
        full: If False (default), export only field mappings. If True, export full rule details.
    
    Returns:
        List of paths to written files
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Export each rule
    exported_files = []
    for rule in rules:
        try:
            file_path = export_rule_to_file(rule, output_path, format, full)
            exported_files.append(file_path)
        except Exception as e:
            print(f"Warning: Failed to export rule '{rule.title}': {e}")
    
    return exported_files

