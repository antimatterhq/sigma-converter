#!/usr/bin/env python
"""
CLI for converting Sigma rules to LakeWatch JSON format.
"""
import argparse
import json
import warnings
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from tqdm import tqdm


@dataclass
class ConversionResult:
    """Results from converting Sigma rules to LakeWatch format."""
    success: bool
    total: int
    converted: int
    failed: int
    output_dir: str
    files: List[str] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[Dict[str, str]] = field(default_factory=list)
    
    @property
    def has_failures(self) -> bool:
        """Check if any conversions failed."""
        return self.failed > 0


def convert_and_save_lakewatch_rules(
    input_dir: str = "fieldmapper/mappings",
    output_dir: str = "output",
    filename: Optional[str] = None
) -> ConversionResult:
    """
    Convert Sigma rules to LakeWatch JSON format and save to files.
    
    Uses DatabricksBackend directly (no subprocess) to convert rules.
    
    Args:
        input_dir: Directory containing mapped Sigma rules (YAML)
        output_dir: Directory to save converted JSON files
        filename: Optional specific filename to convert
        
    Returns:
        ConversionResult dataclass with conversion results
    """
    from sigma.collection import SigmaCollection
    from sigma.backends.databricks import DatabricksBackend
    from sigma.pipelines.lakewatch import lakewatch_pipeline
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Get input files
    input_path = Path(input_dir)
    if filename:
        # Single file mode
        input_files = [input_path / filename]
        if not input_files[0].exists():
            return ConversionResult(
                success=False,
                total=0,
                converted=0,
                failed=1,
                output_dir=str(output_path),
                errors=[{'file': filename, 'error': f"File not found: {input_files[0]}"}]
            )
    else:
        # Batch mode - all .yml files
        input_files = list(input_path.glob("*.yml"))
    
    if not input_files:
        return ConversionResult(
            success=False,
            total=0,
            converted=0,
            failed=0,
            output_dir=str(output_path),
            errors=[{'file': 'N/A', 'error': f"No YAML files found in {input_dir}"}]
        )
    
    # Create backend with lakewatch pipeline
    backend = DatabricksBackend(lakewatch_pipeline())
    
    # Convert each rule
    result = ConversionResult(
        success=True,
        total=len(input_files),
        converted=0,
        failed=0,
        output_dir=str(output_path),
        files=[],
        errors=[],
        warnings=[]
    )
    
    # Suppress warnings from being printed during conversion (we'll show them at the end)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        
        # Process files with progress bar
        with tqdm(total=len(input_files), desc="Converting files", unit="file") as pbar:
            for input_file in input_files:
                # Capture warnings for this file
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    
                    try:
                        # Load rule
                        collection = SigmaCollection.from_yaml(input_file.read_text())
                        
                        # Convert to lakewatch format
                        json_outputs = backend.convert(collection, output_format='lakewatch')
                        
                        # Store any warnings captured during conversion
                        for warning in w:
                            if issubclass(warning.category, UserWarning):
                                result.warnings.append({
                                    'file': input_file.name,
                                    'message': str(warning.message)
                                })
                        
                        # Check if conversion failed (validation errors)
                        if not json_outputs or (
                            len(json_outputs) == 1 and 
                            "# Validation Summary" in json_outputs[0]
                        ):
                            result.failed += 1
                            result.errors.append({
                                'file': input_file.name,
                                'error': 'Validation failed (missing OCSF mappings)'
                            })
                            pbar.update(1)
                            continue
                        
                        # Parse JSON to validate it
                        try:
                            json_data = json.loads(json_outputs[0])
                        except (json.JSONDecodeError, IndexError) as e:
                            result.failed += 1
                            result.errors.append({
                                'file': input_file.name,
                                'error': f'Invalid JSON output: {str(e)}'
                            })
                            pbar.update(1)
                            continue
                        
                        # Save to file with original name
                        output_filename = input_file.stem + '.json'
                        output_file = output_path / output_filename
                        
                        with open(output_file, 'w') as f:
                            json.dump(json_data, f, indent=2)
                        
                        result.converted += 1
                        result.files.append(output_filename)
                    
                    except Exception as e:
                        result.failed += 1
                        result.errors.append({
                            'file': input_file.name,
                            'error': str(e)
                        })
                    
                    # Update progress bar after each file
                    pbar.update(1)
    
    return result


def main():
    """CLI entry point for LakeWatch rule converter."""
    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to LakeWatch JSON format"
    )
    parser.add_argument(
        "-i", "--input-dir",
        type=str,
        default="fieldmapper/mappings",
        help="Input directory containing mapped Sigma rules (default: fieldmapper/mappings)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="output",
        help="Output directory for converted JSON files (default: output)"
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        metavar="FILENAME",
        help="Convert only a specific file (e.g., 'dns_query_win_anonymfiles_com.yml')"
    )
    
    args = parser.parse_args()
    
    print(f"\nConverting Sigma rules to LakeWatch JSON format...")
    print(f"Input:  {args.input_dir}")
    print(f"Output: {args.output_dir}\n")
    
    result = convert_and_save_lakewatch_rules(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        filename=args.file
    )
    
    # Display warnings first (if any)
    if result.warnings:
        print(f"\nWarnings ({len(result.warnings)}):")
        for warning in result.warnings:
            print(f"  Processing {warning['file']}: {warning['message']}")
    
    # Display failed conversions (if any)
    if result.has_failures:
        print(f"\nFailed conversions ({result.failed}):")
        for error in result.errors:
            print(f"  - {error['file']}: {error['error']}")
    
    # Display conversion results summary
    print(f"\nConversion Results:")
    print(f"  Total:     {result.total}")
    print(f"  Converted: {result.converted}")
    print(f"  Failed:    {result.failed}")
    
    # Display successfully converted files (if any)
    if result.converted > 0:
        print(f"\nSuccessfully converted files saved to: {result.output_dir}/")
        if args.file:
            print(f"  - {result.files[0]}")
        else:
            print(f"  ({len(result.files)} files)")
    
    exit(0 if not result.has_failures else 1)


if __name__ == "__main__":
    main()

