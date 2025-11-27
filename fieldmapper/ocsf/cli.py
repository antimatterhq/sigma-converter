#!/usr/bin/env python
"""
Command-line interface for Sigma to OCSF Lite converter.

This module provides the CLI entry point and display/presentation logic.
"""
import argparse
from pathlib import Path
from typing import List

from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
from fieldmapper.ocsf.converter import load_and_process_rules
from fieldmapper.ocsf.analyze_mappings import analyze_directory, generate_report


def print_separator(char="=", length=80):
    """Print a separator line."""
    print(char * length)


def print_rule_details(rule: SigmaRuleOCSFLite, index: int = None):
    """Print detailed information about a single rule."""
    if index is not None:
        print(f"\n{'='*80}")
        print(f"RULE #{index}")
        print(f"{'='*80}")
    
    print(f"\n Basic Information:")
    print(f"   Title:       {rule.title}")
    print(f"   ID:          {rule.id}")
    print(f"   Status:      {rule.status}")
    print(f"   Level:       {rule.level}")
    print(f"   Author:      {rule.author}")
    print(f"   Date:        {rule.date}")
    print(f"   Modified:    {rule.modified}")
    
    if rule.description:
        print(f"\n Description:")
        print(f"   {rule.description}")
    
    print(f"\n  Tags ({len(rule.tags)}):")
    for tag in rule.tags[:5]:  # Show first 5 tags
        print(f"   - {tag}")
    if len(rule.tags) > 5:
        print(f"   ... and {len(rule.tags) - 5} more")
    
    print(f"\n Log Source:")
    print(f"   Category:    {rule.logsource.category}")
    print(f"   Product:     {rule.logsource.product}")
    print(f"   Service:     {rule.logsource.service}")
    
    print(f"\n Detection:")
    detection_names = list(rule.detection.detections.keys())
    print(f"   Detections:  {', '.join(detection_names)}")
    print(f"   Condition:   {rule.detection.condition}")
    
    if rule.fields:
        print(f"\n Fields ({len(rule.fields)}):")
        for field in rule.fields[:5]:
            print(f"   - {field}")
        if len(rule.fields) > 5:
            print(f"   ... and {len(rule.fields) - 5} more")
    
    if rule.references:
        print(f"\n References ({len(rule.references)}):")
        for ref in rule.references[:3]:
            print(f"   - {ref}")
        if len(rule.references) > 3:
            print(f"   ... and {len(rule.references) - 3} more")
    
    print(f"\n OCSF Lite Mapping:")
    print(f"   Class Name:  {rule.ocsflite.class_name or '(not mapped yet)'}")
    
    # Show logsource context (inputs that determined event class)
    if rule.ocsflite.logsource:
        logsource_parts = []
        if rule.ocsflite.logsource.category:
            logsource_parts.append(f"Category: {rule.ocsflite.logsource.category.source_value}")
        if rule.ocsflite.logsource.product:
            logsource_parts.append(f"Product: {rule.ocsflite.logsource.product.source_value}")
        if rule.ocsflite.logsource.service:
            logsource_parts.append(f"Service: {rule.ocsflite.logsource.service.source_value}")
        
        if logsource_parts:
            print(f"\n Logsource Context:")
            for part in logsource_parts:
                print(f"   {part}")
            print(f"   → Mapped to Event Class: {rule.ocsflite.class_name or '(not mapped yet)'}")
    
    # Show detection field mappings
    if rule.ocsflite.detection_fields:
        print(f"\n Detection Field Mappings ({len(rule.ocsflite.detection_fields)} fields):")
        for mapping in rule.ocsflite.detection_fields[:10]:  # Show first 10
            if mapping.target_table and mapping.target_field:
                target = f"{mapping.target_table}.{mapping.target_field}"
            else:
                target = "(not mapped yet)"
            print(f"   {mapping.source_field} -> {target}")
        if len(rule.ocsflite.detection_fields) > 10:
            print(f"   ... and {len(rule.ocsflite.detection_fields) - 10} more")


def print_summary(rules: List[SigmaRuleOCSFLite]):
    """Print a summary of all loaded rules."""
    print(f"\n{'='*80}")
    print(f"SUMMARY - {len(rules)} Rules Loaded")
    print(f"{'='*80}\n")
    
    if not rules:
        print("No rules were loaded. Check your PATHS configuration and file locations.")
        return
    
    print(f"{'#':<4} {'Title':<50} {'Level':<10} {'Status':<10}")
    print("-" * 80)
    
    for i, rule in enumerate(rules, 1):
        title = rule.title[:47] + "..." if len(rule.title) > 50 else rule.title
        level = str(rule.level) if rule.level else "N/A"
        status = str(rule.status) if rule.status else "N/A"
        print(f"{i:<4} {title:<50} {level:<10} {status:<10}")
    
    # Statistics
    print(f"\n Statistics:")

    # Count by log source
    log_sources = {}
    for rule in rules:
        if rule.logsource.product:
            key = f"{rule.logsource.product}"
        elif rule.logsource.category:
            key = f"category:{rule.logsource.category}"
        else:
            key = "unspecified"
        log_sources[key] = log_sources.get(key, 0) + 1
    
    print(f"   By Log Source:")
    for source, count in sorted(log_sources.items()):
        print(f"      {source}: {count}")


def main():
    """
    CLI entry point for Sigma to OCSF Lite converter.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Load and display Sigma rules with OCSF Lite mappings"
    )
    parser.add_argument(
        "-d", "--details",
        action="store_true",
        help="Display detailed information for each rule (default: summary only)"
    )
    
    # Filter options (mutually exclusive)
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "-f", "--file",
        type=str,
        metavar="FILENAME",
        help="Load only a specific file by name (e.g., 'net_firewall_cleartext_protocols.yml')"
    )
    filter_group.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Process only the first N rules (only applies with --map)"
    )
    
    parser.add_argument(
        "--map",
        action="store_true",
        help="Populate OCSF mappings using AI"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="OpenAI API key (or set OPENAI_KEY env var)"
    )
    parser.add_argument(
        "--schema",
        type=str,
        default="fieldmapper/ocsf_data/ocsf_lite_ai_schema.json",
        help="Path to OCSF Lite AI schema file (default: fieldmapper/ocsf_data/ocsf_lite_ai_schema.json)"
    )
    parser.add_argument(
        "--cache",
        type=str,
        default=".mapping_cache.json",
        help="Path to mapping cache file (default: .mapping_cache.json)"
    )
    parser.add_argument(
        "--debug-prompt",
        action="store_true",
        help="Display AI prompts for debugging (shows what's sent to OpenAI and the response)"
    )
    
    # Cache control options (mutually exclusive)
    cache_group = parser.add_mutually_exclusive_group()
    cache_group.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Clear entire cache before mapping (rebuilds cache from scratch)"
    )
    cache_group.add_argument(
        "--no-cache",
        action="store_true",
        help="Skip reading from cache but still write new mappings (updates existing entries)"
    )
    
    # Export options
    parser.add_argument(
        "--output", "-o",
        type=str,
        metavar="DIR",
        help="Export rules to YAML/JSON files in specified directory"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Export full rule details (default: field mappings only)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Export as JSON instead of YAML"
    )
    
    # Analysis options
    parser.add_argument(
        "--analyze",
        type=str,
        metavar="DIR",
        help="Analyze mapping results in directory and generate statistics report"
    )
    
    args = parser.parse_args()
    
    # Validate that --output requires --map
    if args.output and not args.map:
        print("Error: --output requires --map flag (export is for AI-mapped results)")
        exit(1)
    
    # Handle --analyze mode (separate from normal operation)
    if args.analyze:
        try:
            stats, analyses = analyze_directory(Path(args.analyze))
            report = generate_report(stats, analyses)
            print(report)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            exit(1)
        except Exception as e:
            print(f"Error analyzing directory: {e}")
            exit(1)
        
        exit(0)
    
    # Load and process rules
    print("\n Loading Sigma rules...")
    
    result = load_and_process_rules(
        filename=args.file,
        limit=args.limit,
        map_rules=args.map,
        api_key=args.api_key,
        schema_path=args.schema,
        cache_path=args.cache,
        debug_prompts=args.debug_prompt,
        refresh_cache=args.refresh_cache,
        no_cache=args.no_cache,
        output_dir=args.output,
        full_export=args.full,
        json_format=args.json
    )
    
    # Check for errors
    if not result['success']:
        print(f"Error: {result['error']}")
        if 'error_hint' in result:
            print(f"   {result['error_hint']}")
        exit(1)
    
    rules = result['rules']
    stats = result['stats']
    
    print(f"Loaded {stats['total']} rule(s)\n")
    
    if not rules:
        print("No rules found. Check your configuration in fieldmapper/ocsf/rules.py PATHS variable.")
        exit(0)
    
    # Display mapping progress if mapping was performed
    if args.map:
        # Handle cache refresh display
        if args.refresh_cache and args.cache:
            print(f"   Cleared cache: {args.cache}")
        
        # Setup export display
        if args.output:
            export_format = 'JSON' if args.json else 'YAML'
            print(f"📤 Exporting rules to {args.output} (format: {export_format})\n")
        
        # Show limit info if applied
        if 'limited_from' in stats:
            print(f"\nℹ️  Limiting to first {args.limit} rules (out of {stats['limited_from']} total)")
        
        # Map all loaded rules with progress display
        print(f"🔄 Mapping {len(rules)} rules using AI...")
        
        for i, rule in enumerate(rules, 1):
            print(f"  [{i}/{len(rules)}] {rule.title}")
        
        # Display completion summary
        print(f"\n✅ Mapping complete!")
        print(f"   Successful: {stats['success_count']}/{len(rules)}")
        if stats['skipped_count'] > 0:
            print(f"   Skipped: {stats['skipped_count']} (keyword-based detection)")
        if stats['error_count'] > 0:
            print(f"   ⚠️  Errors: {stats['error_count']}")
            # Show individual errors if any
            if 'rule_errors' in result:
                for error_info in result['rule_errors']:
                    print(f"      {error_info['rule']}: {error_info['error']}")
        if args.output:
            print(f"   📁 Exported to: {args.output}")
        print(f"   💾 Cache saved to: {args.cache}\n")
    
    # Print summary
    print_summary(rules)
    
    # Print detailed view if requested
    if args.details:
        for rule in rules:
            print_rule_details(rule)


if __name__ == "__main__":
    main()

