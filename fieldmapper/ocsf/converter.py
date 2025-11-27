"""
This module handles rule loading, AI mapping, and export operations
"""
import os
from typing import Optional, List, Dict, Any

from fieldmapper.ocsf.rules import load_sigma_rules, SigmaRuleOCSFLite
from fieldmapper.ocsf.schema_loader import OCSFLiteSchema
from fieldmapper.ocsf.openai_mapper import OpenAIMapper
from fieldmapper.ocsf.ai_mapper import MappingCache
from fieldmapper.ocsf.export_utils import export_rule_to_file


def load_and_process_rules(
    filename: Optional[str] = None,
    limit: Optional[int] = None,
    map_rules: bool = False,
    api_key: Optional[str] = None,
    schema_path: Optional[str] = None,
    cache_path: Optional[str] = None,
    debug_prompts: bool = False,
    refresh_cache: bool = False,
    no_cache: bool = False,
    output_dir: Optional[str] = None,
    full_export: bool = False,
    json_format: bool = False
) -> Dict[str, Any]:
    """
    Load and process Sigma rules with optional AI mapping.
    
    Args:
        filename: Optional specific filename to load
        limit: Optional limit on number of rules to process (only with map_rules)
        map_rules: If True, use AI to populate OCSF mappings
        api_key: OpenAI API key (or from_KEY env var)
        schema_path: Path to OCSF Lite AI schema file
        cache_path: Path to mapping cache file
        debug_prompts: If True, display AI prompts for debugging
        refresh_cache: If True, clear entire cache before mapping
        no_cache: If True, skip reading from cache but still write new mappings
        output_dir: If specified, export rules to this directory
        full_export: If True, export full rule details (default: field mappings only)
        json_format: If True, export as JSON instead of YAML
    
    Returns:
        Dictionary with results:
        {
            'rules': List[SigmaRuleOCSFLite],
            'success': bool,
            'error': Optional[str],
            'stats': {
                'total': int,
                'success_count': int,
                'skipped_count': int,
                'error_count': int,
                'output_dir': Optional[str],
                'cache_path': Optional[str]
            }
        }
    """
    result = {
        'rules': [],
        'success': False,
        'error': None,
        'stats': {
            'total': 0,
            'success_count': 0,
            'skipped_count': 0,
            'error_count': 0,
            'output_dir': output_dir,
            'cache_path': cache_path
        }
    }
    
    # Load rules
    rules = load_sigma_rules(filename=filename)
    result['stats']['total'] = len(rules)
    
    if not rules:
        result['error'] = "No rules found"
        return result
    
    # Apply limit if specified (only when mapping)
    original_count = len(rules)
    if limit and map_rules and len(rules) > limit:
        rules = rules[:limit]
        result['stats']['limited_from'] = original_count
    
    # Perform AI mapping if requested
    if map_rules:
        if not api_key:
            api_key = os.getenv('OPENAI_KEY')
            if not api_key:
                result['error'] = "API key required: --api-key or OPENAI_KEY env var"
                return result
        
        # Handle cache refresh (delete cache file if it exists)
        if refresh_cache and cache_path and os.path.exists(cache_path):
            os.remove(cache_path)
        
        # Initialize AI mapper
        try:
            schema = OCSFLiteSchema(schema_path)
            cache = MappingCache(cache_path)
            skip_cache_reads = refresh_cache or no_cache
            ai_mapper = OpenAIMapper(
                schema, cache, api_key,
                debug_prompts=debug_prompts,
                skip_cache_reads=skip_cache_reads
            )
            
            # Setup export if output directory specified
            if output_dir:
                export_format = 'json' if json_format else 'yaml'
                os.makedirs(output_dir, exist_ok=True)
            
            # Map all loaded rules with incremental export
            for i, rule in enumerate(rules, 1):
                try:
                    was_mapped = rule.populate_mappings_with_ai(ai_mapper)
                    
                    if was_mapped:
                        # Successfully mapped with detection fields
                        result['stats']['success_count'] += 1
                        
                        # Export immediately after successful mapping
                        if output_dir:
                            export_rule_to_file(rule, output_dir, format=export_format, full=full_export)
                    else:
                        # Skipped - keyword-based detection (no fields to map)
                        result['stats']['skipped_count'] += 1
                    
                    cache.save()
                        
                except Exception as e:
                    result['stats']['error_count'] += 1
                    # Store error details for this rule
                    if 'rule_errors' not in result:
                        result['rule_errors'] = []
                    result['rule_errors'].append({
                        'rule': rule.title,
                        'error': str(e)
                    })
                    # Continue with next rule
            
            # Final cache save
            cache.save()
            
        except FileNotFoundError as e:
            result['error'] = str(e)
            result['error_hint'] = "Make sure to generate the AI schema first: python fieldmapper/ocsf_data/bin/ocsflite_parser.py --export-ai-schema ."
            return result
        except Exception as e:
            result['error'] = f"Error during AI mapping: {e}"
            return result
    
    result['rules'] = rules
    result['success'] = True
    return result

