#!/usr/bin/env python3
"""
Extract MITRE ATT&CK technique to data component mappings.

This script downloads the latest MITRE ATT&CK STIX data and extracts
technique information including data sources and data components.
The output is saved to mitre_attack_data.json for use in AI mapping.

Usage:
    python fieldmapper/ocsf_data/bin/mitre.py
"""

import json
import requests
from pathlib import Path


def extract_mitre_mappings(output_file: str = "mitre_attack_data.json") -> dict:
    """
    Extract technique to data component mappings from MITRE ATT&CK.
    
    Parses STIX 2.1 format following the chain:
    Technique → Detection Strategy → Analytic → Data Component
    
    Args:
        output_file: Path to save the JSON output
        
    Returns:
        Dictionary mapping technique IDs to their metadata
    """
    print("  Downloading MITRE ATT&CK STIX data...")
    
    # Download the enterprise ATT&CK STIX data
    stix_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    stix_file = "enterprise-attack.json"
    
    response = requests.get(stix_url)
    response.raise_for_status()
    with open(stix_file, 'wb') as f:
        f.write(response.content)
    print(f"   Downloaded {stix_file}")
    
    # Load raw STIX data
    with open(stix_file, 'r') as f:
        stix_data = json.load(f)
    
    print("  Building STIX object indexes...")
    
    # Build indexes for all object types
    techniques = {}  # stix_id -> external_id (T1059.002)
    tech_objects = {}  # stix_id -> full object (for extracting all fields)
    detection_strategies = {}  # stix_id -> object
    analytics = {}  # stix_id -> object
    data_components = {}  # stix_id -> name (for quick lookup)
    data_component_objects = {}  # stix_id -> full object (for detailed extraction)
    data_sources = {}  # stix_id -> name
    groups = {}  # stix_id -> object (intrusion-set)
    malware = {}  # stix_id -> object
    mitigations = {}  # stix_id -> object (course-of-action)
    relationships = []  # all relationship objects
    
    for obj in stix_data['objects']:
        obj_type = obj.get('type')
        obj_id = obj.get('id')
        
        if obj_type == 'attack-pattern':
            # Index techniques
            refs = obj.get('external_references', [])
            for ref in refs:
                if ref.get('source_name') == 'mitre-attack':
                    tech_id = ref.get('external_id')
                    if tech_id and not obj.get('revoked', False) and not obj.get('x_mitre_deprecated', False):
                        techniques[obj_id] = tech_id
                        tech_objects[obj_id] = obj  # Store full object
                    break
        
        elif obj_type == 'x-mitre-detection-strategy':
            detection_strategies[obj_id] = obj
        
        elif obj_type == 'x-mitre-analytic':
            analytics[obj_id] = obj
        
        elif obj_type == 'x-mitre-data-component':
            data_components[obj_id] = obj.get('name')
            data_component_objects[obj_id] = obj  # Store full object for detailed extraction
        
        elif obj_type == 'x-mitre-data-source':
            data_sources[obj_id] = obj.get('name')
        
        elif obj_type == 'intrusion-set':
            groups[obj_id] = obj
        
        elif obj_type == 'malware':
            malware[obj_id] = obj
        
        elif obj_type == 'course-of-action':
            mitigations[obj_id] = obj
        
        elif obj_type == 'relationship':
            relationships.append(obj)
    
    print(f"   Indexed {len(techniques)} techniques")
    print(f"   Indexed {len(detection_strategies)} detection strategies")
    print(f"   Indexed {len(analytics)} analytics")
    print(f"   Indexed {len(data_components)} data components")
    print(f"   Indexed {len(groups)} groups")
    print(f"   Indexed {len(malware)} malware")
    print(f"   Indexed {len(mitigations)} mitigations")
    print(f"   Indexed {len(relationships)} relationships")
    
    print("  Extracting data components for each technique...")
    
    # Build technique
    mappings = {}
    for tech_stix_id, tech_id in techniques.items():
        tech_obj = tech_objects.get(tech_stix_id, {})
        
        # Get basic metadata
        tech_name = tech_obj.get('name', 'Unknown')
        tactic = None
        kill_chains = tech_obj.get('kill_chain_phases', [])
        if kill_chains:
            tactic = kill_chains[0].get('phase_name')
        
        # Find detection strategies that detect this technique
        det_strategy_ids = []
        for rel in relationships:
            if (rel.get('relationship_type') == 'detects' and 
                rel.get('target_ref') == tech_stix_id):
                det_strategy_ids.append(rel.get('source_ref'))
        
        # Get analytics from detection strategies
        analytic_ids = []
        for ds_id in det_strategy_ids:
            ds_obj = detection_strategies.get(ds_id)
            if ds_obj:
                analytic_refs = ds_obj.get('x_mitre_analytic_refs', [])
                analytic_ids.extend(analytic_refs)
        
        # Extract data components from analytics
        data_comp_ids = set()
        for analytic_id in analytic_ids:
            analytic = analytics.get(analytic_id)
            if analytic:
                log_sources = analytic.get('x_mitre_log_source_references', [])
                for log_source in log_sources:
                    dc_ref = log_source.get('x_mitre_data_component_ref')
                    if dc_ref:
                        data_comp_ids.add(dc_ref)
        
        # Get data component names
        dc_names = []
        for dc_id in data_comp_ids:
            if dc_id in data_components:
                dc_names.append(data_components[dc_id])
        
        # Find data sources (data components "included-in" data sources)
        ds_ids = set()
        for dc_id in data_comp_ids:
            for rel in relationships:
                if (rel.get('source_ref') == dc_id and 
                    rel.get('relationship_type') == 'included-in'):
                    ds_ids.add(rel.get('target_ref'))
        
        # Get data source names
        ds_names = []
        for ds_id in ds_ids:
            if ds_id in data_sources:
                ds_names.append(data_sources[ds_id])
        
        # Extract detection strategies with comprehensive info
        detection_strats = []
        for ds_id in det_strategy_ids:
            ds_obj = detection_strategies.get(ds_id)
            if ds_obj:
                # Get external references
                refs = ds_obj.get('external_references', [])
                det_id = None
                det_url = None
                for ref in refs:
                    if ref.get('source_name') == 'mitre-attack':
                        det_id = ref.get('external_id')
                        det_url = ref.get('url')
                        break
                
                if det_id:  # Only add if it has an ID
                    # Get associated analytics with log source references
                    analytic_refs = ds_obj.get('x_mitre_analytic_refs', [])
                    analytics_list = []
                    for analytic_id in analytic_refs:
                        analytic = analytics.get(analytic_id)
                        if analytic:
                            # Extract log source references from analytic
                            log_sources_list = []
                            log_source_refs = analytic.get('x_mitre_log_source_references', [])
                            
                            for log_source_ref in log_source_refs:
                                dc_ref = log_source_ref.get('x_mitre_data_component_ref')
                                if dc_ref and dc_ref in data_components:
                                    dc_name = data_components[dc_ref]
                                    
                                    # Get data component external ID from full object
                                    dc_external_id = None
                                    dc_obj = data_component_objects.get(dc_ref)
                                    if dc_obj:
                                        refs = dc_obj.get('external_references', [])
                                        for ref in refs:
                                            if ref.get('source_name') == 'mitre-attack':
                                                dc_external_id = ref.get('external_id')
                                                break
                                    
                                    # Find parent data source via "included-in" relationship
                                    ds_name = None
                                    for rel in relationships:
                                        if (rel.get('source_ref') == dc_ref and 
                                            rel.get('relationship_type') == 'included-in'):
                                            ds_id = rel.get('target_ref')
                                            if ds_id in data_sources:
                                                ds_name = data_sources[ds_id]
                                                break
                                    
                                    log_sources_list.append({
                                        'data_component_id': dc_ref,
                                        'data_component_name': dc_name,
                                        'data_component_external_id': dc_external_id,
                                        'data_source_name': ds_name
                                    })
                            
                            analytics_list.append({
                                'id': analytic.get('id'),
                                'name': analytic.get('name'),
                                'description': analytic.get('description'),
                                'log_sources': log_sources_list,
                                'created': analytic.get('created'),
                                'modified': analytic.get('modified')
                            })
                    
                    detection_strats.append({
                        'id': det_id,
                        'name': ds_obj.get('name'),
                        'url': det_url,
                        'description': ds_obj.get('description'),
                        'analytics': analytics_list,
                        'created': ds_obj.get('created'),
                        'modified': ds_obj.get('modified'),
                        'version': ds_obj.get('x_mitre_version')
                    })
        
        # Extract platforms
        platforms = tech_obj.get('x_mitre_platforms', [])
        
        # Extract description
        description = tech_obj.get('description', '')
        
        # Extract dates
        created = tech_obj.get('created', '')
        modified = tech_obj.get('modified', '')
        
        # Determine if sub-technique
        is_subtechnique = tech_obj.get('x_mitre_is_subtechnique', False)
        parent_technique = None
        if is_subtechnique and '.' in tech_id:
            parent_technique = tech_id.split('.')[0]
        
        # Find procedure examples with comprehensive actor info
        procedure_examples = []
        for rel in relationships:
            if rel.get('target_ref') == tech_stix_id and rel.get('relationship_type') == 'uses':
                source_id = rel.get('source_ref')
                source_obj = groups.get(source_id) or malware.get(source_id)
                if source_obj:
                    # Get external references for actor
                    refs = source_obj.get('external_references', [])
                    actor_id = None
                    actor_url = None
                    for ref in refs:
                        if ref.get('source_name') == 'mitre-attack':
                            actor_id = ref.get('external_id')
                            actor_url = ref.get('url')
                            break
                    
                    procedure_examples.append({
                        'actor': source_obj.get('name'),
                        'description': rel.get('description', ''),
                        'source_type': source_obj.get('type'),
                        'actor_id': actor_id,
                        'actor_aliases': source_obj.get('aliases', []),
                        'actor_url': actor_url,
                        'created': source_obj.get('created'),
                        'modified': source_obj.get('modified')
                    })
        
        # Find mitigations with comprehensive info
        mitigations_list = []
        for rel in relationships:
            if rel.get('target_ref') == tech_stix_id and rel.get('relationship_type') == 'mitigates':
                mitigation_id = rel.get('source_ref')
                mitigation_obj = mitigations.get(mitigation_id)
                if mitigation_obj:
                    refs = mitigation_obj.get('external_references', [])
                    mit_id = None
                    mit_url = None
                    for ref in refs:
                        if ref.get('source_name') == 'mitre-attack':
                            mit_id = ref.get('external_id')
                            mit_url = ref.get('url')
                            break
                    
                    if mit_id:  # Only add if it has an ID
                        mitigations_list.append({
                            'id': mit_id,
                            'name': mitigation_obj.get('name'),
                            'url': mit_url,
                            'description': mitigation_obj.get('description'),  # Full description
                            'relationship_description': rel.get('description', ''),  # How it applies
                            'created': mitigation_obj.get('created'),
                            'modified': mitigation_obj.get('modified'),
                            'version': mitigation_obj.get('x_mitre_version')
                        })
        
        # Store mapping
        mappings[tech_id] = {
            "name": tech_name,
            "tactic": tactic,
            "data_sources": sorted(list(set(ds_names))),
            "data_components": sorted(list(set(dc_names))),
            "detection_strategies": detection_strats,
            "platforms": platforms,
            "description": description,
            "created": created,
            "modified": modified,
            "is_subtechnique": is_subtechnique,
            "parent_technique": parent_technique,
            "subtechniques": [],  # Will populate in second pass
            "procedure_examples": procedure_examples[:5],  # Limit to 5
            "mitigations": mitigations_list
        }
    
    # Second pass: populate subtechniques for parent techniques
    print("🔗 Building parent-child relationships...")
    for tech_id, data in mappings.items():
        if data['is_subtechnique'] and data['parent_technique']:
            parent = mappings.get(data['parent_technique'])
            if parent and 'subtechniques' in parent:
                parent['subtechniques'].append(tech_id)
    
    print(f"  Extracted {len(mappings)} techniques")
    
    # Save to JSON
    output_path = Path(output_file)
    with open(output_path, 'w') as f:
        json.dump(mappings, f, indent=2)
    
    print(f"  Saved to {output_path.absolute()}")
    
    # Print statistics
    techniques_with_components = sum(1 for m in mappings.values() if m['data_components'])
    techniques_with_detection_strategies = sum(1 for m in mappings.values() if m['detection_strategies'])
    techniques_with_procedures = sum(1 for m in mappings.values() if m['procedure_examples'])
    techniques_with_mitigations = sum(1 for m in mappings.values() if m['mitigations'])
    subtechniques_count = sum(1 for m in mappings.values() if m['is_subtechnique'])
    
    print(f"\n  Statistics:")
    print(f"   Total techniques: {len(mappings)}")
    print(f"   Sub-techniques: {subtechniques_count}")
    print(f"   With data components: {techniques_with_components}")
    print(f"   With detection strategies: {techniques_with_detection_strategies}")
    print(f"   With procedure examples: {techniques_with_procedures}")
    print(f"   With mitigations: {techniques_with_mitigations}")
    
    return mappings


def main():
    """Main entry point."""
    try:
        extract_mitre_mappings()
        print("\n  Done! You can now use the mapping data with --map option.")
    except Exception as e:
        print(f"\n  Error: {e}")
        print("\nMake sure mitreattack-python is installed:")
        print("  pip install mitreattack-python")
        raise


if __name__ == "__main__":
    main()

