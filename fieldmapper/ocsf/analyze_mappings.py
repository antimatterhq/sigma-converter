"""
Mapping Statistics Analyzer

Analyzes exported OCSF Lite mapping results and generates statistics about mapping quality.
Designed to be extensible for future metrics and analysis types.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml


@dataclass
class RuleMappingAnalysis:
    """Per-rule analysis of mapping status."""
    filename: str
    rule_id: str
    rule_title: str
    class_name: Optional[str]
    activity_id: Optional[int | str]  # Can be int or "UNMAPPED"
    total_detection_fields: int
    mapped_detection_fields: int
    unmapped_detection_fields: int
    mapping_status: str  # "complete", "partial", "unmapped"


@dataclass
class MappingStatistics:
    """Aggregate statistics across all analyzed rules."""
    total_rules: int
    completely_mapped: int  # class_name set AND all fields mapped
    partially_mapped: int   # class_name set AND some fields mapped
    completely_unmapped: int  # class_name null OR no fields mapped
    no_event_class: int  # Rules with null/missing class_name
    
    # Field-level stats (no defaults)
    total_fields: int
    mapped_fields: int
    unmapped_fields: int
    
    # Activity ID stats (with defaults - must come after non-default fields)
    has_activity_id: int = 0  # Count of rules with valid activity_id
    unmapped_activity_id: int = 0  # Count with "UNMAPPED"
    no_activity_id: int = 0  # Count with None (event class has no activity_id field)
    
    # Event class distribution
    event_classes: Dict[str, int] = field(default_factory=dict)  # class_name -> count
    
    # Unmapped field frequency
    unmapped_field_counts: Dict[str, int] = field(default_factory=dict)  # field_name -> count


def classify_mapping_status(analysis: RuleMappingAnalysis) -> str:
    """
    Classify the mapping status of a rule.
    
    Args:
        analysis: RuleMappingAnalysis object
        
    Returns:
        Status string: "complete", "partial", or "unmapped"
    """
    if not analysis.class_name or analysis.class_name == "null":
        return "unmapped"
    
    # Check if activity_id is unmapped (when it should exist)
    activity_id_unmapped = (analysis.activity_id == "UNMAPPED")
    
    if analysis.total_detection_fields == 0:
        # No fields to map, but check activity_id
        return "complete" if not activity_id_unmapped else "partial"
    
    # Consider both fields and activity_id
    all_complete = (analysis.mapped_detection_fields == analysis.total_detection_fields 
                    and not activity_id_unmapped)
    some_mapped = (analysis.mapped_detection_fields > 0 or not activity_id_unmapped)
    
    if all_complete:
        return "complete"
    elif some_mapped:
        return "partial"
    else:
        return "unmapped"


def analyze_rule(rule_path: Path) -> Optional[RuleMappingAnalysis]:
    """
    Parse a single YAML file and extract mapping statistics.
    
    Args:
        rule_path: Path to the YAML file
        
    Returns:
        RuleMappingAnalysis object or None if parsing fails
    """
    try:
        with open(rule_path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not data or not isinstance(data, dict):
            return None
        
        # Extract basic rule info
        filename = rule_path.name
        rule_id = data.get('id', 'unknown')
        rule_title = data.get('title', 'unknown')
        
        # Extract OCSF mapping info
        ocsf_mapping = data.get('ocsf_mapping', {})
        class_name = ocsf_mapping.get('class_name')
        activity_id = ocsf_mapping.get('activity_id')
        
        # Count detection fields
        detection_fields = ocsf_mapping.get('detection_fields', [])
        total_detection_fields = len(detection_fields)
        
        # Count mapped vs unmapped fields
        mapped_count = 0
        for field_mapping in detection_fields:
            target_field = field_mapping.get('target_field')
            if target_field and target_field != 'null' and target_field != '<UNMAPPED>':
                mapped_count += 1
        
        unmapped_count = total_detection_fields - mapped_count
        
        analysis = RuleMappingAnalysis(
            filename=filename,
            rule_id=rule_id,
            rule_title=rule_title,
            class_name=class_name,
            activity_id=activity_id,
            total_detection_fields=total_detection_fields,
            mapped_detection_fields=mapped_count,
            unmapped_detection_fields=unmapped_count,
            mapping_status=""  # Will be set next
        )
        
        # Classify the mapping status
        analysis.mapping_status = classify_mapping_status(analysis)
        
        return analysis
        
    except Exception as e:
        print(f"Warning: Failed to analyze {rule_path}: {e}")
        return None


def get_unmapped_fields_from_file(file_path: Path) -> List[str]:
    """
    Re-parse YAML file to extract list of unmapped field names.
    
    Args:
        file_path: Path to the YAML mapping file
        
    Returns:
        List of field names that are unmapped
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        unmapped_fields = []
        
        # Check if ocsf_mapping exists and has detection_fields
        ocsf_mapping = data.get('ocsf_mapping', {})
        detection_fields = ocsf_mapping.get('detection_fields', [])
        
        for field_mapping in detection_fields:
            target_field = field_mapping.get('target_field')
            if target_field == '<UNMAPPED>':
                source_field = field_mapping.get('source_field')
                if source_field:
                    unmapped_fields.append(source_field)
        
        return unmapped_fields
        
    except Exception as e:
        print(f"Warning: Failed to extract unmapped fields from {file_path}: {e}")
        return []


def analyze_directory(dir_path: Path) -> Tuple[MappingStatistics, List[RuleMappingAnalysis]]:
    """
    Scan all YAML files in a directory and aggregate statistics.
    
    Args:
        dir_path: Path to directory containing YAML mapping files
        
    Returns:
        Tuple of (MappingStatistics, List[RuleMappingAnalysis])
    """
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")
    
    analyses: List[RuleMappingAnalysis] = []
    
    # Find all YAML files
    yaml_files = list(dir_path.glob("*.yml")) + list(dir_path.glob("*.yaml"))
    
    # Analyze each file
    for yaml_file in yaml_files:
        analysis = analyze_rule(yaml_file)
        if analysis:
            analyses.append(analysis)
    
    # Aggregate statistics
    total_rules = len(analyses)
    completely_mapped = sum(1 for a in analyses if a.mapping_status == "complete")
    partially_mapped = sum(1 for a in analyses if a.mapping_status == "partial")
    completely_unmapped = sum(1 for a in analyses if a.mapping_status == "unmapped")
    
    total_fields = sum(a.total_detection_fields for a in analyses)
    mapped_fields = sum(a.mapped_detection_fields for a in analyses)
    unmapped_fields = sum(a.unmapped_detection_fields for a in analyses)
    
    # Count rules without event class
    no_event_class = sum(
        1 for a in analyses 
        if not a.class_name or a.class_name in ('null', '<UNMAPPED>')
    )
    
    # Count activity_id statistics
    has_activity_id = 0
    unmapped_activity_id = 0
    no_activity_id = 0
    
    for analysis in analyses:
        if analysis.activity_id is not None:
            if isinstance(analysis.activity_id, int):
                has_activity_id += 1
            elif analysis.activity_id == "UNMAPPED":
                unmapped_activity_id += 1
        else:
            no_activity_id += 1
    
    # Count event classes
    event_classes: Dict[str, int] = {}
    for analysis in analyses:
        if analysis.class_name and analysis.class_name != "null":
            event_classes[analysis.class_name] = event_classes.get(analysis.class_name, 0) + 1
    
    # Build unmapped field frequency count
    unmapped_field_counts: Dict[str, int] = {}
    for yaml_file in yaml_files:
        unmapped_fields_list = get_unmapped_fields_from_file(yaml_file)
        for field_name in unmapped_fields_list:
            unmapped_field_counts[field_name] = unmapped_field_counts.get(field_name, 0) + 1
    
    stats = MappingStatistics(
        total_rules=total_rules,
        completely_mapped=completely_mapped,
        partially_mapped=partially_mapped,
        completely_unmapped=completely_unmapped,
        no_event_class=no_event_class,
        has_activity_id=has_activity_id,
        unmapped_activity_id=unmapped_activity_id,
        no_activity_id=no_activity_id,
        total_fields=total_fields,
        mapped_fields=mapped_fields,
        unmapped_fields=unmapped_fields,
        event_classes=event_classes,
        unmapped_field_counts=unmapped_field_counts
    )
    
    return stats, analyses


def generate_report(stats: MappingStatistics, analyses: List[RuleMappingAnalysis]) -> str:
    """
    Format a human-readable report from statistics.
    
    Args:
        stats: MappingStatistics object
        analyses: List of per-rule analyses
        
    Returns:
        Formatted report string
    """
    lines = []
    
    lines.append("Mapping Statistics Report")
    lines.append("=" * 50)
    lines.append("")
    
    # Overall statistics
    lines.append(f"Total Rules: {stats.total_rules:,}")
    
    if stats.total_rules > 0:
        complete_pct = (stats.completely_mapped / stats.total_rules) * 100
        partial_pct = (stats.partially_mapped / stats.total_rules) * 100
        unmapped_pct = (stats.completely_unmapped / stats.total_rules) * 100
        
        lines.append(f"  - Completely Mapped: {stats.completely_mapped:,} ({complete_pct:.1f}%)")
        lines.append(f"  - Partially Mapped: {stats.partially_mapped:,} ({partial_pct:.1f}%)")
        lines.append(f"  - Completely Unmapped: {stats.completely_unmapped:,} ({unmapped_pct:.1f}%)")
        
        no_class_pct = (stats.no_event_class / stats.total_rules) * 100
        lines.append(f"  - Rules Without Event Class: {stats.no_event_class:,} ({no_class_pct:.1f}%)")
    
    lines.append("")
    
    # Field-level statistics
    lines.append("Field-Level Statistics:")
    lines.append(f"  - Total Fields: {stats.total_fields:,}")
    
    if stats.total_fields > 0:
        mapped_pct = (stats.mapped_fields / stats.total_fields) * 100
        unmapped_pct = (stats.unmapped_fields / stats.total_fields) * 100
        
        lines.append(f"  - Mapped: {stats.mapped_fields:,} ({mapped_pct:.1f}%)")
        lines.append(f"  - Unmapped: {stats.unmapped_fields:,} ({unmapped_pct:.1f}%)")
    
    lines.append("")
    
    # Activity ID statistics
    lines.append("Activity ID Statistics:")
    if stats.total_rules > 0:
        has_activity_pct = (stats.has_activity_id / stats.total_rules) * 100
        unmapped_activity_pct = (stats.unmapped_activity_id / stats.total_rules) * 100
        no_activity_pct = (stats.no_activity_id / stats.total_rules) * 100
        
        lines.append(f"  - Mapped Activity IDs: {stats.has_activity_id:,} ({has_activity_pct:.1f}%)")
        lines.append(f"  - Unmapped Activity IDs: {stats.unmapped_activity_id:,} ({unmapped_activity_pct:.1f}%)")
        lines.append(f"  - No Activity ID Field: {stats.no_activity_id:,} ({no_activity_pct:.1f}%)")
    
    lines.append("")
    
    # Top event classes
    if stats.event_classes:
        lines.append("Top Event Classes:")
        # Sort by count descending
        sorted_classes = sorted(stats.event_classes.items(), key=lambda x: x[1], reverse=True)
        
        for i, (class_name, count) in enumerate(sorted_classes[:10], 1):
            lines.append(f"  {i}. {class_name}: {count:,}")
    
    lines.append("")
    
    # Top unmapped fields
    lines.append("Top 20 Unmapped Fields:")
    if stats.unmapped_field_counts:
        sorted_fields = sorted(stats.unmapped_field_counts.items(), key=lambda x: x[1], reverse=True)
        for field_name, count in sorted_fields[:20]:
            lines.append(f"  - {field_name}: {count:,} rules")
    else:
        lines.append("  None - All fields successfully mapped!")
    
    # Detailed breakdown of problematic rules
    lines.append("")
    lines.append("Rules Needing Attention:")
    
    # Partially mapped rules
    partial_rules = [a for a in analyses if a.mapping_status == "partial"]
    if partial_rules:
        lines.append(f"  Partially Mapped ({len(partial_rules)}):")
        for analysis in sorted(partial_rules, key=lambda x: x.filename):
            mapped_ratio = f"{analysis.mapped_detection_fields}/{analysis.total_detection_fields}"
            lines.append(f"    - {analysis.filename}: {mapped_ratio} fields mapped")
    
    # Completely unmapped rules
    unmapped_rules = [a for a in analyses if a.mapping_status == "unmapped"]
    if unmapped_rules:
        lines.append(f"  Completely Unmapped ({len(unmapped_rules)}):")
        for analysis in sorted(unmapped_rules, key=lambda x: x.filename):
            lines.append(f"    - {analysis.filename}")
    
    # Rules without event class
    no_class_rules = [a for a in analyses if not a.class_name or a.class_name in ('null', '<UNMAPPED>')]
    if no_class_rules:
        lines.append(f"  Rules Without Event Class ({len(no_class_rules)}):")
        for analysis in sorted(no_class_rules, key=lambda x: x.filename):
            lines.append(f"    - {analysis.filename}")
    
    if not partial_rules and not unmapped_rules and not no_class_rules:
        lines.append("  None - All rules completely mapped!")
    
    return "\n".join(lines)

