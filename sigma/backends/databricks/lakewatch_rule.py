from typing import Optional, List, Dict, Literal, Union
import json
import re
from pydantic import BaseModel

from dasl_api import (
    CoreV1Schedule as Schedule,
    CoreV1RuleSpec as RuleSpec,
    CoreV1RuleSpecInput as Input,
    CoreV1RuleSpecInputStream as StreamInput,
    CoreV1RuleSpecInputBatch as BatchInput,
    CoreV1RuleSpecInputStreamTablesInner as Table,
    CoreV1RuleSpecInputStreamTablesInnerWatermark as Watermark,
    CoreV1RuleSpecInputStreamCustom as CustomFunction,
    CoreV1RuleSpecOutput as Output,
    CoreV1RuleSpecMetadata as SpecMetadata,
    CoreV1RuleSpecMetadataMitreInner as MitreAttack,
    CoreV1RuleSpecMetadataResponse as Response,
    CoreV1RuleSpecMetadataResponsePlaybooksInner as Playbook,
    CoreV1RuleObservable as Observable,
    CoreV1RuleObservableRisk as Risk,
    CoreV1Rule,
    CommonV1ObjectMeta as RuleMetadata,
)

def dasl_to_dict(model: BaseModel) -> dict:
    """Convert dasl-api model to dict with camelCase fields"""
    return model.model_dump(
        exclude_none=True,
        by_alias=True,
        mode='python'
    )


def dasl_to_json(model: BaseModel, indent: int = 2) -> str:
    """Convert dasl-api model to JSON with camelCase fields"""
    return model.model_dump_json(
        exclude_none=True,
        by_alias=True,
        indent=indent
    )


def parse_mitre_tags(tags: List[str]) -> List['MitreAttack']:
    """
    Parse MITRE ATT&CK tags from Sigma rule tags.
    
    Extracts tags like 'attack.t1078', 'attack.persistence', 'attack.t1078.001'
    and converts them to LakeWatch MitreAttack objects.
    
    Args:
        tags: List of Sigma rule tags
        
    Returns:
        List of MitreAttack objects
    """
    mitre_attacks = []
    tactics_map = {}  # Track tactics by technique ID
    techniques_map = {}  # Track technique details
    
    for tag in tags:
        tag_str = str(tag).lower()
        
        # Check if it's an attack tag
        if not tag_str.startswith('attack.'):
            continue
        
        tag_value = tag_str[7:]  # Remove 'attack.' prefix
        
        # Check if it's a technique ID (starts with 't' followed by digits)
        if tag_value.startswith('t') and len(tag_value) > 1 and tag_value[1].isdigit():
            # Parse technique ID (e.g., t1078 or t1078.001)
            parts = tag_value.split('.')
            technique_id = parts[0].upper()  # T1078
            
            # Handle sub-technique
            sub_technique_id = None
            if len(parts) > 1:
                sub_technique_id = f"{parts[1]}"  # 001
            
            if sub_technique_id:
                techniques_map[sub_technique_id] = {
                    'techniqueId': technique_id,
                    'subTechniqueId': sub_technique_id
                }
            else:
                techniques_map[technique_id] = {
                    'techniqueId': technique_id
                }
        else:
            # It's a tactic name (e.g., 'persistence', 'privilege_escalation')
            tactic = tag_value.replace('_', ' ').title()
            tactics_map[tag_value] = tactic
    
    # Build MitreAttack objects
    # If we have techniques, create entries for them
    if techniques_map:
        for tech_id, tech_data in techniques_map.items():
            mitre_attack = MitreAttack(
                taxonomy="MITRE ATT&CK",
                technique_id=tech_data.get('techniqueId'),
                sub_technique_id=tech_data.get('subTechniqueId')
            )
            mitre_attacks.append(mitre_attack)
    
    # Add tactics as separate entries if we have them but no techniques
    # or attach them to techniques if both are present
    if tactics_map and not techniques_map:
        for tactic_key, tactic_name in tactics_map.items():
            mitre_attack = MitreAttack(
                taxonomy="MITRE ATT&CK",
                tactic=tactic_name
            )
            mitre_attacks.append(mitre_attack)
    elif tactics_map and techniques_map:
        # Attach first tactic to each technique
        first_tactic = list(tactics_map.values())[0]
        for mitre_attack in mitre_attacks:
            mitre_attack.tactic = first_tactic
    
    return mitre_attacks


def normalize_multiline_string(text: Optional[str]) -> Optional[str]:
    """
    Normalize multi-line strings to single-line by replacing newlines with spaces.
    
    Args:
        text: Input string that may contain newlines
        
    Returns:
        Normalized single-line string, or None if input is None/empty
    """
    if not text:
        return None
    
    # Replace newlines with spaces
    normalized = text.replace('\n', ' ')
    # Collapse multiple whitespace characters to single space
    normalized = re.sub(r'\s+', ' ', normalized)
    # Strip leading/trailing whitespace
    normalized = normalized.strip()
    
    return normalized if normalized else None


def truncate_rule_name(name: str, max_length: int = 80) -> str:
    """
    Truncate rule name to maximum length, adding ellipsis if truncated.
    
    Args:
        name: Rule name to truncate
        max_length: Maximum allowed length (default: 80)
        
    Returns:
        Truncated rule name, with ellipsis if truncated
    """
    if not name:
        return "Untitled Rule"
    
    if len(name) <= max_length:
        return name
    
    # Truncate to leave room for ellipsis
    ellipsis = "..."
    truncate_to = max_length - len(ellipsis)
    return name[:truncate_to] + ellipsis


def map_sigma_level_to_severity(level) -> str:
    """
    Map Sigma rule level to LakeWatch severity.
    
    Args:
        level: Sigma rule level (SigmaLevel object or string)
        
    Returns:
        LakeWatch severity string
    """
    if not level:
        return "Medium"
    
    # Convert SigmaLevel object to string
    level_str = str(level).lower() if level else None
    if not level_str:
        return "Medium"
    
    mapping = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'informational': 'Low'
    }
    return mapping.get(level_str, 'Medium')


def build_objective_from_sigma_metadata(rule) -> Optional[str]:
    """
    Build objective text from Sigma rule metadata.
    
    Captures:
    - rule.fields: What fields to examine
    - rule.falsepositives: Known false positive scenarios
    - rule.references: Reference URLs
    
    Args:
        rule: SigmaRule object
        
    Returns:
        Formatted objective string or None if no metadata available
    """
    sections = []
    
    # Add fields section
    if hasattr(rule, 'fields') and rule.fields:
        fields_str = ', '.join(str(f) for f in rule.fields)
        sections.append(f"Examine fields: {fields_str}")
    
    # Add false positives section
    if hasattr(rule, 'falsepositives') and rule.falsepositives:
        fp_list = [str(fp) for fp in rule.falsepositives]
        if len(fp_list) == 1:
            sections.append(f"False positive: {fp_list[0]}")
        else:
            fp_numbered = [f"{i+1}. {fp}" for i, fp in enumerate(fp_list)]
            sections.append(f"False positives: " + " ".join(fp_numbered))
    
    # Add references section
    if hasattr(rule, 'references') and rule.references:
        ref_list = [str(ref) for ref in rule.references]
        if len(ref_list) == 1:
            sections.append(f"Reference: {ref_list[0]}")
        else:
            sections.append(f"References: {', '.join(ref_list)}")
    
    # Return formatted text or None (normalized to single line)
    if sections:
        result = " ".join(sections)
        return normalize_multiline_string(result)
    return None

class Rule(CoreV1Rule):
    """Extended CoreV1Rule with Sigma conversion classmethod"""
    
    def to_json(self, indent: int = 2) -> str:
        """Convert Rule to JSON with None values removed and field order maintained"""
        import json
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_dict(self) -> dict:
        """Convert Rule to dict with None values removed and field order maintained"""
        result = dasl_to_dict(self)
        
        def reorder_dict(data: dict, key_order: list) -> dict:
            """Helper to reorder dict keys with specified order, keeping extras at end"""
            ordered = {}
            # Add keys in specified order
            for key in key_order:
                if key in data:
                    ordered[key] = data[key]
            # Add any remaining keys
            for key in data:
                if key not in ordered:
                    ordered[key] = data[key]
            return ordered
        
        # Reorder nested structures
        if 'spec' in result:
            spec = result['spec']
            
            # Reorder spec.metadata if present
            if 'metadata' in spec:
                spec['metadata'] = reorder_dict(
                    spec['metadata'],
                    ['version', 'severity', 'fidelity', 'objective', 'mitre', 'response']
                )
            
            # Reorder spec itself
            result['spec'] = reorder_dict(
                spec,
                ['schedule', 'input', 'output', 'metadata', 'computeMode']
            )
        
        # Reorder top-level
        return reorder_dict(result, ['metadata', 'spec', 'apiVersion', 'kind'])
    
    def save(self, filepath: str) -> None:
        """Save rule to JSON file"""
        with open(filepath, 'w') as f:
            f.write(self.to_json())
    
    @classmethod
    def from_sigma_rule(cls, rule, query: str, is_correlation: bool = False) -> 'Rule':
        """
        Build a LakeWatch Rule from a Sigma rule and its SQL query.
        
        Args:
            rule: SigmaRule or SigmaCorrelationRule
            query: The finalized SQL query string
            is_correlation: Whether this is a correlation rule
            
        Returns:
            LakeWatch Rule object
        """
        # Build annotations with logsource fields
        annotations = {"source": "sigma"}
        
        # Add logsource fields to annotations if available
        if hasattr(rule, 'logsource') and rule.logsource:
            if rule.logsource.category:
                annotations["category"] = str(rule.logsource.category)
            if rule.logsource.product:
                annotations["product"] = str(rule.logsource.product)
            if rule.logsource.service:
                annotations["service"] = str(rule.logsource.service)

        # add the sigma status: since the vast majority are either test or experimental not stable. 
        # experimental and test rules sometimes lack enough quality information for AI mapping to be accurate.
        annotations["sigma_status"] = str(rule.status)
        
        # Build metadata
        rule_metadata = RuleMetadata(
            name=truncate_rule_name(rule.title or "Untitled Rule"),
            comment=normalize_multiline_string(rule.description),
            annotations=annotations,
            resource_status=None  # Exclude from JSON output
        )
        
        # Build schedule
        # Non-correlation: 12 hours (batch)
        # Correlation: 5 minutes (streaming placeholder)
        schedule_interval = "5m" if is_correlation else "12h"
        schedule = Schedule(
            at_least_every=schedule_interval,
            enabled=False  # dasl_api default is True
        )
        
        # Build input
        input_config = None
        if is_correlation:
            # Correlation rules: streaming input (placeholder for now)
            stream_input = StreamInput(sql=query)
            input_config = Input(stream=stream_input)
        else:
            # Non-correlation rules: batch input
            batch_input = BatchInput(sql=query)
            input_config = Input(batch=batch_input)
        
        # Build output
        output = Output(
            summary=normalize_multiline_string(rule.description or rule.title or "Detection Alert"),
            default_context=True
        )
        
        # Build spec metadata
        severity = map_sigma_level_to_severity(getattr(rule, 'level', None))
        
        # Parse MITRE tags
        mitre_attacks = []
        if hasattr(rule, 'tags') and rule.tags:
            mitre_attacks = parse_mitre_tags(rule.tags)
        
        # Build objective from Sigma metadata
        objective = build_objective_from_sigma_metadata(rule)
        
        spec_metadata = SpecMetadata(
            version=1.0,
            severity=severity,
            fidelity="Investigative",  # Explicitly set (not available in Sigma)
            category=None,
            objective=objective,
            mitre=mitre_attacks if mitre_attacks else None
        )
        
        # Build rule spec
        rule_spec = RuleSpec(
            schedule=schedule,
            input=input_config,
            output=output,
            metadata=spec_metadata,
            compute_mode="high"
        )
        
        # Build complete rule
        return cls(
            api_version="v1",  # dasl_api defaults to None
            kind="Rule",
            metadata=rule_metadata,
            spec=rule_spec
        )
