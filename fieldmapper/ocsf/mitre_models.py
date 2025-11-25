"""
MITRE ATT&CK Data Models

Dataclasses for structured MITRE ATT&CK data with flexible extraction
for AI context generation.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class LogSourceReference:
    """Log source reference from an analytic, linking to data components."""
    data_component_id: str  # STIX ID like "x-mitre-data-component--..."
    data_component_name: str  # Human-readable name like "Process Creation"
    data_component_external_id: Optional[str] = None  # External ID like "DC0032"
    data_source_name: Optional[str] = None  # Parent data source like "Process"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Analytic:
    """Associated analytic for a detection strategy."""
    id: str  # STIX ID from x_mitre_analytic_refs
    name: str
    description: Optional[str] = None
    log_sources: List['LogSourceReference'] = field(default_factory=list)  # Log source references
    created: Optional[str] = None  # ISO date string
    modified: Optional[str] = None  # ISO date string
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with nested LogSourceReference."""
        result = asdict(self)
        # Convert nested LogSourceReference objects
        result['log_sources'] = [ls if isinstance(ls, dict) else ls.to_dict() for ls in self.log_sources]
        return result


@dataclass
class DetectionStrategy:
    """Detection strategy information from MITRE ATT&CK."""
    id: str  # DET0414
    name: str  # "Detection of AppleScript-Based Execution on macOS"
    url: Optional[str] = None
    description: Optional[str] = None  # Full description from detection strategy object
    analytics: List['Analytic'] = field(default_factory=list)  # Associated analytics
    created: Optional[str] = None  # ISO date string
    modified: Optional[str] = None  # ISO date string
    version: Optional[str] = None  # x_mitre_version
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        # Convert nested Analytic objects
        result['analytics'] = [a if isinstance(a, dict) else a.to_dict() for a in self.analytics]
        return result


@dataclass
class ProcedureExample:
    """Procedure example showing real-world usage of a technique."""
    actor: str  # Group or malware name
    description: str  # How they used the technique (from relationship)
    source_type: Optional[str] = None  # 'intrusion-set' or 'malware'
    actor_id: Optional[str] = None  # External ID (G0001, S0001)
    actor_aliases: List[str] = field(default_factory=list)  # Other names for the actor
    actor_url: Optional[str] = None  # URL to ATT&CK page
    created: Optional[str] = None  # ISO date string
    modified: Optional[str] = None  # ISO date string
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Mitigation:
    """Mitigation information for a technique."""
    id: str  # M1038
    name: str  # "Execution Prevention"
    url: Optional[str] = None
    description: Optional[str] = None  # Full mitigation description from mitigation object
    relationship_description: Optional[str] = None  # How it applies to this specific technique
    created: Optional[str] = None  # ISO date string
    modified: Optional[str] = None  # ISO date string
    version: Optional[str] = None  # x_mitre_version
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MitreTechnique:
    """
    Comprehensive MITRE ATT&CK technique data.
    
    Stores complete information about a technique with methods for
    flexible extraction to AI prompts.
    """
    id: str  # T1059.002
    name: str  # AppleScript
    tactic: Optional[str]  # execution
    
    # Core detection data
    data_sources: List[str] = field(default_factory=list)
    data_components: List[str] = field(default_factory=list)
    detection_strategies: List[DetectionStrategy] = field(default_factory=list)
    
    # Platform and environment
    platforms: List[str] = field(default_factory=list)  # macOS, Windows, Linux, etc.
    
    # Descriptive information
    description: Optional[str] = None  # Full description
    created: Optional[str] = None  # ISO date string
    modified: Optional[str] = None  # ISO date string
    
    # Technique hierarchy
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None  # T1059 for T1059.002
    subtechniques: List[str] = field(default_factory=list)  # List of sub-technique IDs
    
    # Real-world usage and mitigation
    procedure_examples: List[ProcedureExample] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.
        
        Returns:
            Dictionary with all fields, nested dataclasses converted to dicts
        """
        result = {
            'id': self.id,
            'name': self.name,
            'tactic': self.tactic,
            'data_sources': self.data_sources,
            'data_components': self.data_components,
            'detection_strategies': [ds.to_dict() for ds in self.detection_strategies],
            'platforms': self.platforms,
            'description': self.description,
            'created': self.created,
            'modified': self.modified,
            'is_subtechnique': self.is_subtechnique,
            'parent_technique': self.parent_technique,
            'subtechniques': self.subtechniques,
            'procedure_examples': [pe.to_dict() for pe in self.procedure_examples],
            'mitigations': [m.to_dict() for m in self.mitigations]
        }
        return result
    
    def to_ai_context(self, include_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Extract specified fields for AI context to manage token usage.
        
        Args:
            include_fields: List of field names to include. If None, uses default set.
                           Available fields: 'name', 'tactic', 'data_sources',
                           'data_components', 'detection_strategies', 'platforms',
                           'description', 'is_subtechnique', 'parent_technique',
                           'procedure_examples', 'mitigations'
        
        Returns:
            Dict with only requested fields (id and name always included)
        """
        # Default fields for AI context (balanced token usage)
        if include_fields is None:
            include_fields = ['detection_strategies', 'data_components', 'platforms']
        
        # Always include id and name
        result = {
            'id': self.id,
            'name': self.name
        }
        
        # Add requested fields
        if 'tactic' in include_fields and self.tactic:
            result['tactic'] = self.tactic
        
        if 'data_sources' in include_fields and self.data_sources:
            result['data_sources'] = self.data_sources
        
        if 'data_components' in include_fields and self.data_components:
            result['data_components'] = self.data_components
        
        if 'detection_strategies' in include_fields and self.detection_strategies:
            result['detection_strategies'] = [
                {'id': ds.id, 'name': ds.name} 
                for ds in self.detection_strategies
            ]
        
        if 'platforms' in include_fields and self.platforms:
            result['platforms'] = self.platforms
        
        if 'description' in include_fields and self.description:
            # Truncate description to save tokens
            desc = self.description[:300] + '...' if len(self.description) > 300 else self.description
            result['description'] = desc
        
        if 'is_subtechnique' in include_fields:
            result['is_subtechnique'] = self.is_subtechnique
        
        if 'parent_technique' in include_fields and self.parent_technique:
            result['parent_technique'] = self.parent_technique
        
        if 'procedure_examples' in include_fields and self.procedure_examples:
            # Limit to 2 examples to save tokens
            result['procedure_examples'] = [
                {'actor': pe.actor, 'description': pe.description[:150] + '...' if len(pe.description) > 150 else pe.description}
                for pe in self.procedure_examples[:2]
            ]
        
        if 'mitigations' in include_fields and self.mitigations:
            # Limit to 3 mitigations
            result['mitigations'] = [
                {'id': m.id, 'name': m.name}
                for m in self.mitigations[:3]
            ]
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MitreTechnique':
        """
        Create MitreTechnique from dictionary.
        
        Args:
            data: Dictionary with technique data
            
        Returns:
            MitreTechnique instance
        """
        # Convert nested dicts to dataclass instances
        detection_strategies = []
        for ds in data.get('detection_strategies', []):
            if isinstance(ds, dict):
                # Handle nested analytics in detection strategy
                analytics = []
                for analytic_data in ds.get('analytics', []):
                    if isinstance(analytic_data, dict):
                        # Handle nested log sources in analytic
                        log_sources = []
                        for ls_data in analytic_data.get('log_sources', []):
                            if isinstance(ls_data, dict):
                                log_sources.append(LogSourceReference(**ls_data))
                            else:
                                log_sources.append(ls_data)
                        
                        analytic_copy = analytic_data.copy()
                        analytic_copy['log_sources'] = log_sources
                        analytics.append(Analytic(**analytic_copy))
                    else:
                        analytics.append(analytic_data)
                
                ds_copy = ds.copy()
                ds_copy['analytics'] = analytics
                detection_strategies.append(DetectionStrategy(**ds_copy))
            else:
                detection_strategies.append(ds)
        
        procedure_examples = [
            ProcedureExample(**pe) if isinstance(pe, dict) else pe
            for pe in data.get('procedure_examples', [])
        ]
        
        mitigations = [
            Mitigation(**m) if isinstance(m, dict) else m
            for m in data.get('mitigations', [])
        ]
        
        return cls(
            id=data['id'],
            name=data['name'],
            tactic=data.get('tactic'),
            data_sources=data.get('data_sources', []),
            data_components=data.get('data_components', []),
            detection_strategies=detection_strategies,
            platforms=data.get('platforms', []),
            description=data.get('description'),
            created=data.get('created'),
            modified=data.get('modified'),
            is_subtechnique=data.get('is_subtechnique', False),
            parent_technique=data.get('parent_technique'),
            subtechniques=data.get('subtechniques', []),
            procedure_examples=procedure_examples,
            mitigations=mitigations
        )


# Configuration presets for AI context extraction
MITRE_AI_FIELD_PRESETS = {
    'minimal': ['data_components'],
    'standard': ['detection_strategies', 'data_components', 'platforms'],
    'detailed': ['detection_strategies', 'data_components', 'platforms', 'tactic'],
    'comprehensive': ['detection_strategies', 'data_components', 'platforms', 'tactic', 'procedure_examples'],
    'full': ['tactic', 'data_sources', 'data_components', 'detection_strategies', 
             'platforms', 'description', 'procedure_examples', 'mitigations']
}

