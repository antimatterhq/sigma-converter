from sigma.rule import SigmaYAMLLoader, SigmaRuleBase, SigmaRule
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict, Union
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import yaml
import json


PATHS = [
    "rules/"
]

@dataclass
class FieldMapping:
    """Represents a single field mapping from source to target."""
    source_field: str           # e.g., "category", "product", "service"
    source_value: Any          # Original value from Sigma rule
    mapped_at: Optional[str] = None     # ISO timestamp when mapping occurred
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'source_field': self.source_field,
            'source_value': self.source_value,
            'mapped_at': self.mapped_at
        }


@dataclass
class LogSourceMapping:
    """Contains all logsource field mappings."""
    category: Optional[FieldMapping] = None
    product: Optional[FieldMapping] = None
    service: Optional[FieldMapping] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {}
        if self.category:
            result['category'] = self.category.to_dict()
        if self.product:
            result['product'] = self.product.to_dict()
        if self.service:
            result['service'] = self.service.to_dict()
        return result


@dataclass
class DetectionFieldMapping:
    """Maps detection fields to OCSF table fields."""
    source_field: str                   # e.g., "EventID", "dst_port"
    target_table: Optional[str] = None  # e.g., "network", "process"  
    target_field: Optional[str] = None  # OCSF field name
    mapped_at: Optional[str] = None     # ISO timestamp when mapping occurred
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'source_field': self.source_field,
            'target_table': self.target_table,
            'target_field': self.target_field,
            'mapped_at': self.mapped_at
        }


@dataclass
class OCSFLite:
    """OCSF Lite mapping for Sigma rules."""
    class_name: Optional[str] = None                           # Target OCSF event class
    activity_id: Optional[Union[int, str]] = None              # Target activity_id (int) or "<UNMAPPED>"
    logsource: Optional[LogSourceMapping] = None               # Logsource mappings
    detection_fields: Optional[List[DetectionFieldMapping]] = None  # Detection field mappings
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'class_name': self.class_name,
            'activity_id': self.activity_id,
            'logsource': self.logsource.to_dict() if self.logsource else None,
            'detection_fields': [f.to_dict() for f in self.detection_fields] if self.detection_fields else []
        }


@dataclass
class PipelineMappings:
    """Container for all pipeline processing mappings extracted from OCSF rule files."""
    
    logsource_mappings: Dict[tuple[Optional[str], Optional[str], Optional[str]], str]
    """Logsources that map unambiguously to a single table"""
    
    conflicted_rule_mappings: Dict[str, str]
    """Rules from conflicted logsources that need per-rule table assignment"""
    
    activity_id_mappings: Dict[str, int]
    """Rules with valid activity_id (integer) that should be added to WHERE clause"""
    
    field_mappings: Dict[str, List[str]]
    """Source field to list of target field paths (for FieldMappingTransformation)"""
    
    @property
    def logsource_count(self) -> int:
        """Number of non-conflicted logsource mappings"""
        return len(self.logsource_mappings)
    
    @property
    def conflicted_count(self) -> int:
        """Number of conflicted rule mappings"""
        return len(self.conflicted_rule_mappings)
    
    @property
    def activity_id_count(self) -> int:
        """Number of rules with activity_id"""
        return len(self.activity_id_mappings)
    
    @property
    def total_table_mappings(self) -> int:
        """Total number of table assignment ProcessingItems needed"""
        return self.logsource_count + self.conflicted_count
    
    @property
    def field_mapping_count(self) -> int:
        """Number of unique source fields mapped"""
        return len(self.field_mappings)


class SigmaRuleOCSFLite(SigmaRule):
    """Extended SigmaRule with OCSF Lite mapping."""
    
    def __init__(self, *args, **kwargs):
        """Initialize with an OCSF Lite mapping."""
        super().__init__(*args, **kwargs)
        self.ocsflite = OCSFLite()
        self.source_filename = kwargs.get('source_filename', None)
    
    @classmethod
    def from_sigma_rule(cls, sigma_rule: SigmaRule, source_filename: Optional[str] = None) -> 'SigmaRuleOCSFLite':
        """Create a SigmaRuleOCSFLite from a SigmaRule, adding OCSF Lite mapping."""
        # Create instance by copying the sigma_rule
        instance = cls.__new__(cls)
        # Copy all attributes from sigma_rule
        instance.__dict__.update(sigma_rule.__dict__)
        # Add the ocsflite field
        instance.ocsflite = OCSFLite()
        instance.source_filename = source_filename
        return instance

    @classmethod
    def load(cls, path: str, base_dir: str = "mappings") -> 'SigmaRuleOCSFLite':
        """
        Load a mapped rule from YAML file.
        
        Supports two input formats:
        1. Full path: load("mappings/windows/process_creation/rule.yml")
        2. Rule name: load("rule_name") - searches recursively in base_dir
        
        Auto-detects and supports both export formats:
        - Full format (default): All rule metadata + ocsf_mapping
        - Condensed format: Only event_class + field_mappings
        
        Args:
            path: Full path to mapping file or rule name (searches recursively)
            base_dir: Base directory for rule name search (default: "mappings")
            
        Returns:
            SigmaRuleOCSFLite instance with mappings loaded
            
        Raises:
            FileNotFoundError: If file not found
            ValueError: If file format is invalid
            
        Example:
            # Load by full path
            rule = SigmaRuleOCSFLite.load("mappings/windows/process_creation/rule.yml")
            
            # Load by rule name (searches recursively)
            rule = SigmaRuleOCSFLite.load("rule_name")
            
            # Load from custom directory
            rule = SigmaRuleOCSFLite.load("rule_name", base_dir="custom_mappings")
        """
        file_path = Path(path)
        
        # If not an absolute path or doesn't exist, search in base_dir
        if not file_path.is_absolute() or not file_path.exists():
            # Try as-is first
            if file_path.exists():
                target_file = file_path
            else:
                # Search recursively in base_dir
                base = Path(base_dir)
                if not base.exists():
                    raise FileNotFoundError(f"Base directory not found: {base_dir}")
                
                # Search for file by name (with or without extension)
                yaml_files = list(base.rglob(f"{path}")) + \
                            list(base.rglob(f"{path}.yml")) + \
                            list(base.rglob(f"{path}.yaml")) + \
                            list(base.rglob(f"{path}.json"))
                
                if not yaml_files:
                    raise FileNotFoundError(
                        f"Rule file not found: {path} (searched in {base_dir})"
                    )
                
                # Use first match
                target_file = yaml_files[0]
        else:
            target_file = file_path
        
        # Read the file
        with open(target_file, 'r') as f:
            if target_file.suffix == '.json':
                data = json.load(f)
            else:
                data = yaml.safe_load(f)
        
        # Create instance from dictionary
        return cls.from_mapping_dict(data, source_filename=target_file.name)

    @classmethod
    def from_mapping_dict(cls, data: dict, source_filename: Optional[str] = None) -> 'SigmaRuleOCSFLite':
        """
        Create instance from exported mapping dictionary.
        
        Auto-detects format:
        - Full format: Has 'ocsf_mapping' key with all rule attributes
        - Condensed format: Has only 'event_class' and 'field_mappings'
        
        Args:
            data: Dictionary from to_export_dict()
            source_filename: Original filename for reference
            
        Returns:
            SigmaRuleOCSFLite instance
        """
        # Detect format by checking for 'ocsf_mapping' key
        is_full_format = 'ocsf_mapping' in data
        
        if is_full_format:
            # Full format: Reconstruct complete SigmaRule
            instance = cls.__new__(cls)
            
            # Set all SigmaRule attributes from data
            for key, value in data.items():
                if key != 'ocsf_mapping':
                    setattr(instance, key, value)
            
            # OCSF mapping dict
            ocsf_data = data['ocsf_mapping']
            instance.ocsflite = OCSFLite()

            instance.ocsflite.class_name = ocsf_data.get('class_name') or ocsf_data.get('event_class')
            instance.ocsflite.activity_id = ocsf_data.get('activity_id')
            
            # logsource mappings
            if ocsf_data.get('logsource'):
                ls = ocsf_data['logsource']
                instance.ocsflite.logsource = LogSourceMapping()
                
                if ls.get('category'):
                    instance.ocsflite.logsource.category = FieldMapping(**ls['category'])
                if ls.get('product'):
                    instance.ocsflite.logsource.product = FieldMapping(**ls['product'])
                if ls.get('service'):
                    instance.ocsflite.logsource.service = FieldMapping(**ls['service'])
            
            # detection field mappings
            if ocsf_data.get('detection_fields'):
                instance.ocsflite.detection_fields = [
                    DetectionFieldMapping(**field) 
                    for field in ocsf_data['detection_fields']
                ]
            
            instance.source_filename = source_filename
            return instance
            
        else:
            # Condensed format: Minimal instance with just mappings
            instance = cls.__new__(cls)
            
            # Initialize basic attributes
            instance.ocsflite = OCSFLite()
            instance.ocsflite.class_name = data.get('class_name') or data.get('event_class')
            instance.source_filename = source_filename
            
            # Parse field mappings from condensed format
            # Format: {"CommandLine": "process_activity.process.cmd_line", ...}
            field_mappings = data.get('field_mappings', {})
            instance.ocsflite.detection_fields = []
            
            for source_field, target_path in field_mappings.items():
                if target_path == "<UNMAPPED>":
                    # Unmapped field
                    mapping = DetectionFieldMapping(
                        source_field=source_field,
                        target_table=None,
                        target_field="<UNMAPPED>"
                    )
                elif target_path:
                    # Split "table.field" into components
                    parts = target_path.split('.', 1)
                    target_table = parts[0] if len(parts) > 0 else None
                    target_field = parts[1] if len(parts) > 1 else target_path
                    
                    mapping = DetectionFieldMapping(
                        source_field=source_field,
                        target_table=target_table,
                        target_field=target_field
                    )
                else:
                    # None value
                    mapping = DetectionFieldMapping(
                        source_field=source_field,
                        target_table=None,
                        target_field=None
                    )
                
                instance.ocsflite.detection_fields.append(mapping)
            
            return instance

    @classmethod
    def build_pipeline_mappings(
        cls,
        mappings_dir: str = "fieldmapper/mappings"
    ) -> PipelineMappings:
        """
        Build all pipeline mappings (tables, activity_id, fields).
        
        This method analyzes all OCSF-mapped rules and extracts:
        1. Non-conflicted logsources: Where all rules with the same logsource map to the same table
        2. Conflicted rules: Where the logsource maps to multiple tables, requiring per-rule assignment
        3. Activity IDs: For rules with valid integer activity_id values
        4. Field mappings: Source field -> list of target field paths (deduplicated)
        
        Args:
            mappings_dir: Directory containing OCSF-mapped rule files
                          Default: "fieldmapper/mappings"
        
        Returns:
            PipelineMappings dataclass containing:
            - logsource_mappings: Dict[(category, product, service)] -> table_name
              For logsources where ALL rules map to the same table
            - conflicted_rule_mappings: Dict[rule_id] -> table_name
              For rules where logsource maps to multiple tables
            - activity_id_mappings: Dict[rule_id] -> activity_id
              For rules with valid integer activity_id
            - field_mappings: Dict[source_field] -> List[target_field]
              For FieldMappingTransformation (deduplicated across all rules)
        
        Example:
            >>> mappings = SigmaRuleOCSFLite.build_pipeline_mappings()
            >>> 
            >>> # Non-conflicted: All process_creation/linux rules -> process_activity
            >>> print(mappings.logsource_mappings[('process_creation', 'linux', None)])
            'process_activity'
            >>> 
            >>> # Conflicted: file_event/windows rules need per-rule assignment
            >>> print(mappings.conflicted_rule_mappings['fcc6d700-68d9-4241-9a1a-06874d621b06'])
            'file_activity'
            >>> 
            >>> # Activity IDs
            >>> print(mappings.activity_id_mappings['f512acbf-e662-4903-843e-97ce4652b740'])
            12
            >>> 
            >>> # Field mappings
            >>> print(mappings.field_mappings['CommandLine'])
            ['process.cmd_line']
            >>> 
            >>> # Use helper properties
            >>> print(f"Logsources: {mappings.logsource_count}, Conflicted: {mappings.conflicted_count}")
            >>> print(f"Rules with activity_id: {mappings.activity_id_count}")
            >>> print(f"Mapped fields: {mappings.field_mapping_count}")
        """
        # Group rules by logsource
        logsource_to_rules = defaultdict(list)
        
        # Field mappings accumulator (use set to avoid duplicates)
        field_mappings_sets: Dict[str, set] = {}
        
        # Find all YAML files in mappings directory
        base_path = Path(mappings_dir)
        if not base_path.exists():
            raise FileNotFoundError(f"Mappings directory not found: {mappings_dir}")
        
        yaml_files = list(base_path.rglob("*.yml"))
        
        # Load each file and extract all mappings in a single pass
        for file_path in yaml_files:
            try:
                rule = cls.load(str(file_path))
                
                # Skip if no OCSF mapping, no ID, or unmapped
                if not rule.ocsflite or not rule.ocsflite.class_name:
                    continue
                if rule.ocsflite.class_name == "<UNMAPPED>":
                    continue
                if not rule.id:
                    continue
            
                # logsource mappings (for conflict detection, include ALL rules)
                # Get logsource fields (handle dict or object)
                logsource = rule.logsource
                if isinstance(logsource, dict):
                    category = logsource.get('category')
                    product = logsource.get('product')
                    service = logsource.get('service')
                else:
                    category = getattr(logsource, 'category', None)
                    product = getattr(logsource, 'product', None)
                    service = getattr(logsource, 'service', None)
                
                logsource_key = (category, product, service)
                
                logsource_to_rules[logsource_key].append({
                    'id': str(rule.id),
                    'table': rule.ocsflite.class_name,
                    'activity_id': rule.ocsflite.activity_id
                })
                
                # Extract field mappings (from ALL rules with detection_fields)
                if rule.ocsflite and rule.ocsflite.detection_fields:
                    for field_mapping in rule.ocsflite.detection_fields:
                        # Skip unmapped fields
                        if not field_mapping.target_field or field_mapping.target_field == "<UNMAPPED>":
                            continue
                        
                        source = field_mapping.source_field
                        target = field_mapping.target_field
                        
                        # Add to mappings (use set to deduplicate)
                        if source not in field_mappings_sets:
                            field_mappings_sets[source] = set()
                        field_mappings_sets[source].add(target)
            
            except Exception as e:
                # Skip files that can't be loaded
                continue
        
        # Separate non-conflicted logsources from conflicted rules
        logsource_mappings = {}
        conflicted_rule_mappings = {}
        
        for logsource_key, rules in logsource_to_rules.items():
            # Get unique tables for this logsource
            tables = set(r['table'] for r in rules)
            
            if len(tables) == 1:
                # No conflict: all rules with this logsource map to the same table
                # Use LogsourceCondition for efficiency
                logsource_mappings[logsource_key] = list(tables)[0]
            else:
                # Conflict: rules with this logsource map to different tables
                # Add each rule individually using RuleIDCondition
                for rule in rules:
                    conflicted_rule_mappings[rule['id']] = rule['table']
        
        # Extract activity_id mappings (only valid integers)
        activity_id_mappings = {}
        for logsource_key, rules in logsource_to_rules.items():
            for rule in rules:
                activity_id = rule.get('activity_id')
                if isinstance(activity_id, int):
                    activity_id_mappings[rule['id']] = activity_id
        
        # Convert field mapping sets to sorted lists for consistent output
        field_mappings = {source: sorted(list(targets)) 
                         for source, targets in sorted(field_mappings_sets.items())}
        
        return PipelineMappings(
            logsource_mappings=logsource_mappings,
            conflicted_rule_mappings=conflicted_rule_mappings,
            activity_id_mappings=activity_id_mappings,
            field_mappings=field_mappings
        )

    @property
    def ocsf_category(self) -> Optional[str]:
        """
        Full OCSF category path (e.g., 'system/process_activity').
        
        Returns:
            Category/class path or None if not mapped
            
        Example:
            >>> rule.ocsf_category
            'system/process_activity'
        """
        return self.ocsflite.class_name
    
    @property
    def gold_table(self) -> Optional[str]:
        """
        OCSF event class / gold table name (e.g., 'process_activity').
        
        Returns:
            Event class name or None if not mapped
            
        Example:
            >>> rule.gold_table
            'process_activity'
        """
        if not self.ocsflite.class_name:
            return None
        # Extract table name from "system/process_activity" -> "process_activity"
        return self.ocsflite.class_name.split('/')[-1]

    @property
    def activity_id(self) -> Optional[int]:
        """
        OCSF activity_id for the rule.
        """
        if not self.ocsflite.activity_id:
            return None

        return self.ocsflite.activity_id
    
    @property
    def detection_fields(self) -> List[str]:
        """
        List of all Sigma detection field names.
        
        Returns:
            List of source field names (e.g., ['CommandLine', 'Image', 'User'])
            Empty list if no detection fields
            
        Example:
            >>> rule.detection_fields
            ['CommandLine', 'Image', 'ParentImage']
        """
        if not self.ocsflite.detection_fields:
            return []
        return [mapping.source_field for mapping in self.ocsflite.detection_fields]
    
    # Methods for field lookups
    
    def gold_table_field(self, sigma_field: str) -> Optional[str]:
        """
        Get OCSF field path for a Sigma detection field.
        
        Args:
            sigma_field: Sigma detection field name
            
        Returns:
            Full OCSF field path (table.field) or None if unmapped/not found
            
        Example:
            >>> rule.gold_table_field('CommandLine')
            'process_activity.process.cmd_line'
            >>> rule.gold_table_field('Unknown')
            None
        """
        if not self.ocsflite.detection_fields:
            return None
        
        for mapping in self.ocsflite.detection_fields:
            if mapping.source_field == sigma_field:
                # Check if unmapped
                if mapping.target_field == "<UNMAPPED>" or not mapping.target_field:
                    return None
                # Return full path: table.field
                if mapping.target_table:
                    return f"{mapping.target_table}.{mapping.target_field}"
                else:
                    # Fallback if no table (shouldn't happen in normal cases)
                    return mapping.target_field
        
        # Field not found
        return None
    
    def get_field_mappings(self) -> dict[str, Optional[str]]:
        """
        Get all field mappings as a dictionary.
        
        Returns:
            Dict of sigma_field -> ocsf_field_path
            Unmapped fields have None value
            
        Example:
            >>> rule.get_field_mappings()
            {
                'CommandLine': 'process_activity.process.cmd_line',
                'Image': 'process_activity.process.name',
                'Unknown': None
            }
        """
        if not self.ocsflite.detection_fields:
            return {}
        
        mappings = {}
        for mapping in self.ocsflite.detection_fields:
            sigma_field = mapping.source_field
            
            # Check if unmapped
            if mapping.target_field == "<UNMAPPED>" or not mapping.target_field:
                mappings[sigma_field] = None
            elif mapping.target_table:
                mappings[sigma_field] = f"{mapping.target_table}.{mapping.target_field}"
            else:
                # Fallback if no table
                mappings[sigma_field] = mapping.target_field
        
        return mappings
    
    @property
    def is_mapped(self) -> bool:
        """
        Check if rule has been mapped to an OCSF event class.
        
        Returns:
            True if event_class exists and is not '<UNMAPPED>'
            
        Example:
            >>> rule.is_mapped
            True
        """
        return (
            self.ocsflite.class_name is not None and 
            self.ocsflite.class_name != "<UNMAPPED>"
        )
    
    @property
    def has_field_mappings(self) -> bool:
        """
        Check if rule has any detection field mappings.
        
        Returns:
            True if detection_fields exist and not empty
            
        Example:
            >>> rule.has_field_mappings
            True
        """
        return (
            self.ocsflite.detection_fields is not None and 
            len(self.ocsflite.detection_fields) > 0
        )
    
    def unmapped_fields(self) -> List[str]:
        """
        Get list of detection fields that couldn't be mapped.
        
        Returns:
            List of field names with '<UNMAPPED>' or None target
            
        Example:
            >>> rule.unmapped_fields()
            ['UnknownField', 'CustomField']
        """
        if not self.ocsflite.detection_fields:
            return []
        
        unmapped = []
        for mapping in self.ocsflite.detection_fields:
            if (mapping.target_field == "<UNMAPPED>" or 
                mapping.target_field is None):
                unmapped.append(mapping.source_field)
        
        return unmapped

    def create_logsource_mappings(self) -> None:
        """Initialize logsource mappings from the rule's logsource fields."""
        if not self.logsource:
            return
        
        mappings = LogSourceMapping()
        
        if self.logsource.category:
            mappings.category = FieldMapping(
                source_field="category",
                source_value=self.logsource.category
            )
        
        if self.logsource.product:
            mappings.product = FieldMapping(
                source_field="product", 
                source_value=self.logsource.product
            )
        
        if self.logsource.service:
            mappings.service = FieldMapping(
                source_field="service",
                source_value=self.logsource.service
            )
        
        self.ocsflite.logsource = mappings
    
    def create_detection_mappings(self) -> None:
        """
        Initialize detection field mappings from the rule's detection fields.
        
        Handles both dict-style and list-style detection structures by
        recursively traversing SigmaDetection objects to find SigmaDetectionItem
        objects that contain the actual field names.
        
        Dict-style:
          detection:
            selection:
              EventID: 4688
              
        List-style (with modifiers):
          detection:
            selection:
              - Image|endswith: '.exe'
        """
        if not self.detection or not self.detection.detections:
            return
        
        field_mappings = []
        seen_fields = set()  # Track unique field names
        
        def extract_fields_recursive(detection):
            """Recursively extract field names from detection structure."""
            for item in detection.detection_items:
                # Check if item is a SigmaDetectionItem (has 'field' attribute)
                if hasattr(item, 'field') and item.field:
                    field_name = item.field
                    
                    # Add if not already seen
                    if field_name not in seen_fields:
                        field_mappings.append(
                            DetectionFieldMapping(
                                source_field=field_name,
                                target_table=None,  # To be filled by AI
                                target_field=None   # To be filled by AI
                            )
                        )
                        seen_fields.add(field_name)
                
                # Check if item is a nested SigmaDetection
                elif hasattr(item, 'detection_items'):
                    # Recursively process nested detection
                    extract_fields_recursive(item)
        
        # Process all detection blocks
        for detection_name, detection in self.detection.detections.items():
            extract_fields_recursive(detection)
        
        # Always set detection_fields, even if empty
        self.ocsflite.detection_fields = field_mappings if field_mappings else []
    
    def populate_mappings_with_ai(self, ai_mapper) -> bool:
        """
        Use AI to populate OCSF Lite mappings.
        
        This method performs two-step mapping:
        1. Maps logsource + context to OCSF event class
        2. Maps detection fields to OCSF field paths
        
        Args:
            ai_mapper: OpenAIMapper instance for performing AI mappings
            
        Returns:
            bool: True if rule was successfully mapped, False if skipped (keyword-based detection)
        """
        # Ensure base mappings exist
        if not self.ocsflite.logsource:
            self.create_logsource_mappings()
        if not self.ocsflite.detection_fields:
            self.create_detection_mappings()
        
        # Map to event class
        # Lazy import to avoid circular dependency (ai_mapper imports rules)
        from fieldmapper.ocsf.ai_mapper import MappingContext
        context = MappingContext.from_sigma_rule(self)
        event_class = ai_mapper.map_to_event_class(context)
        
        if event_class != "<UNMAPPED>":
            self.ocsflite.class_name = event_class
        
        # if no detection fields to map
        if not self.ocsflite.detection_fields:
            print(f"     Skipping field mapping: Rule '{self.title}' uses keyword-based detection (no fields)")
            return False
        
        # Map detection fields (only if we have fields and event class)
        if event_class != "<UNMAPPED>":
            # Set timestamp on logsource mappings since event class was determined
            timestamp = datetime.now(timezone.utc).isoformat()
            if self.ocsflite.logsource:
                if self.ocsflite.logsource.category:
                    self.ocsflite.logsource.category.mapped_at = timestamp
                if self.ocsflite.logsource.product:
                    self.ocsflite.logsource.product.mapped_at = timestamp
                if self.ocsflite.logsource.service:
                    self.ocsflite.logsource.service.mapped_at = timestamp
            
            # Map detection fields (batch call, only uncached)
            source_fields = [m.source_field for m in self.ocsflite.detection_fields]
            field_mappings = ai_mapper.map_detection_fields(event_class, source_fields)
            
            # Extract table name: "system/process_activity" → "process_activity"
            table_name = event_class.split('/')[-1]
            
            # Update detection field mappings
            for mapping in self.ocsflite.detection_fields:
                target_path = field_mappings.get(mapping.source_field, "<UNMAPPED>")
                mapping.target_table = table_name
                mapping.target_field = target_path  # Store AI response directly (field path or "<UNMAPPED>")
                mapping.mapped_at = datetime.now(timezone.utc).isoformat()

        # Map activity_id for the event class
        if event_class != "<UNMAPPED>":
            activity_id = ai_mapper.map_activity_id(event_class, context)

            if activity_id is not None:
                self.ocsflite.activity_id = activity_id
            else:
                self.ocsflite.activity_id = "<UNMAPPED>"
        else:
            print(f"     Skipping activity_id mapping:")
        
        return True
    
    def to_export_dict(self, full: bool = False) -> dict:
        """
        Export rule mappings to dictionary format.
        
        Args:
            full: If False (default), returns only event_class and field_mappings.
                  If True, returns full rule details including OCSF mappings.
        
        Returns:
            Dictionary representation suitable for YAML/JSON export
        """
        if full:
            # Full export: include all SigmaRule attributes + OCSF mappings
            # Define all SigmaRule attributes to export
            rule_attrs = [
                'id', 'title', 'status', 'level', 'description', 'author',
                'date', 'modified', 'tags', 'references', 'fields',
                'falsepositives', 'license', 'custom_attributes',
                'name', 'related', 'scope', 'taxonomy',
                'logsource',    # Original logsource from YAML
                'detection'     # Original detection from YAML
            ]
            
            result = {}
            
            # Export all SigmaRule attributes
            for attr in rule_attrs:
                if hasattr(self, attr):
                    value = getattr(self, attr)
                    if value is not None:
                        # Skip empty collections (lists, tuples, dicts)
                        if isinstance(value, (list, tuple, dict)) and not value:
                            continue
                        # Convert to serializable format
                        if isinstance(value, (list, tuple)):
                            # Convert items to strings if they're objects (like SigmaRuleTag)
                            # but preserve simple types as-is
                            result[attr] = [str(item) if not isinstance(item, (str, int, float, bool)) else item for item in value]
                        elif isinstance(value, dict):
                            result[attr] = value
                        elif hasattr(value, 'to_dict'):
                            # Use object's own serialization method
                            result[attr] = value.to_dict()
                        else:
                            # Only convert non-serializable types to string
                            if isinstance(value, (str, int, float, bool, type(None))):
                                result[attr] = value
                            else:
                                result[attr] = str(value)
            
            # Add OCSF mappings (shows source -> target mappings)
            result['ocsf_mapping'] = self.ocsflite.to_dict()
            
            return result
        else:
            # Default export: only event_class and field mappings (simple dict format)
            field_mappings = {}
            if self.ocsflite.detection_fields:
                for mapping in self.ocsflite.detection_fields:
                    if mapping.target_field == "<UNMAPPED>":
                        # Source field name stays as key, value is "<UNMAPPED>"
                        field_mappings[mapping.source_field] = "<UNMAPPED>"
                    elif mapping.target_field:
                        # Format as "source_field: target_table.target_field"
                        field_mappings[mapping.source_field] = f"{mapping.target_table}.{mapping.target_field}"
                    else:
                        field_mappings[mapping.source_field] = None
            
            return {
                'event_class': self.ocsflite.class_name,
                'activity_id': self.ocsflite.activity_id,
                'field_mappings': field_mappings
            }
    



def load_sigma_rules(base_path: str = ".", 
                     filename: Optional[str] = None,
                     initialize_logsource_mappings: bool = True,
                     initialize_detection_mappings: bool = True) -> List[SigmaRuleOCSFLite]:
    """
    Recursively discover YAML files in PATHS, load them using SigmaRule.from_yaml(),
    and return a list of SigmaRuleOCSFLite objects.
    
    Args:
        base_path: Base directory to resolve relative paths from (defaults to current directory)
        filename: Optional specific filename to load (e.g., "net_firewall_cleartext_protocols.yml")
                  If provided, only this file will be loaded from PATHS directories
        initialize_logsource_mappings: If True, initialize logsource mapping structures
        initialize_detection_mappings: If True, initialize detection field mapping structures
    
    Returns:
        List of SigmaRuleOCSFLite objects with OCSF Lite mapping structures
    """
    rules = []
    base = Path(base_path)
    
    for path_str in PATHS:
        path = base / path_str
        
        if not path.exists():
            print(f"Warning: Path does not exist: {path}")
            continue
        
        if filename:
            # Search for specific file directly
            yaml_files = list(path.rglob(f"**/{filename}"))
        else:
            # Find all .yml and .yaml files
            yaml_files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))

        for yaml_file in yaml_files:
            try:
                # Read the YAML file
                with open(yaml_file, 'r') as f:
                    yaml_str = f.read()
                
                # Load the Sigma rule using SigmaRule.from_yaml()
                sigma_rule = SigmaRule.from_yaml(yaml_str)
                
                # Convert to SigmaRuleOCSFLite
                if sigma_rule:
                    rule = SigmaRuleOCSFLite.from_sigma_rule(sigma_rule, source_filename=yaml_file.name)
                    
                    # Initialize mappings if requested
                    if initialize_logsource_mappings:
                        rule.create_logsource_mappings()
                    if initialize_detection_mappings:
                        rule.create_detection_mappings()
                    
                    rules.append(rule)
                        
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")
                continue
    
    return rules
