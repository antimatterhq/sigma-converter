"""
OCSF Lite Schema Loader

Loads and provides access to the OCSF Lite schema for AI mapping.
The schema is exported from generate-ocsf-lite-tables.py in a flattened
format optimized for AI prompts.
"""

import json
from typing import List, Dict, Optional


class OCSFLiteSchema:
    """Loads and provides access to OCSF Lite schema for AI mapping."""
    
    def __init__(self, schema_path: str = "ocsf_lite_ai_schema.json"):
        """
        Initialize the schema loader.
        
        Args:
            schema_path: Path to the AI-optimized schema JSON file
        """
        with open(schema_path) as f:
            self.schema = json.load(f)
        
        # Index for fast lookup
        self.event_classes = {ec["event_class"]: ec for ec in self.schema}
        self.field_index = {}  # event_class -> {field_path: field_info}
        self.node_index = {}   # event_class -> {node_path: node_info}
        
        for ec in self.schema:
            self.field_index[ec["event_class"]] = {
                f["path"]: f for f in ec["fields"]
            }
            nodes = ec.get("nodes", [])
            self.node_index[ec["event_class"]] = {
                n["path"]: n for n in nodes
            }
    
    def get_event_class_names(self) -> List[str]:
        """
        Return list of all event class names.
        
        Returns:
            List of event class names (e.g., ["system/process_activity", ...])
        """
        return list(self.event_classes.keys())
    
    def get_event_class(self, name: str) -> Optional[Dict]:
        """
        Get full schema for an event class.
        
        Args:
            name: Event class name (e.g., "system/process_activity")
            
        Returns:
            Event class schema dict or None if not found
        """
        return self.event_classes.get(name)
    
    def get_fields_for_event_class(self, name: str) -> List[str]:
        """
        Get list of field paths for an event class.
        
        Args:
            name: Event class name
            
        Returns:
            List of field paths (e.g., ["process.cmd_line", "actor.user.name", ...])
        """
        return list(self.field_index.get(name, {}).keys())
    
    def validate_field(self, event_class: str, field_path: str) -> bool:
        """
        Check if a field path exists in the event class.
        
        Args:
            event_class: Event class name
            field_path: Field path to validate (e.g., "process.cmd_line")
            
        Returns:
            True if field exists, False otherwise
        """
        return field_path in self.field_index.get(event_class, {})
    
    def get_field_info(self, event_class: str, field_path: str) -> Optional[Dict]:
        """
        Get detailed information about a specific field.
        
        Args:
            event_class: Event class name
            field_path: Field path
            
        Returns:
            Field info dict with path, type, and description, or None if not found
        """
        return self.field_index.get(event_class, {}).get(field_path)
    
    def search_fields_by_name(self, field_name: str, case_sensitive: bool = False) -> Dict[str, List[str]]:
        """
        Find all event classes containing fields matching field_name.
        
        Args:
            field_name: Field name to search for
            case_sensitive: Whether to perform case-sensitive search
            
        Returns:
            Dict mapping event class names to lists of matching field paths
        """
        results = {}
        search_term = field_name if case_sensitive else field_name.lower()
        
        for ec_name, fields in self.field_index.items():
            matching = []
            for path in fields:
                compare_path = path if case_sensitive else path.lower()
                if search_term in compare_path:
                    matching.append(path)
            
            if matching:
                results[ec_name] = matching
        
        return results
    
    def get_stats(self) -> Dict:
        """
        Get schema statistics.
        
        Returns:
            Dict with schema statistics (num_event_classes, total_fields, etc.)
        """
        total_fields = sum(len(fields) for fields in self.field_index.values())
        
        return {
            "num_event_classes": len(self.event_classes),
            "total_fields": total_fields,
            "avg_fields_per_class": total_fields / len(self.event_classes) if self.event_classes else 0,
            "event_classes": list(self.event_classes.keys())
        }

