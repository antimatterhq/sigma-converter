"""
AI Mapping Module for Sigma to OCSF Lite conversion.

This module handles AI-powered mapping of Sigma rule fields to OCSF Lite classes and fields,
with unified caching support for both logsource and detection field mappings.
"""
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field as dataclass_field
import json
from datetime import datetime
from enum import Enum
from pathlib import Path


class MappingType(Enum):
    """Types of mappings that can be cached."""
    LOGSOURCE = "logsource"
    DETECTION_FIELD = "detection_field"


@dataclass
class MappingContext:
    """
    Context information sent to AI for mapping.
    
    This class holds all relevant information from a Sigma rule needed for
    AI-powered mapping to OCSF Lite event classes and fields.
    """
    # Rule context for better mapping
    title: str
    description: Optional[str] = None
    tags: List[str] = dataclass_field(default_factory=list)
    detection_field_names: List[str] = dataclass_field(default_factory=list)
    
    # Logsource fields (stored for convenience but also available via logsource property)
    _logsource_category: Optional[str] = None
    _logsource_product: Optional[str] = None
    _logsource_service: Optional[str] = None
    
    @property
    def logsource(self) -> Dict[str, Optional[str]]:
        """Get logsource as dict."""
        return {
            'category': self._logsource_category,
            'product': self._logsource_product,
            'service': self._logsource_service
        }
    
    @classmethod
    def from_sigma_rule(cls, rule) -> 'MappingContext':
        """
        Create MappingContext from a SigmaRuleOCSFLite object.
        
        Args:
            rule: SigmaRuleOCSFLite instance
            
        Returns:
            MappingContext with extracted information
        """
        # Extract unique detection field names
        detection_field_names = []
        if rule.ocsflite and rule.ocsflite.detection_fields:
            detection_field_names = [m.source_field for m in rule.ocsflite.detection_fields]
        
        return cls(
            title=rule.title,
            description=rule.description,
            tags=[str(tag) for tag in rule.tags] if rule.tags else [],
            detection_field_names=detection_field_names,
            _logsource_category=rule.logsource.category if rule.logsource else None,
            _logsource_product=rule.logsource.product if rule.logsource else None,
            _logsource_service=rule.logsource.service if rule.logsource else None
        )


class MappingCache:
    """
    Unified cache for both logsource and detection field mappings.
    Stores mappings in a structured format to support multiple mapping types.
    """
    
    def __init__(self, cache_file: str = ".mapping_cache.json"):
        self.cache_file = cache_file
        self._cache: Dict[str, Dict[str, Any]] = {
            "logsource": {},      # logsource_key -> class_name
            "detection_fields": {} # field_key -> {table, field}
        }
        self.load()
    
    def get_logsource_mapping(self, logsource_key: str) -> Optional[Dict[str, str]]:
        """
        Get cached logsource -> OCSF class mapping.
        
        Returns:
            Dict with mapping info (e.g., {"event_class": "process_activity"}), or None if not cached
        """
        return self._cache["logsource"].get(logsource_key)
    
    def set_logsource_mapping(self, logsource_key: str, mapping: Dict[str, str]) -> None:
        """
        Store logsource mapping in cache.
        
        Args:
            logsource_key: The cache key for the logsource
            mapping: Dict containing the mapping (e.g., {"event_class": "process_activity"})
        """
        self._cache["logsource"][logsource_key] = mapping
        self.save()
    
    def get_detection_field_mapping(self, field_name: str) -> Optional[Dict[str, str]]:
        """
        Get cached detection field mapping.
        
        Cache key is field name only (no context). Field names in Sigma are not ambiguous
        across contexts, enabling maximum cache efficiency.
        
        Args:
            field_name: The source field name (e.g., "EventID", "dst_port")
        
        Returns:
            Dict with mapping info (e.g., {"target_field": "process.cmd_line"}), or None if not cached
        """
        return self._cache["detection_fields"].get(field_name)
    
    def set_detection_field_mapping(self, field_name: str, mapping: Dict[str, str]) -> None:
        """
        Store detection field mapping in cache.
        
        Args:
            field_name: The source field name
            mapping: Dict containing the mapping (e.g., {"target_field": "process.cmd_line"})
        """
        self._cache["detection_fields"][field_name] = mapping
        self.save()
    
    def load(self) -> None:
        """Load cache from disk."""
        try:
            cache_path = Path(self.cache_file)
            if cache_path.exists():
                with open(self.cache_file, 'r') as f:
                    loaded_cache = json.load(f)
                    # Ensure the loaded cache has the correct structure
                    if "logsource" in loaded_cache and "detection_fields" in loaded_cache:
                        self._cache = loaded_cache
                    else:
                        print(f"Warning: Cache file {self.cache_file} has incorrect structure. Starting fresh.")
                        self._cache = {
                            "logsource": {},
                            "detection_fields": {}
                        }
        except FileNotFoundError:
            # Initialize with default structure
            self._cache = {
                "logsource": {},
                "detection_fields": {}
            }
        except json.JSONDecodeError:
            print(f"Warning: Cache file {self.cache_file} is corrupted. Starting fresh.")
            self._cache = {
                "logsource": {},
                "detection_fields": {}
            }
    
    def save(self) -> None:
        """Save cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save cache to {self.cache_file}: {e}")
    
    def clear(self, mapping_type: Optional[MappingType] = None) -> None:
        """
        Clear cached mappings.
        
        Args:
            mapping_type: If specified, only clear that type. If None, clear all.
        """
        if mapping_type == MappingType.LOGSOURCE:
            self._cache["logsource"] = {}
        elif mapping_type == MappingType.DETECTION_FIELD:
            self._cache["detection_fields"] = {}
        else:
            # Clear all
            self._cache = {
                "logsource": {},
                "detection_fields": {}
            }
        self.save()
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "logsource_mappings": len(self._cache["logsource"]),
            "detection_field_mappings": len(self._cache["detection_fields"])
        }
    