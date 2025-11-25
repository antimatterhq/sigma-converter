"""
OpenAI Mapper

Handles AI-powered mapping of Sigma rules to OCSF Lite using OpenAI's API.
Implements a two-step mapping strategy with intelligent caching.
"""

import json
from typing import Dict, List, Optional
from openai import OpenAI
from pydantic import BaseModel, Field, ConfigDict

from fieldmapper.ocsf.schema_loader import OCSFLiteSchema
from fieldmapper.ocsf.ai_mapper import MappingCache, MappingContext


class EventClassResponse(BaseModel):
    """Structured response for event class mapping."""
    model_config = ConfigDict(extra='forbid')
    event_class: str = Field(description="OCSF event class name or <UNMAPPED>")


class FieldMapping(BaseModel):
    """A single field mapping entry."""
    model_config = ConfigDict(extra='forbid')
    source_field: str = Field(description="Source Sigma field name")
    target_field: str = Field(description="Target OCSF field path or <UNMAPPED>")


class FieldMappingsResponse(BaseModel):
    """Structured response for field mappings."""
    model_config = ConfigDict(extra='forbid')
    mappings: List[FieldMapping] = Field(description="List of field mappings from source to target")


class OpenAIMapper:
    """Handles AI-powered mapping using OpenAI API."""

    DERIVED_FIELDS = ['activity', 'severity', 'status']
    DERIVED_SUFFIXES = ['_uid', '_name']
    
    def __init__(self, schema: OCSFLiteSchema, cache: MappingCache, 
                 api_key: str, model: str = "gpt-4o-2024-08-06",
                 mitre_data_file: str = "fieldmapper/ocsf_data/mitre_attack_data.json",
                 debug_prompts: bool = False,
                 skip_cache_reads: bool = False):
        """
        Initialize the OpenAI mapper.
        
        Args:
            schema: Loaded OCSF Lite schema
            cache: Mapping cache instance
            api_key: OpenAI API key
            model: OpenAI model to use (default: gpt-4o-2024-08-06, required for structured outputs)
            mitre_data_file: Path to MITRE ATT&CK data JSON file
            debug_prompts: If True, display AI prompts for debugging
            skip_cache_reads: If True, skip reading from cache (but still write)
        """
        self.schema = schema
        self.cache = cache
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_retries = 3
        self.debug_prompts = debug_prompts
        self.skip_cache_reads = skip_cache_reads
        self.mitre_data = self._load_mitre_data(mitre_data_file)
    
    def map_to_event_class(self, context: MappingContext) -> str:
        """
        Step 1: Map rule context to OCSF event class.
        
        Cache key: sorted detection field names only (logsource excluded for max efficiency)
        
        Args:
            context: Rule context with logsource, title, description, tags, and fields
            
        Returns:
            Event class name (e.g., "system/process_activity") or "<UNMAPPED>"
        """
        # Generate cache key from field names only
        cache_key = ','.join(sorted(context.detection_field_names))
        
        # Check cache (unless skip flag is set)
        if not self.skip_cache_reads:
            print(f"Checking cache for {cache_key}")
            cached = self.cache.get_logsource_mapping(cache_key)
            if cached:
                return cached.get("event_class")
        else:
            print(f"Skipping cache check for {cache_key}")
        
        # Build prompt (logsource sent as context, not in cache key)
        prompt = self._build_event_class_prompt(context)
        
        # Call OpenAI with retry logic
        for attempt in range(self.max_retries):
            response_data = self._call_openai(prompt, EventClassResponse)
            event_class = response_data['event_class']
            
            # Validate response
            if event_class == "<UNMAPPED>":
                self.cache.set_logsource_mapping(cache_key, {"event_class": event_class})
                break
            
            if event_class in self.schema.get_event_class_names():
                # Valid! Cache and return
                self.cache.set_logsource_mapping(cache_key, {"event_class": event_class})
                return event_class
            
            # Invalid response, retry with stronger prompt
            prompt = self._build_event_class_prompt(context, retry_hint=True)
        
        return "<UNMAPPED>"
    
    def map_detection_fields(self, event_class: str, 
                           detection_fields: List[str]) -> Dict[str, str]:
        """
        Step 2: Map detection fields to OCSF fields.
        
        Cache key: source field name only (no event class context needed)
        Field names in Sigma are not ambiguous across contexts.
        
        Only sends uncached fields to AI in a single batch call.
        
        Args:
            event_class: The OCSF event class determined in step 1
            detection_fields: List of Sigma detection field names
            
        Returns:
            Dict mapping source_field -> target_field_path (or "<UNMAPPED>")
        """
        mappings = {}
        uncached_fields = []
        
        # Check cache for each field (unless skip flag is set)
        if not self.skip_cache_reads:
            for source_field in detection_fields:
                cached = self.cache.get_detection_field_mapping(field_name=source_field)
                
                if cached:
                    mappings[source_field] = cached.get("target_field")
                else:
                    uncached_fields.append(source_field)
        else:
            # Skip cache reads - treat all fields as uncached
            uncached_fields = detection_fields
        
        # Only call AI if there are uncached fields
        if uncached_fields:
            # Single AI call for ALL uncached fields
            new_mappings = self._map_fields_batch(event_class, uncached_fields)
            
            # Cache each new mapping individually
            for field, target in new_mappings.items():
                self.cache.set_detection_field_mapping(
                    field_name=field,
                    mapping={"target_field": target}
                )
            
            mappings.update(new_mappings)
        
        return mappings
    
    def _map_fields_batch(self, event_class: str, 
                         fields: List[str]) -> Dict[str, str]:
        """
        Map multiple fields in a single AI call with retry/validation.
        
        Args:
            event_class: OCSF event class name
            fields: List of Sigma field names to map
            
        Returns:
            Dict mapping source_field -> target_field_path
        """
        available_fields = self.schema.get_fields_for_event_class(event_class)
        
        # Augment with missing fields for specific event classes
        available_fields = self._augment_event_class_fields(event_class, available_fields)
        
        # Filter out derived/computed fields that should never be mapped
        available_fields = self._filter_derived_fields(available_fields)
        
        prompt = self._build_batch_field_mapping_prompt(event_class, fields, available_fields)
        
        for attempt in range(self.max_retries):
            response_data = self._call_openai(prompt, FieldMappingsResponse)
            # Convert list of mappings to dict for backward compatibility
            mappings = {m['source_field']: m['target_field'] for m in response_data['mappings']}
            
            # Validate all mappings are actual fields; and that no hallucinations are present
            all_valid = True
            for source, target in mappings.items():
                if target != "<UNMAPPED>":
                    # Check if field exists in schema OR in our augmented list
                    if target not in available_fields and not self.schema.validate_field(event_class, target):
                        all_valid = False
                        break
            
            if all_valid:
                return mappings
            
            # Invalid, retry with hint
            if attempt < self.max_retries - 1:
                prompt = self._build_batch_field_mapping_prompt(
                    event_class, fields, available_fields, retry_hint=True
                )
        
        # Failed all retries - return unmapped for all
        return {field: "<UNMAPPED>" for field in fields}
    
    def _filter_derived_fields(self, fields: List[str]) -> List[str]:
        """
        Filter out derived/computed OCSF fields that should never be mapped from source data.
        
        These are always top-level fields:
        - Fields ending with _uid (category_uid, class_uid, type_uid, etc.)
        - Fields ending with _name (category_name, activity_name, class_name, etc.)
        - Standalone computed fields: activity, severity, status
        
        Args:
            fields: List of field paths (e.g., ["metadata.product", "category_uid", "actor.user.name"])
            
        Returns:
            Filtered list excluding derived fields
        """
        filtered = []
        
        for field in fields:
            # Skip if field ends with _uid or _name
            if any(field.endswith(suffix) for suffix in OpenAIMapper.DERIVED_SUFFIXES):
                continue
            
            # Skip standalone computed fields (top-level only)
            if field in OpenAIMapper.DERIVED_FIELDS:
                continue
            
            # This field is okay to map
            filtered.append(field)
        
        return filtered
    
    def _augment_event_class_fields(self, event_class: str, fields: List[str]) -> List[str]:
        """
        Add missing fields to specific event classes.
        
        Some event classes are missing important fields in the schema.
        This method dynamically adds them so the AI can map to them.
        
        Args:
            event_class: OCSF event class name
            fields: Current list of fields from schema
            
        Returns:
            Augmented list of fields
        """
        # TODO: remove this once sc-10006 is done.
        augmented = fields.copy()
        
        # Add missing fields for process_activity
        if event_class == 'process_activity':
            # Parent process fields
            parent_process_fields = [
                'process.parent_process.cmd_line',
                'process.parent_process.name',
                'process.parent_process.pid',
                'process.parent_process.uid',
                'process.parent_process.session.created_time',
                'process.parent_process.session.is_remote',
                'process.parent_process.session.issuer',
                'process.parent_process.session.terminal',
                'process.parent_process.session.uid',
                'process.parent_process.session.uid_alt',
                'process.parent_process.session.uuid',
            ]
            
            # File fields (if not already present)
            file_fields = [
                'process.file.name',
                'process.file.path',
                'process.file.parent_folder',
                'process.file.company_name',
                'process.file.ext',
                'process.file.hashes.value',
                'process.file.hashes.algorithm',
            ]
            
            # Add fields that don't already exist
            for field in parent_process_fields + file_fields:
                if field not in augmented:
                    augmented.append(field)
        
        return augmented
    
    def _build_event_class_prompt(self, context: MappingContext, 
                                 retry_hint: bool = False) -> str:
        """Build prompt for event class mapping with dynamic MITRE context."""
        event_classes = self.schema.get_event_class_names()
        mitre_context = self._extract_mitre_context(context.tags)
        
        prompt = f"""You are an expert in mapping Sigma detection rules to OCSF event classes.

Given this Sigma rule context:
- Category: {context.logsource.get('category', 'N/A')}
- Detection Fields: {', '.join(context.detection_field_names) if context.detection_field_names else 'N/A'}
- Product: {context.logsource.get('product', 'N/A')}
- Service: {context.logsource.get('service', 'N/A')}
- Title: {context.title}
- Tags: {', '.join(context.tags) if context.tags else 'N/A'}

{mitre_context if mitre_context else 'MITRE Context: Not available'}

Available OCSF Lite Event Classes:
{chr(10).join(f'  - {ec}' for ec in event_classes)}

CRITICAL: If Category is provided, you MUST use this mapping table:

CATEGORY → EVENT CLASS (MANDATORY):
- process_creation → process_activity
- file_event → file_activity  
- file_change → file_activity
- file_access → file_activity
- file_delete → file_activity
- network_connection → network_activity
- firewall → network_activity
- dns_query → dns_activity
- web → http_activity
- proxy → http_activity

If the Category matches one of the above, return that event class IMMEDIATELY.
Do NOT consider the rule's title, description, or semantic purpose.
The category indicates the LOG SOURCE TYPE, not what the detection is looking for.

Examples:
- Category "process_creation" → ALWAYS process_activity (even if detecting account changes)
- Category "file_event" → ALWAYS file_activity (even if detecting malware)
- Category "network_connection" → ALWAYS network_activity (even if detecting C2)

ONLY if Category is N/A or not in the table above:
1. Check MITRE data components:
   * Process Creation (DC0032) → process_activity
   * File Creation/Modification → file_activity
   * Network Traffic → network_activity or http_activity
   * User Account operations → account_change
   
2. If no MITRE data, use detection fields:
   * Process fields (CommandLine, Image, etc.) → process_activity
   * File fields (TargetFilename, etc.) → file_activity
   * Network fields (DestinationIp, DestinationPort) → network_activity

{self._get_few_shot_examples()}

Which OCSF Lite event class best matches this rule?
Return ONLY the event class name or <UNMAPPED>.
"""
        
        if retry_hint:
            prompt += "\n\nNOTE: Previous response was invalid. Return a valid event class from the list above."
        
        return prompt
    
    def _build_batch_field_mapping_prompt(self, event_class: str, fields: List[str],
                                         available_fields: List[str], retry_hint: bool = False) -> str:
        """Build prompt for mapping multiple fields at once."""

        field_subset = available_fields
        
        # Get few-shot examples
        few_shot_examples = self._get_field_mapping_few_shot_examples()
        
        prompt = f"""Map these Sigma fields to OCSF fields.

Event Class: {event_class}

{few_shot_examples}

Sigma Fields to Map:
{chr(10).join(f'  - {field}' for field in fields)}

Available OCSF fields in {event_class}:
{chr(10).join(f'  - {field}' for field in field_subset)}

IMPORTANT: Return ONLY valid JSON with no additional text or explanation.
Your entire response must be parseable JSON in this exact format:
{{
  "field_name": "ocsf.field.path",
  "another_field": "<UNMAPPED>"
}}

Rules:
- NEVER map to fields ending with _uid (category_uid, class_uid, type_uid, etc.) - these are computed
- NEVER map to fields ending with _name (category_name, activity_name, etc.) - these are derived labels
- NEVER map to standalone fields: activity, severity, status - these are computed from *_id fields
- Use full dot-notation for nested fields (e.g., "actor.process.file.path")
- If no good match exists, use "<UNMAPPED>"
- Follow the patterns shown in the examples above
- Do not include any text before or after the JSON
"""
        
        if retry_hint:
            prompt += "\n\nNOTE: Previous response contained invalid fields. Ensure all field paths exist in the schema above, or use <UNMAPPED>."
        
        return prompt
    
    def _get_few_shot_examples(self) -> str:
        """Few-shot examples showing category priority and MITRE data component reasoning."""
        return """
EXAMPLES:

1. Category + MITRE data components align (CRITICAL - Script Execution):
   Category: process_creation, Product: macos
   MITRE: T1059.002 (AppleScript) - Data Components: [Process Creation (DC0032)]
   Detection: Detection of AppleScript-Based Execution on macOS
   Fields: [Image, CommandLine]
   → process_activity
   
   REASONING: Despite "Script" in the name, AppleScript execution creates PROCESSES.
   DC0032 (Process Creation) confirms this. The script interpreter runs as a process.
   Map to process_activity, NOT script_activity.

2. Category overrides misleading title:
   Category: process_creation, Product: windows
   MITRE: T1059.001 (PowerShell) - Data Components: [Process Creation]
   Title: "PowerShell Script Execution"
   → process_activity
   (Despite "script" in title, process creation takes priority)

3. No category, MITRE guides:
   Category: N/A, Product: zeek
   MITRE: T1071.001 (Web Protocols) - Data Components: [Network Traffic Content]
   Fields: [c-uri, c-useragent]
   → http_activity
   (Network Traffic + http fields → http_activity)

4. Category only (no MITRE):
   Category: file_event, Product: windows
   Fields: [TargetFilename, Image]
   → file_activity
   (Category is clear, no MITRE needed)


IMPORTANT DISTINCTION FOR WINDOWS POWERSHELL:
- A rule that has the field 'ScriptBlockText' should be mapped to the event class 'script_activity' and not 'process_activity'

RULES:
- for cloud based rules (aws, m365 etc) eventSource always maps to metadata.product

"""
    
    def _get_field_mapping_few_shot_examples(self) -> str:
        """Few-shot examples for field mapping across different event classes."""
        return """
FIELD MAPPING EXAMPLES:

1. Windows Process Fields (process_activity):
   Sigma Field → OCSF Field
   # NOTE: Use 'process' not 'actor.process' for the main process being observed
   - CommandLine → process.cmd_line
   - Image → process.name
   - ParentImage → process.parent_process.name
   - User → actor.user.name
   - ParentCommandLine → process.parent_process.cmd_line
   - ProcessId → process.pid
   
2. Network Fields (network_activity):
   Sigma Field → OCSF Field
   # Note: Network fields use various naming conventions across log sources
   - DestinationPort → dst_endpoint.port
   - destination.port → dst_endpoint.port  # Netflow, lowercase with dots
   - DestinationIp → dst_endpoint.ip
   - destination.ip → dst_endpoint.ip  # Netflow variant
   - SourcePort → src_endpoint.port
   - source.port → src_endpoint.port  # Netflow variant
   - SourceIp → src_endpoint.ip
   - source.ip → src_endpoint.ip  # Netflow variant
   - Protocol → connection_info.protocol_name
   - SourceHostname → src_endpoint.hostname
   - DestinationHostname → dst_endpoint.hostname

3. File System Fields (file_activity):
   Sigma Field → OCSF Field
   - TargetFilename → file.path
   - TargetObject → file.path
   - FileName → file.name
   
4. macOS/Linux Fields (process_activity):
   Sigma Field → OCSF Field
   - CommandLine → process.cmd_line
   - exe → process.file.path
   - uid → actor.user.uid
   - gid → actor.user.groups[].uid
   - comm → process.name

5. Windows Fields:
   Sigma Field → OCSF Field
   - EventID → metadata.event_id

6. AWS CloudTrail Fields (api_activity):
   Sigma Field → OCSF Field
   - eventSource → metadata.product
   - eventName → api.operation
   - userIdentity.userName → actor.user.name
   - userIdentity.principalId → actor.user.uid
   - awsRegion → cloud.region
   - sourceIPAddress → src_endpoint.ip

7. Unmappable Fields (use <UNMAPPED>):
   Sigma Field → OCSF Field
   - CustomVendorField → <UNMAPPED>
   - LegacyFieldName → <UNMAPPED>
   - UnsupportedAttribute → <UNMAPPED>

IMPORTANT DISTINCTION for process_activity:
- 'process' = The main process being observed (the target of the event)
  Example: The process that was launched, terminated, or modified
  Use for: CommandLine, Image, ProcessId, CurrentDirectory, etc.
  
- 'actor.process' = The process that performed the action
  Example: A parent process that launched a child process
  Rarely used in field mappings - mostly use 'actor.user' for who initiated it

RULES:
- **CRITICAL for AWS CloudTrail and cloud API logs**: eventSource always maps to metadata.product and eventName maps to api.operation
- Always use full dot-notation for nested fields
- **IMPORTANT for process_activity**: Use 'process.*' for the main process (CommandLine, Image, etc.)
  NOT 'actor.process.*'. The 'actor' object represents WHO initiated the activity.
- Parent process fields use 'process.parent_process.*' prefix
- Actor fields (user/session info) use 'actor.user.*' or 'actor.session.*'
- If no good semantic match exists, use <UNMAPPED>
- Match field semantics, not just names (e.g., Image = file path of executable)
"""
    
    def _call_openai(self, prompt: str, response_model: type[BaseModel]) -> dict:
        """
        Call OpenAI API with structured output guarantee.
        
        Args:
            prompt: The prompt to send
            response_model: Pydantic model defining expected response structure
            
        Returns:
            Parsed response as dictionary
        """
        if self.debug_prompts:
            print("\n" + "="*80)
            print("🔍 DEBUG: AI PROMPT")
            print("="*80)
            print(prompt)
            print("="*80 + "\n")
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": response_model.__name__,
                    "schema": response_model.model_json_schema(),
                    "strict": True
                }
            }
        )
        
        response_content = response.choices[0].message.content
        
        if self.debug_prompts:
            print("\n" + "="*80)
            print("🤖 DEBUG: AI RESPONSE")
            print("="*80)
            print(response_content)
            print("="*80 + "\n")
        
        return json.loads(response_content)
    
    def _extract_mitre_context(self, tags: List[str], 
                              include_fields: Optional[List[str]] = None) -> str:
        """
        Extract relevant MITRE ATT&CK context from rule tags with flexible field selection.
        
        Args:
            tags: List of tags from Sigma rule (e.g., ['attack.execution', 'attack.t1059.002'])
            include_fields: List of fields to include. If None, uses 'standard' preset.
                           Available fields: 'detection_strategies', 'data_components', 
                           'platforms', 'tactic', 'procedure_examples'
            
        Returns:
            Formatted string with MITRE context for prompt, or empty string if no context
        """
        if not self.mitre_data or not tags:
            return ""
        
        # Use standard preset if not specified
        if include_fields is None:
            # Standard: detection strategies, data components, platforms
            include_fields = ['detection_strategies', 'data_components', 'platforms']
        
        # Extract technique IDs from tags
        technique_ids = []
        for tag in tags:
            if tag.startswith('attack.t'):
                # Extract T1059.002 from 'attack.t1059.002'
                # Convert 'attack.t1059.002' -> 'T1059.002'
                tech_id = tag.replace('attack.t', 'T').replace('attack.T', 'T').upper()
                technique_ids.append(tech_id)
        
        if not technique_ids:
            return ""
        
        # Build context string with selected fields
        contexts = []
        for tech_id in technique_ids:
            if tech_id in self.mitre_data:
                data = self.mitre_data[tech_id]
                parts = [f"{tech_id} ({data['name']})"]
                
                # Add detection strategies if requested and available
                if 'detection_strategies' in include_fields and data.get('detection_strategies'):
                    ds_names = [ds['name'] for ds in data['detection_strategies'][:2]]  # Limit to 2
                    parts.append(f"Detection: {'; '.join(ds_names)}")
                
                # Extract data components from analytics log sources (preferred source)
                data_component_added = False
                if 'data_components' in include_fields:
                    # First try to get from analytics log sources (more detailed)
                    for ds in data.get('detection_strategies', []):
                        for analytic in ds.get('analytics', []):
                            log_sources = analytic.get('log_sources', [])
                            if log_sources:
                                # Build data component list with external IDs
                                dc_parts = []
                                for ls in log_sources:
                                    dc_name = ls.get('data_component_name')
                                    dc_id = ls.get('data_component_external_id')
                                    if dc_name:
                                        if dc_id:
                                            dc_parts.append(f"{dc_name} ({dc_id})")
                                        else:
                                            dc_parts.append(dc_name)
                                
                                if dc_parts:
                                    parts.append(f"Data Components: [{', '.join(dc_parts)}]")
                                    data_component_added = True
                                    break  # Only use first analytic's log sources
                        if data_component_added:
                            break  # Only use first detection strategy
                    
                    # Fallback to top-level data_components if no analytics data
                    if not data_component_added and data.get('data_components'):
                        components = ', '.join(data['data_components'])
                        parts.append(f"Data Components: [{components}]")
                
                # Add platforms if requested and available
                if 'platforms' in include_fields and data.get('platforms'):
                    platforms = ', '.join(data['platforms'])
                    parts.append(f"Platforms: {platforms}")
                
                # Add tactic if requested and available
                if 'tactic' in include_fields and data.get('tactic'):
                    parts.append(f"Tactic: {data['tactic']}")
                
                # Add procedure examples if requested and available (limit to 1 for tokens)
                if 'procedure_examples' in include_fields and data.get('procedure_examples'):
                    example = data['procedure_examples'][0]
                    desc = example['description'][:100] + '...' if len(example['description']) > 100 else example['description']
                    parts.append(f"Example: {example['actor']} - {desc}")
                
                contexts.append('  - ' + ' | '.join(parts))
        
        if contexts:
            return "MITRE ATT&CK Context:\n" + "\n".join(contexts)
        return ""
    
    def _load_mitre_data(self, filepath: str) -> Dict:
        """
        Load MITRE ATT&CK technique data from JSON file.
        
        Args:
            filepath: Path to mitre_attack_data.json
            
        Returns:
            Dictionary mapping technique IDs to metadata, or empty dict if not found
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            print(f"✅ Loaded MITRE ATT&CK data: {len(data)} techniques")
            return data
        except FileNotFoundError:
            print(f"⚠️  MITRE data not found: {filepath}")
            print(f"   Run: python fieldmapper/ocsf_data/bin/mitre.py")
            return {}
        except json.JSONDecodeError as e:
            print(f"⚠️  Invalid JSON in MITRE data file: {e}")
            return {}

