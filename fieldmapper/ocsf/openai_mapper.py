"""
OpenAI Mapper

Handles AI-powered mapping of Sigma rules to OCSF Lite using OpenAI's API.
Implements a two-step mapping strategy with intelligent caching.
"""

import json
from typing import Dict, List, Optional, Union
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


class ActivityIdResponse(BaseModel):
    """Structured response for activity_id mapping."""
    model_config = ConfigDict(extra='forbid')
    activity_id: Union[int, str] = Field(description="OCSF activity_id integer from enum, or UNMAPPED if uncertain")


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
    
    def _get_activity_id_enum(self, event_class: str) -> Dict[str, Dict[str, str]]:
        """
        Extract activity_id enum from raw event class JSON file.
        
        Args:
            event_class: OCSF event class name (e.g., "system/process_activity")
            
        Returns:
            Dict mapping activity_id values to their caption and description
            Example: {"1": {"caption": "Launch", "description": "..."}, ...}
        """
        from pathlib import Path
        
        # Search for base name in all subdirectories
        events_dir = Path("fieldmapper/ocsf_data/_ocsf_lite") / "events"
        json_path = None
       
        for subdir in events_dir.glob("*/"):
            if subdir.is_dir():
                candidate = subdir / f"{event_class}.json"
                if candidate.exists():
                    json_path = candidate
                    break
        
        # Check if file was found
        if json_path is None:
            return {}
        
        try:
            with open(json_path) as f:
                event_data = json.load(f)
            
            attributes = event_data.get("attributes", {})
            activity_id_attr = attributes.get("activity_id", {})
            return activity_id_attr.get("enum", {})
        except (json.JSONDecodeError, IOError):
            return {}
    
    def map_detection_fields(self, event_class: str, 
                           detection_fields: List[str]) -> Dict[str, str]:
        """
        Step 2: Map detection fields to OCSF fields.
        
        Cache key: event_class + field name for context-aware caching.
        The same field can map differently across event classes (e.g., Image in process_activity vs file_activity).
        
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
                cached = self.cache.get_detection_field_mapping(event_class=event_class, field_name=source_field)
                
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
                    event_class=event_class,
                    field_name=field,
                    mapping={"target_field": target}
                )
            
            mappings.update(new_mappings)
        
        return mappings
    
    # TODO: Implement the activity_id mapping here. 
    def map_activity_id(self, event_class: str, context: MappingContext) -> Optional[int]:
        """
        Map Sigma rule to OCSF activity_id using AI.
        
        This is Step 3 of the mapping process - determining the specific activity_id
        for an already-mapped event class based on the Sigma rule's context.
        
        Args:
            event_class: Already-determined OCSF event class (e.g., "system/process_activity")
            context: Sigma rule context (title, description, logsource, tags)
            
        Returns:
            activity_id integer, or None if event class has no activity_id enum,
            or -1 is returned by AI to indicate UNMAPPED
        """
        # Get available activity IDs for this event class
        activity_enum = self._get_activity_id_enum(event_class)
        
        if not activity_enum:
            # Event class doesn't have activity_id field
            print(f"NO ACTIVITY ID ENUM FOR {event_class}")
            return None
        
        # Build prompt with context and available activity IDs
        prompt = self._build_activity_id_prompt(event_class, context, activity_enum)
        
        # Call AI with structured output
        try:
            response_data = self._call_openai(prompt, ActivityIdResponse)
            activity_id = response_data['activity_id']
            # Handle UNMAPPED string response
            if activity_id == "UNMAPPED":
                return None
            
            # Validate activity_id exists in enum
            if isinstance(activity_id, int) and str(activity_id) in activity_enum:
                return activity_id
            else:
                # AI returned invalid activity_id, treat as unmapped
                return None
                
        except Exception:
            # On error, treat as unmapped
            return None

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
    
    def _build_activity_id_prompt(self, event_class: str, context: MappingContext, 
                                   activity_enum: Dict[str, Dict[str, str]]) -> str:
        """Build prompt for activity_id mapping."""
        
        # Format available activity IDs
        activity_options = []
        for id_val, details in sorted(activity_enum.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 99):
            caption = details.get("caption", "")
            description = details.get("description", "")
            if description and description != caption:
                activity_options.append(f"  {id_val}: {caption} - {description}")
            else:
                activity_options.append(f"  {id_val}: {caption}")
        
        activities_text = "\n".join(activity_options)
        
        # Get all logsource fields
        category = context._logsource_category or "N/A"
        product = context._logsource_product or "N/A"
        service = context._logsource_service or "N/A"
        
        prompt = f"""You are selecting the correct OCSF activity_id for an already-mapped event class.

Rule Context:
- Title: {context.title}
- Description: {context.description or 'N/A'}
- Logsource Category: {category}
- Logsource Product: {product}
- Logsource Service: {service}
- Tags: {', '.join(context.tags) if context.tags else 'N/A'}

Already-Selected Event Class: {event_class}

Available Activity IDs (select ONE from this list):
{activities_text}

Task: Select the most appropriate activity_id based on STRONG EVIDENCE from the rule's context.

CRITICAL GUIDELINES:
1. Logsource category is the PRIMARY indicator:
   - "process_creation" → activity_id 1 (Launch/Create)
   - "process_termination" → activity_id 2 (Terminate)
   - "file_delete" → activity_id 4 (Delete)
   - "file_change" or "file_event" → activity_id 3 (Update/Modify)
   
2. If category doesn't clearly map, examine product/service and title/description

3. **IMPORTANT**: If you CANNOT determine the activity_id with HIGH CONFIDENCE, you MUST return "UNMAPPED"
   - Not enough evidence in the context? → UNMAPPED
   - Rule could match multiple activities? → UNMAPPED
   - Activity type is ambiguous? → UNMAPPED
   
4. Only use activity_id 0 (Unknown) if it exists in the enum AND the source data itself indicates unknown activity

5. Do NOT guess or infer without strong evidence

Return the activity_id as an integer OR the string "UNMAPPED"."""
        
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
SEMANTIC MAPPING RULES - Understanding Subject vs Actor:

The event_class name identifies the SUBJECT of the event (what the event is about):
- file_activity → a FILE is being acted upon
- process_activity → a PROCESS is being created/terminated/modified  
- network_activity → a NETWORK CONNECTION is being established
- http_activity → an HTTP REQUEST is being made

Key Objects and When to Use Them:

1. SUBJECT objects (the thing being observed):
   - 'file.*' in file_activity → the file being created/deleted/modified
   - 'process.*' in process_activity → the process being launched/terminated
   - 'src_endpoint.*' and 'dst_endpoint.*' in network_activity → the connection endpoints

2. ACTOR objects (who/what performed the action):
   - 'actor.user.*' → the user account that initiated the activity
   - 'actor.process.*' → the process that performed the activity (when not the subject)

Context-Aware Field Mapping Strategy:

A. Fields like 'Image', 'CommandLine', 'ProcessId':
   - In process_activity: These describe the SUBJECT process → map to 'process.*'
     Example: Image → process.name
   
   - In file_activity: These describe the ACTOR process (that touched the file) → map to 'actor.process.*'
     Example: Image → actor.process.name
   
   - In network_activity: These describe the ACTOR process (that made the connection) → map to 'actor.process.*'
     Example: Image → actor.process.name

B. Fields like 'TargetFilename', 'FileName':
   - In file_activity: These describe the SUBJECT file → map to 'file.*'
     Example: TargetFilename → file.path

C. Fields like 'User', 'Username':
   - In any event_class: The user who initiated → 'actor.user.name'
   - Exception: 'TargetUsername' in account_change → the account being changed

Key Insight: Ask yourself "Is this field describing the SUBJECT of the event or the ACTOR performing it?"

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

IMPORTANT DISTINCTION - Subject vs Actor in Different Event Classes:
- In process_activity:
  'process' = The SUBJECT process being observed (launched/terminated/modified)
  Use for: CommandLine, Image, ProcessId, CurrentDirectory, etc.
  
- In file_activity, network_activity, etc:
  'actor.process' = The process that PERFORMED the action (not the subject)
  Use for: Image, CommandLine when they describe the process that acted on a file/made a connection
  
- 'actor.user' = The user account that initiated any activity (used in all event classes)

RULES:
- **CRITICAL for AWS CloudTrail and cloud API logs**: eventSource always maps to metadata.product and eventName maps to api.operation
- Always use full dot-notation for nested fields
- **Apply the Subject vs Actor pattern**: Determine if the field describes the subject of the event or the actor performing it
- In process_activity: Process fields (Image, CommandLine) → 'process.*' (the subject)
- In other event classes: Process fields (Image, CommandLine) → 'actor.process.*' (the actor)
- Parent process fields always use 'process.parent_process.*' prefix (in process_activity)
- User fields always use 'actor.user.*' (in all event classes)
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

