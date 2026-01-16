from sigma.processing.transformations import (
    FieldMappingTransformation, SetCustomAttributeTransformation, AddConditionTransformation
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.pipelines.base import Pipeline

from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
from sigma.pipelines.lakewatch.custom_conditions import RuleIDCondition

# Get all pipeline mappings (field mappings, table assignments, activity_id) in a single pass
# This includes:
# - logsource_field_mappings: for Sigma field -> OCSF field mapping (FieldMappingTransformation) for non-conflicted logsources
# - conflicted_rule_field_mappings: for Sigma field -> OCSF field mapping (FieldMappingTransformation) for conflicted rules
# - logsource_mappings: for non-conflicting logsources (LogsourceCondition)
# - conflicted_rule_mappings: for rules needing per-rule table assignment (RuleIDCondition)
# - activity_id_mappings: for rules with valid activity_id to add to WHERE clause
lakewatch_mappings = SigmaRuleOCSFLite.build_pipeline_mappings()


@Pipeline
def lakewatch_pipeline() -> ProcessingPipeline:
    """
    Lakewatch processing pipeline for converting Sigma rules to OCSF-compliant queries.
    
    This pipeline performs:
    1. Static configuration: Sets time_column, catalog, schema attributes for all rules
    2. Field mapping: Maps Sigma field names to OCSF field names
    3. Table assignment: Sets the OCSF table (event class):
       - LogsourceCondition for non-conflicted logsources (~70% of rules)
       - RuleIDCondition for conflicted rules (~30% of rules)
    4. Activity ID injection: Adds activity_id conditions to WHERE clause for query efficiency
    
    """
    items = [
        # Step 1: Set static configuration attributes for all rules
        ProcessingItem(
            identifier="set_time_column",
            transformation=SetCustomAttributeTransformation(
                attribute="time_column",
                value="time"
            )
        ),
        ProcessingItem(
            identifier="set_catalog",
            transformation=SetCustomAttributeTransformation(
                attribute="catalog",
                value="lakewatch"
            )
        ),
        ProcessingItem(
            identifier="set_schema",
            transformation=SetCustomAttributeTransformation(
                attribute="schema",
                value="gold"
            )
        ),
    ]
    
    # Step 2a: Apply field mappings for non-conflicted logsources
    # These use the same LogsourceCondition as table assignments
    for (category, product, service), table_name in lakewatch_mappings.logsource_mappings.items():
        if (category, product, service) in lakewatch_mappings.logsource_field_mappings:
            field_mapping = lakewatch_mappings.logsource_field_mappings[(category, product, service)]
            # Create a safe identifier from logsource fields
            id_parts = []
            if category:
                id_parts.append(f"cat_{category.replace(' ', '_')}")
            if product:
                id_parts.append(f"prod_{product.replace(' ', '_')}")
            if service:
                id_parts.append(f"svc_{service.replace(' ', '_')}")
            identifier = "field_mapping_ls_" + "_".join(id_parts) if id_parts else "field_mapping_ls_default"
            
            items.append(
                ProcessingItem(
                    identifier=identifier,
                    transformation=FieldMappingTransformation(mapping=field_mapping),
                    rule_conditions=[LogsourceCondition(
                        category=category,
                        product=product,
                        service=service
                    )]
                )
            )
    
    # Step 2b: Apply field mappings for conflicted rules
    # These use the same RuleIDCondition as table assignments
    for rule_id, table_name in lakewatch_mappings.conflicted_rule_mappings.items():
        if rule_id in lakewatch_mappings.conflicted_rule_field_mappings:
            field_mapping = lakewatch_mappings.conflicted_rule_field_mappings[rule_id]
            items.append(
                ProcessingItem(
                    identifier=f"field_mapping_rule_{rule_id}",
                    transformation=FieldMappingTransformation(mapping=field_mapping),
                    rule_conditions=[RuleIDCondition(rule_id=rule_id)]
                )
            )

    # Step 2c: Attach field type mappings for non-conflicted logsources
    for (category, product, service), table_name in lakewatch_mappings.logsource_mappings.items():
        if (category, product, service) in lakewatch_mappings.logsource_field_type_mappings:
            field_types = lakewatch_mappings.logsource_field_type_mappings[(category, product, service)]
            # Create a safe identifier from logsource fields
            id_parts = []
            if category:
                id_parts.append(f"cat_{category.replace(' ', '_')}")
            if product:
                id_parts.append(f"prod_{product.replace(' ', '_')}")
            if service:
                id_parts.append(f"svc_{service.replace(' ', '_')}")
            identifier = "field_types_ls_" + "_".join(id_parts) if id_parts else "field_types_ls_default"

            items.append(
                ProcessingItem(
                    identifier=identifier,
                    transformation=SetCustomAttributeTransformation(
                        attribute="field_types",
                        value=field_types
                    ),
                    rule_conditions=[LogsourceCondition(
                        category=category,
                        product=product,
                        service=service
                    )]
                )
            )

    # Step 2d: Attach field type mappings for conflicted rules
    for rule_id, table_name in lakewatch_mappings.conflicted_rule_mappings.items():
        if rule_id in lakewatch_mappings.conflicted_rule_field_type_mappings:
            field_types = lakewatch_mappings.conflicted_rule_field_type_mappings[rule_id]
            items.append(
                ProcessingItem(
                    identifier=f"field_types_rule_{rule_id}",
                    transformation=SetCustomAttributeTransformation(
                        attribute="field_types",
                        value=field_types
                    ),
                    rule_conditions=[RuleIDCondition(rule_id=rule_id)]
                )
            )

    # Step 2e: Attach parent array info for non-conflicted logsources
    for (category, product, service), table_name in lakewatch_mappings.logsource_mappings.items():
        if (category, product, service) in lakewatch_mappings.logsource_field_parent_mappings:
            parent_info = lakewatch_mappings.logsource_field_parent_mappings[(category, product, service)]
            id_parts = []
            if category:
                id_parts.append(f"cat_{category.replace(' ', '_')}")
            if product:
                id_parts.append(f"prod_{product.replace(' ', '_')}")
            if service:
                id_parts.append(f"svc_{service.replace(' ', '_')}")
            identifier = "field_parent_ls_" + "_".join(id_parts) if id_parts else "field_parent_ls_default"

            items.append(
                ProcessingItem(
                    identifier=identifier,
                    transformation=SetCustomAttributeTransformation(
                        attribute="field_parent_info",
                        value=parent_info
                    ),
                    rule_conditions=[LogsourceCondition(
                        category=category,
                        product=product,
                        service=service
                    )]
                )
            )

    # Step 2f: Attach parent array info for conflicted rules
    for rule_id, table_name in lakewatch_mappings.conflicted_rule_mappings.items():
        if rule_id in lakewatch_mappings.conflicted_rule_field_parent_mappings:
            parent_info = lakewatch_mappings.conflicted_rule_field_parent_mappings[rule_id]
            items.append(
                ProcessingItem(
                    identifier=f"field_parent_rule_{rule_id}",
                    transformation=SetCustomAttributeTransformation(
                        attribute="field_parent_info",
                        value=parent_info
                    ),
                    rule_conditions=[RuleIDCondition(rule_id=rule_id)]
                )
            )
    
    # Step 3a: Apply table assignments for non-conflicted logsources
    # These logsources map unambiguously to a single OCSF table
    for (category, product, service), table_name in lakewatch_mappings.logsource_mappings.items():
        # Create a safe identifier from logsource fields
        id_parts = []
        if category:
            id_parts.append(f"cat_{category.replace(' ', '_')}")
        if product:
            id_parts.append(f"prod_{product.replace(' ', '_')}")
        if service:
            id_parts.append(f"svc_{service.replace(' ', '_')}")
        identifier = "set_table_ls_" + "_".join(id_parts) if id_parts else "set_table_ls_default"
        
        items.append(
            ProcessingItem(
                identifier=identifier,
                transformation=SetCustomAttributeTransformation(
                    attribute="table",
                    value=table_name
                ),
                rule_conditions=[LogsourceCondition(
                    category=category,
                    product=product,
                    service=service
                )]
            )
        )
    
    # Step 3b: Apply table assignments for conflicted rules
    # These rules share a logsource with other rules that map to different tables
    # so we need per-rule precision using RuleIDCondition
    for rule_id, table_name in lakewatch_mappings.conflicted_rule_mappings.items():
        items.append(
            ProcessingItem(
                identifier=f"set_table_rule_{rule_id}",
                transformation=SetCustomAttributeTransformation(
                    attribute="table",
                    value=table_name
                ),
                rule_conditions=[RuleIDCondition(rule_id=rule_id)]
            )
        )
    
    # Step 4: Add activity_id conditions
    for rule_id, activity_id in lakewatch_mappings.activity_id_mappings.items():
        items.append(
            ProcessingItem(
                identifier=f"add_activity_id_{rule_id}",
                transformation=AddConditionTransformation(
                    conditions={"activity_id": activity_id}
                ),
                rule_conditions=[RuleIDCondition(rule_id=rule_id)]
            )
        )
    
    return ProcessingPipeline(
        name="Lakewatch pipeline",
        priority=20,
        items=items
    )