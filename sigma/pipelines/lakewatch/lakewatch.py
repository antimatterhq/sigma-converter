from sigma.processing.transformations import (
    FieldMappingTransformation, SetCustomAttributeTransformation
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.pipelines.base import Pipeline

from fieldmapper.ocsf.rules import SigmaRuleOCSFLite
from sigma.pipelines.lakewatch.custom_conditions import RuleIDCondition

# Get the source & target field mappings
lakewatch_field_mapping = SigmaRuleOCSFLite.build_field_mapping_dict()

# Get the table mappings for the pipeline
# This is a tuple of (logsource_mapping, conflicted_rule_mapping)
# logsource_mapping is used for non conflicting sources; a rule is considered conflicted if it has a different table 
# than the others with the same logsource. Conflicted rules are assigned a table using the RuleIDCondition
# and therefore one-to-one mapping (rule -> table). 
# This is the only way to ensure 100% accuracy in table assignment, for OCSF IMHO.
lakewatch_logsource_mapping, lakewatch_conflicted_rules = \
    SigmaRuleOCSFLite.build_table_mappings()


@Pipeline
def lakewatch_pipeline() -> ProcessingPipeline:
    """
    Lakewatch processing pipeline for converting Sigma rules to OCSF-compliant queries.
    
    This pipeline performs:
    1. Field mapping: Maps Sigma field names to OCSF field names
    2. Table assignment: Sets the OCSF table (event class):
       - LogsourceCondition for non-conflicted logsources (~70% of rules)
       - RuleIDCondition for conflicted rules (~30% of rules)
    
    """
    items = [
        # Step 1: Apply field mappings
        ProcessingItem(
            identifier="lakewatch_field_mapping",
            transformation=FieldMappingTransformation(mapping=lakewatch_field_mapping)
        ),
    ]
    
    # Step 2a: Apply table assignments for non-conflicted logsources
    # These logsources map unambiguously to a single OCSF table
    for (category, product, service), table_name in lakewatch_logsource_mapping.items():
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
    
    # Step 2b: Apply table assignments for conflicted rules
    # These rules share a logsource with other rules that map to different tables
    # so we need per-rule precision using RuleIDCondition
    for rule_id, table_name in lakewatch_conflicted_rules.items():
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
    
    return ProcessingPipeline(
        name="Lakewatch pipeline",
        priority=20,
        items=items
    )