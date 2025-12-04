"""
OCSF mapping validators for Sigma rules.

Validates that Sigma rules have complete OCSF mappings before conversion to SQL.
"""

from typing import List
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue, SigmaValidationIssueSeverity
from fieldmapper.ocsf.rules import SigmaRuleOCSFLite, OCSFValidationResult


class MissingTableMappingIssue(SigmaValidationIssue):
    """Rule has no valid OCSF table mapping."""
    
    description = "Rule has no valid OCSF table mapping"
    severity = SigmaValidationIssueSeverity.LOW
    
    def __init__(self, rules: List[SigmaRule]):
        super().__init__(rules)
        self.table_value = None
        # Get the actual table value if available
        if rules and hasattr(rules[0], 'custom_attributes'):
            self.table_value = rules[0].custom_attributes.get('table')
    
    def __str__(self):
        rule_ids = ", ".join(str(r.id) or r.title or "Unknown" for r in self.rules)
        if self.table_value:
            return (
                f"{self.description}: {rule_ids}. "
                f"Table attribute is '{self.table_value}'. "
            )
        return (
            f"{self.description}: {rule_ids}. "
            f"No table attribute found. Ensure the rule is mapped by AI ocsf_mappings-> event_class"
        )


class UnmappedFieldsIssue(SigmaValidationIssue):
    """Rule has unmapped detection fields."""
    
    description = "Rule has unmapped detection fields"
    severity = SigmaValidationIssueSeverity.LOW
    
    def __init__(self, rules: List[SigmaRule], unmapped_fields: List[str]):
        super().__init__(rules)
        self.unmapped_fields = unmapped_fields
    
    def __str__(self):
        rule_ids = ", ".join(str(r.id) or r.title or "Unknown" for r in self.rules)
        field_list = ", ".join(f"'{f}'" for f in self.unmapped_fields)
        return (
            f"{self.description}: {rule_ids}. "
            f"Unmapped fields: {field_list}. "
            f"Ensure all fields are mapped in ocsf_mappings-> detection_fields"
        )


class OCSFTableMappingValidator(SigmaRuleValidator):
    """Validate that rule has a valid OCSF table mapping."""
    
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        """Check if rule has a valid OCSF table mapping."""
        if isinstance(rule, SigmaCorrelationRule):
            return []
        
        # Convert to OCSFLite if not already
        if not isinstance(rule, SigmaRuleOCSFLite):
            ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule_with_ocsf_mapping(rule)
            if not ocsf_rule:
                # No ocsf_mapping, check pipeline attribute
                table = rule.custom_attributes.get('table')
                if not table or table == '<UNMAPPED_TABLE>':
                    return [MissingTableMappingIssue([rule])]
                return []
            rule = ocsf_rule
        
        # validation
        result = rule.validate_ocsf_mappings()
        if not result.has_valid_table:
            return [MissingTableMappingIssue([rule])]
        
        return []


class OCSFFieldMappingValidator(SigmaRuleValidator):
    """Validate that all detection fields have valid OCSF mappings."""
    
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        """Check if all detection fields have valid OCSF mappings."""
        if isinstance(rule, SigmaCorrelationRule):
            return []
        
        # Convert to OCSFLite if not already
        if not isinstance(rule, SigmaRuleOCSFLite):
            ocsf_rule = SigmaRuleOCSFLite.from_sigma_rule_with_ocsf_mapping(rule)
            if not ocsf_rule:
                return []  # No OCSF mapping, skip validation
            rule = ocsf_rule
        
        # validation
        result = rule.validate_ocsf_mappings()
        if result.unmapped_fields:
            return [UnmappedFieldsIssue([rule], result.unmapped_fields)]
        
        return []

