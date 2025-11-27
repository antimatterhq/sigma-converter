"""
Custom condition class for Sigma rule processing pipelines.

This module provides RuleIDCondition for per-rule matching based on unique rule IDs,
enabling precise rule identification beyond standard logsource conditions.
"""

from dataclasses import dataclass
from typing import Union

from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import RuleProcessingCondition


@dataclass
class RuleIDCondition(RuleProcessingCondition):
    """
    Matches a Sigma rule by its unique ID (UUID).
    
    This condition allows you to target specific rules in processing pipelines,
    which is useful when multiple rules share the same logsource but require
    different transformations or attributes.
    
    Args:
        rule_id: The UUID string of the rule to match (e.g., "abc-123-def-456")
    
    Example:
        >>> from sigma.processing.conditions.custom import RuleIDCondition
        >>> from sigma.processing.transformations import SetCustomAttributeTransformation
        >>> from sigma.processing.pipeline import ProcessingItem
        >>> 
        >>> # Set a custom attribute for a specific rule
        >>> item = ProcessingItem(
        ...     identifier="specific_rule_override",
        ...     transformation=SetCustomAttributeTransformation(
        ...         attribute="table",
        ...         value="file_activity"
        ...     ),
        ...     rule_conditions=[RuleIDCondition(
        ...         rule_id="48d91a3a-2363-43ba-a456-ca71ac3da5c2"
        ...     )]
        ... )
    """
    
    rule_id: str
    
    def match(
        self,
        pipeline,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        """
        Match condition on Sigma rule by ID.
        
        Args:
            pipeline: The processing pipeline (not used but required by interface)
            rule: The Sigma rule to check
            
        Returns:
            True if the rule ID matches, False otherwise
        """
        if isinstance(rule, SigmaRule):
            return str(rule.id) == self.rule_id if rule.id else False
        elif isinstance(rule, SigmaCorrelationRule):
            # For correlation rules, check if any of the referenced rules match
            for ref in rule.rules:
                if hasattr(ref, "rule") and isinstance(ref.rule, SigmaRule):
                    if self.match(pipeline, ref.rule):
                        return True
            return False
