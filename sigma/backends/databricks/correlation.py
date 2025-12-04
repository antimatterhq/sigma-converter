from typing import ClassVar, Dict, Optional, Union

from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaConversionError
from sigma.rule import SigmaRule

from .base import DatabricksBaseBackend
from .lakewatch_rule import Rule


class PartialFormatDict(dict):
    """Dictionary that returns {key} for missing keys instead of raising KeyError."""
    def __missing__(self, key):
        return "{" + key + "}"


class DatabricksBackend(DatabricksBaseBackend):
    """
    Databricks backend correlation support.
    
    Extends DatabricksBaseBackend to add correlation rule conversion for detecting
    patterns across multiple events using Spark SQL window functions.
    
    Correlation Types Supported:
    - event_count: Count events matching rules within a timespan
      Example: "5 failed logins within 10 minutes"
    
    Future Support:
    - value_count: Count distinct values of a field within timespan
    - temporal: Detect event sequences without specific ordering
    - temporal_ordered: Detect event sequences in specific order
    
    Generated SQL uses:
    - Common Table Expressions (WITH ... AS)
    - Window functions (COUNT(*) OVER)
    - PARTITION BY for grouping
    - RANGE BETWEEN for timespan windowing
    - UNION ALL for multi-rule correlation
    """
    
    # Correlation method mapping
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default method"
    }

    # Query templates by correlation type
    event_count_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "WITH combined_events AS ({search}), event_counts AS ({aggregate}) {condition}"
    }

    value_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_correlation_query: ClassVar[Optional[Dict[str, str]]] = None

    # Search phase templates (UNION ALL)
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = (
        "SELECT *, '{ruleid}' as rule_id FROM ({query})"
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " UNION ALL "

    # Aggregation phase templates (window functions)
    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": (
            "SELECT *, COUNT(*) OVER ("
            "PARTITION BY {groupby} ORDER BY {timefield} "
            "RANGE BETWEEN INTERVAL '{timespan}' SECOND PRECEDING AND CURRENT ROW"
            ") as correlation_event_count FROM combined_events"
        )
    }

    value_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = None

    # Condition phase templates (final filter)
    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "SELECT * FROM event_counts WHERE correlation_event_count {op} {count}"
    }

    value_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_condition_expression: ClassVar[Optional[Dict[str, str]]] = None

    # Note: Group-by fields now use escape_and_quote_field() for consistency with WHERE clauses
    # Template variables removed - no longer needed since we use the same quoting logic
    
    def _get_sql_operator_from_correlation_op(self, correlation_op) -> str:
        """
        Get SQL operator symbol from correlation condition operator enum.
        
        Converts correlation condition operator enum (accessed via .name.lower())
        to SQL operator symbol.
        
        Args:
            correlation_op: Correlation condition operator enum
            
        Returns:
            SQL operator symbol (e.g., "=", ">=", ">", "<=", "<")
            
        Raises:
            SigmaConversionError: If operator is not supported
        """
        # Get the lowercase name of the correlation operator enum
        op_name = correlation_op.name.lower()
        
        if op_name not in self.operator_mapping:
            raise SigmaConversionError(
                f"Condition operator '{op_name}' is not supported. "
                f"Supported operators: {', '.join(self.operator_mapping.keys())}"
            )
        
        return self.operator_mapping[op_name]
    
    def convert_correlation_aggregation_groupby_from_template(
        self, groupby_fields: list, method: str
    ) -> str:
        """
        Convert list of OCSF field names to comma-separated GROUP BY expression.
        
        Args:
            groupby_fields: List of OCSF field names (after pipeline transformation)
            method: Correlation method (currently unused, kept for future extensibility)
        
        Returns:
            Comma-separated field list with consistent quoting
        """
        if not groupby_fields:
            raise ValueError("Group-by fields cannot be empty for correlation rules")
        
        # Use the same quoting logic as WHERE clauses for consistency
        formatted_fields = [
            self.escape_and_quote_field(field)
            for field in groupby_fields
        ]
        
        # Join with comma separator
        return ", ".join(formatted_fields)
    
    def convert_correlation_search(self, rule: SigmaCorrelationRule) -> str:
        """
        Generate UNION ALL of referenced rule queries with rule_id tracking.
        
        For each referenced Sigma rule:
        1. Get the converted query from the rule and finalize it
        2. Wrap with SELECT *, 'rule_id' as rule_id FROM (query)
        3. Join all with UNION ALL
        
        Args:
            rule: The correlation rule containing referenced rules
        
        Returns:
            Combined SQL string with UNION ALL queries
        """
        queries = []
        
        for rule_reference in rule.rules:
            # Get the sigma rule from the reference
            sigma_rule = rule_reference.rule
            
            # Get the conversion states for this rule
            states = sigma_rule.get_conversion_states()
            
            # Get the converted queries for this rule (usually just one)
            rule_queries = sigma_rule.get_conversion_result()
            
            # For each query, finalize it and wrap with rule_id tracking
            for idx, query in enumerate(rule_queries):
                # Finalize the query to get the full SELECT * FROM table WHERE ...
                state = states[idx] if idx < len(states) else states[0]
                finalized_query = super().finalize_query_default(sigma_rule, query, idx, state)
                
                # Use rule name or ID for tracking
                rule_id = sigma_rule.name or str(sigma_rule.id)
                
                # Format the query expression with rule_id
                wrapped_query = self.correlation_search_multi_rule_query_expression.format(
                    ruleid=rule_id,
                    query=finalized_query
                )
                queries.append(wrapped_query)
        
        # Join all queries with UNION ALL
        return self.correlation_search_multi_rule_query_expression_joiner.join(queries)
    
    def convert_correlation_aggregation_from_template(
        self, rule: SigmaCorrelationRule, correlation_type: str,
        method: str, search: str
    ) -> str:
        """
        Generate window function aggregation expression.
        
        Uses templates from event_count_aggregation_expression, etc.
        Substitutes:
        - {groupby}: Result of convert_correlation_aggregation_groupby_from_template()
        - {timefield}: self.time_column
        - {timespan}: rule.timespan.seconds
        
        Args:
            rule: Correlation rule with group-by and timespan
            correlation_type: "event_count", "value_count", etc.
            method: Correlation method ("default")
            search: Search phase SQL (not used in aggregation, but passed through)
        
        Returns:
            SQL aggregation expression with window function
        
        Raises:
            NotImplementedError: If correlation_type not supported
            SigmaConversionError: If method not found in templates
        """
        # Get aggregation template for this correlation type
        templates = getattr(self, f"{correlation_type}_aggregation_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        
        if method not in templates:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported for correlation type '{correlation_type}'."
            )
        
        template = templates[method]
        
        # Generate group-by fields expression
        groupby = self.convert_correlation_aggregation_groupby_from_template(
            rule.group_by, method
        )
        
        # Format the aggregation expression
        return template.format(
            groupby=groupby,
            timefield=self.time_column,
            timespan=rule.timespan.seconds
        )
    
    def convert_correlation_condition_from_template(
        self, condition, rules, correlation_type: str, method: str
    ) -> str:
        """
        Generate final WHERE filter based on correlation condition.
        
        Maps condition operator (gte, gt, eq, etc.) to SQL operator (>=, >, =)
        
        Args:
            condition: Correlation condition object with .op and .count/.value
            rules: Referenced rules (not currently used)
            correlation_type: "event_count", "value_count", etc.
            method: Correlation method
        
        Returns:
            SQL condition expression (SELECT * FROM ... WHERE ...)
        
        Raises:
            NotImplementedError: If correlation_type not supported
            SigmaConversionError: If method not found or operator not mapped
        """
        # Get condition template for this correlation type
        templates = getattr(self, f"{correlation_type}_condition_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        
        if method not in templates:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported for correlation type '{correlation_type}'."
            )
        
        template = templates[method]

        sql_operator = self._get_sql_operator_from_correlation_op(condition.op)
        
        # Format the condition expression
        return template.format(
            op=sql_operator,
            count=condition.count
        )
    
    def convert_correlation_rule_from_template(
        self, rule: SigmaCorrelationRule, correlation_type: str, method: str
    ) -> list[str]:
        """
        Main entry point for correlation rule conversion.
        
        Orchestrates three phases:
        1. Search: Generate UNION ALL of rule queries
        2. Aggregation: Add window function for counting
        3. Condition: Add final filter
        
        Args:
            rule: Correlation rule to convert
            correlation_type: Type of correlation ("event_count", etc.)
            method: Correlation method ("default")
        
        Returns:
            List containing single SQL query string
        
        Raises:
            NotImplementedError: If correlation_type not supported
            SigmaConversionError: If method not found in templates
        """
        # Get the query template for this correlation type
        template_attr = f"{correlation_type}_correlation_query"
        template_dict = getattr(self, template_attr, None)
        
        if template_dict is None:
            raise NotImplementedError(
                f"Correlation rule type '{correlation_type}' is not supported by backend."
            )
        
        if method not in template_dict:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported by backend for correlation type '{correlation_type}'."
            )
        
        template = template_dict[method]
        
        # Phase 1: Generate search expression (UNION ALL of rule queries)
        search = self.convert_correlation_search(rule)
        
        # Phase 2: Generate aggregation expression (window function)
        aggregate = self.convert_correlation_aggregation_from_template(
            rule, correlation_type, method, search
        )
        
        # Phase 3: Generate condition expression (final filter)
        condition = self.convert_correlation_condition_from_template(
            rule.condition, rule.rules, correlation_type, method
        )
        
        # Format the complete query using PartialFormatDict
        # (allows missing placeholders to remain as {placeholder})
        query = template.format_map(
            PartialFormatDict(
                timefield=self.time_column,
                search=search,
                aggregate=aggregate,
                condition=condition,
            )
        )
        
        return [query]
    
    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Override to handle correlation rules differently from single-event rules.
        
        Correlation rules are already finalized in convert_correlation_rule_from_template(),
        so we just return them as-is. Single-event rules delegate to parent class.
        
        Args:
            rule: SigmaRule or SigmaCorrelationRule
            query: Query string
            index: Query index
            state: Conversion state
        
        Returns:
            Finalized query string
        """
        if isinstance(rule, SigmaCorrelationRule):
            return query  # Already complete
        
        return super().finalize_query_default(rule, query, index, state)
    
    def finalize_query_lakewatch(
        self, rule: Union[SigmaRule, SigmaCorrelationRule], query: str,
        index: int, state: ConversionState
    ) -> str:
        """
        Override to handle correlation rules for lakewatch format.
        
        Correlation rules are already complete SQL from convert_correlation_rule_from_template().
        Non-correlation rules are delegated to parent class.
        
        Args:
            rule: SigmaRule or SigmaCorrelationRule
            query: Query string (complete SQL for correlation, WHERE clause for non-correlation)
            index: Query index
            state: Conversion state
            
        Returns:
            JSON string representing the LakeWatch rule
        """
        if isinstance(rule, SigmaCorrelationRule):
            # Correlation rules already have complete SQL
            # Build and return LakeWatch rule as JSON
            return Rule.from_sigma_rule(rule, query, is_correlation=True).to_json()
        
        # Non-correlation rules: delegate to parent
        return super().finalize_query_lakewatch(rule, query, index, state)

