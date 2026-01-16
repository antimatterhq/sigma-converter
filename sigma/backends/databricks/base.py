import re
import json
import warnings
from typing import Pattern, Union, ClassVar, Tuple, List, Dict, Any, Optional, Set

from sigma.conditions import ConditionItem, ConditionOR, ConditionAND, ConditionNOT, \
    ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaString, SigmaCasedString, SigmaNumber, SigmaBool
from sigma.types import SpecialChars

from sigma.validation import SigmaValidator
from sigma.validators.ocsf import ocsf_validators
from sigma.collection import SigmaCollection

from .lakewatch_rule import Rule
from .sql_validator import verify_databricks_sql


class DatabricksBaseBackend(TextQueryBackend):
    """
    Databricks base backend for PySigma.
    
    Converts Sigma detection rules into Databricks SQL queries.
    
    Features:
    - Case-sensitive and case-insensitive string matching
    - Field-to-field comparisons
    - Field existence checks
    - OR-to-IN optimization for multiple value matches
    - IPv4 CIDR subnet matching (IPs stored as strings)
        
    Current limitations:
    - Always uses SELECT * (rule.fields not yet implemented)
    - Fields key in sigma not ported; due to Sigma bug/feature missing those in pipeline mapping
    - Unbound values (keywords detection) are not supported
    
    Future enhancements:
    - Implement rule.fields with per-rule OCSF field mappings
    - IPv6 CIDR support needed.
    """
    
    name: ClassVar[str] = "databricks"
    formats: Dict[str, str] = {
        "default": "Databricks SQL queries",
        "lakewatch": "LakeWatch Detection Rule JSON"
    }
    default_format: ClassVar[str] = "lakewatch"

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        time_column: str = "time",
        catalog: str = None,
        schema: str = None,
        time_filter: str = "24 HOUR",
        **backend_options: Dict,
    ):
        super().__init__(
            processing_pipeline=processing_pipeline,
            collect_errors=collect_errors,
            **backend_options,
        )
        self.time_column = time_column
        self.catalog = catalog
        self.schema = schema
        self.time_filter = time_filter

        # Track rule-specific custom attributes for type-aware conversions
        self._current_rule_custom_attributes: Optional[Dict[str, Any]] = None

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None) -> List[Any]:
        """Capture per-rule custom attributes for type-aware conversions."""
        previous = self._current_rule_custom_attributes
        try:
            self._current_rule_custom_attributes = rule.custom_attributes
            return super().convert_rule(rule, output_format)
        finally:
            self._current_rule_custom_attributes = previous

    def convert_correlation_rule(self, rule, output_format: Optional[str] = None, method: Optional[str] = None) -> List[Any]:
        """Capture correlation rule custom attributes for type-aware conversions."""
        previous = self._current_rule_custom_attributes
        try:
            self._current_rule_custom_attributes = getattr(rule, "custom_attributes", {})
            return super().convert_correlation_rule(rule, output_format, method)
        finally:
            self._current_rule_custom_attributes = previous

    def convert(self, rule, output_format: Optional[str] = None, correlation_method: Optional[str] = None, **kwargs):
        """
        Convert rule(s) to queries.
        
        Validates rules have:
        - Valid table mapping (not <UNMAPPED_TABLE>)
        - All detection fields with valid OCSF mappings
        
        Skips invalid rules with warnings.
        
        Args:
            rule: SigmaRule, SigmaCorrelationRule, or SigmaCollection
            output_format: Optional output format override
            correlation_method: Optional correlation method (passed to parent)
            **kwargs: Additional arguments passed through to parent
            
        Returns:
            List of SQL query strings for valid rules
        """
        
        # Create validator with OCSF validators
        validator = SigmaValidator(ocsf_validators.values())
        
        # Handle collection vs single rule
        if isinstance(rule, SigmaCollection):
            rules = rule.rules
        else:
            rules = [rule]
        
        # Validate rules
        issues = validator.validate_rules(iter(rules))
        
        if issues:
            
            # Get affected rule IDs
            affected_rule_ids = set()
            for issue in issues:
                for r in issue.rules:
                    affected_rule_ids.add(str(r.id) if r.id else None)
            
            # Filter out invalid rules
            valid_rules = [r for r in rules if str(r.id) not in affected_rule_ids]
            
            if not valid_rules:
                summary = f"# Validation Summary\n\nAll {len(rules)} rule(s) skipped due to validation failures.\nReview warnings above for details."
                return [summary]
            
            # Convert only valid rules
            if isinstance(rule, SigmaCollection):
                from sigma.collection import SigmaCollection as SC
                validated_collection = SC(rules=valid_rules)
                return super().convert(validated_collection, output_format, correlation_method, **kwargs)
            else:
                # Single rule - if it was invalid, we return empty
                return super().convert(valid_rules[0], output_format, correlation_method, **kwargs)
        
        # All valid, proceed normally
        return super().convert(rule, output_format, correlation_method, **kwargs)

    requires_pipeline: bool = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT, ConditionAND, ConditionOR
    )
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    # Character used to quote field characters if field_quote_pattern matches (or not, depending on
    # field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote: ClassVar[str] = "`"
    # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is
    # always quoted if pattern is not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile("^(\\w|\\.)+$")
    # Negate field_quote_pattern result. Field name is quoted if pattern doesn't match if set to True (default).
    field_quote_pattern_negation: ClassVar[bool] = True

    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    field_escape: ClassVar[str] = ""
    # Escape quote string defined in field_quote
    field_escape_quote: ClassVar[bool] = True
    # All matches of this pattern are prepended with the string contained in field_escape.
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")

    ## Values
    str_quote: ClassVar[str] = "'"  # string quoting character (added as escaping character)
    escape_char: ClassVar[str] = "\\"  # Escaping character for special characters inside string
    wildcard_multi: ClassVar[str] = ".*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "."  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = "\\'"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Field type handling (from custom_attributes["field_types"])
    # These types are normalized to strict Databricks SQL types and are derived
    # from the OCSF Lite schema via the pipeline.
    numeric_field_types: ClassVar[Set[str]] = {"INT", "FLOAT", "DOUBLE", "BIGINT"}
    timestamp_field_types: ClassVar[Set[str]] = {"TIMESTAMP"}
    boolean_field_types: ClassVar[Set[str]] = {"BOOLEAN"}
    variant_field_types: ClassVar[Set[str]] = {"VARIANT"}
    array_string_field_types: ClassVar[Set[str]] = {"ARRAY<STRING>"}
    array_int_field_types: ClassVar[Set[str]] = {"ARRAY<INT>", "ARRAY<BIGINT>"}
    array_variant_field_types: ClassVar[Set[str]] = {"ARRAY<VARIANT>"}
    field_type_casts: ClassVar[Dict[str, str]] = {
        "INT": "INT",
        "FLOAT": "DOUBLE",
        "DOUBLE": "DOUBLE",
        "BOOLEAN": "BOOLEAN",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "startswith(lower({field}), lower({value}))"
    endswith_expression: ClassVar[str] = "endswith(lower({field}), lower({value}))"
    contains_expression: ClassVar[str] = "contains(lower({field}), lower({value}))"
    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_expression: ClassVar[str] = "lower({field}) regexp {value}"
    
    # Case-sensitive string matching expressions
    case_sensitive_match_expression: ClassVar[str] = "{field} = {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} LIKE {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} LIKE {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} LIKE {value}"

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = "{field} rlike '{regex}'"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    # List of strings that are escaped
    re_escape: ClassVar[Tuple[str]] = ("{}[]()\\+")
    # Regular expression flags. We rely on the default implementation of the backend to handle them.
    re_flag_prefix: bool = True

    # cidr expressions
    # Spark does not support CIDR matching natively yet, so we need to implement it manually.
    # CIDR matching is implemented via custom method:
    # - convert_condition_field_eq_val_cidr() handles both single CIDR and CIDR lists
    # These use IP-to-integer conversion and bitwise operations for subnet matching
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    # Note: cidr_expression not used - overridden by custom methods
    cidr_expression: ClassVar[str] = None
    cidr_in_list_expression: ClassVar[str] = None

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }
    
    # Operator mapping for all comparison operations
    # Maps operator names (lowercase strings) to SQL operator symbols
    operator_mapping: ClassVar[Dict[str, str]] = {
        "lt": "<",
        "lte": "<=",
        "gt": ">",
        "gte": ">=",
        "eq": "=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "{field} is null"
    
    # Field existence checks
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"
    
    # Field-to-field comparison
    field_equals_field_expression: ClassVar[str] = "LOWER({field1}) = LOWER({field2})"
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default) only plain values are converted
    # into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = False
    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "lower({field}) {op} ({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = "in"
    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    and_in_operator: ClassVar[str] = "contains-all"
    # List element separator
    list_separator: ClassVar[str] = ", "

    # Keyword Searches are NOT supported in the Databricks backend yet.
    ###################################################################
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = "{value}"
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '{value}'
    # Expression for regular expression not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'

    # Query finalization: appending and concatenating deferred query part
    # String used as separator between main query and deferred parts
    deferred_start: ClassVar[str] = "\n| "
    # String used to join multiple deferred query parts
    deferred_separator: ClassVar[str] = "\n| "
    # String used as query if final query only contains deferred expression
    deferred_only_query: ClassVar[str] = "*"

    def make_sql_string(self, s: SigmaString, case_sensitive: bool = False):
        """
        Convert a SigmaString to a SQL string value.
        
        Args:
            s: The SigmaString to convert.
            case_sensitive: If True, preserve case. If False, convert to lowercase.
            
        Returns:
            The quoted SQL string.
        """
        converted = s.convert(
            self.escape_char,
            None,
            None,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )
        converted = self._normalize_sql_string_literal(converted)
        # Convert to lowercase for case-insensitive matching
        if not case_sensitive:
            converted = converted.lower()
        return self.quote_string(converted)

    def _get_field_types(self) -> Dict[str, str]:
        """Return field type mappings from current rule custom attributes.

        The pipeline sets custom_attributes["field_types"] to a map of
        target_field -> normalized Databricks SQL type.
        """
        attrs = self._current_rule_custom_attributes
        if not isinstance(attrs, dict):
            return {}
        field_types = attrs.get("field_types")
        return field_types if isinstance(field_types, dict) else {}

    def _get_field_parent_info(self) -> Dict[str, Dict[str, str]]:
        """Return parent array info from current rule custom attributes."""
        attrs = self._current_rule_custom_attributes
        if not isinstance(attrs, dict):
            return {}
        parent_info = attrs.get("field_parent_info")
        return parent_info if isinstance(parent_info, dict) else {}

    def _normalize_field_key(self, field: str) -> str:
        """Normalize field key for type lookups."""
        if field.startswith(self.field_quote) and field.endswith(self.field_quote):
            return field[len(self.field_quote):-len(self.field_quote)]
        return field

    def _get_field_type(self, field: str) -> Optional[str]:
        """Lookup field type from custom attributes.

        Returns normalized Databricks SQL type or None if no mapping exists.
        """
        field_types = self._get_field_types()
        if not field_types:
            return None
        field_key = self._normalize_field_key(field)
        field_type = field_types.get(field_key)
        return field_type.upper() if isinstance(field_type, str) else None

    def _get_field_parent(self, field: str) -> Optional[Dict[str, str]]:
        """Lookup parent array info for a field."""
        parent_info = self._get_field_parent_info()
        if not parent_info:
            return None
        field_key = self._normalize_field_key(field)
        return parent_info.get(field_key)

    def _cast_field_for_type(self, field_expr: str, field_type: str) -> str:
        """Cast field expression for numeric, boolean, and timestamp types."""
        if field_type in self.numeric_field_types or field_type in self.boolean_field_types:
            sql_type = self.field_type_casts.get(field_type, field_type)
            return f"CAST({field_expr} AS {sql_type})"
        if field_type in self.timestamp_field_types:
            return f"try_to_timestamp({field_expr})"
        return field_expr

    def _cast_value_for_type(self, value_expr: str, field_type: str) -> str:
        """Cast value expression for numeric, boolean, and timestamp types."""
        if field_type in self.numeric_field_types or field_type in self.boolean_field_types:
            sql_type = self.field_type_casts.get(field_type, field_type)
            return f"CAST({value_expr} AS {sql_type})"
        if field_type in self.timestamp_field_types:
            return f"try_to_timestamp({value_expr})"
        return value_expr

    def _variant_array_expression(self, field_expr: str) -> str:
        """Return safe JSON-parsed array expression for VARIANT fields.

        We treat VARIANT as JSON stored in a string-like column. try_cast avoids
        runtime failures on non-JSON values; from_json then returns NULL.
        """
        return f"from_json(try_cast({field_expr} AS STRING), 'array<string>')"

    def _array_string_expression(self, field_expr: str, field_type: str) -> str:
        """Return array expression for string comparisons.

        ARRAY<VARIANT> values are normalized to STRING so membership checks are stable.
        """
        if field_type in self.array_variant_field_types:
            return f"transform({field_expr}, x -> CAST(x AS STRING))"
        return field_expr

    def _infer_case_sensitive(self, args) -> bool:
        """Infer whether membership matching should be case-sensitive."""
        if any(isinstance(arg.value, SigmaCasedString) for arg in args):
            return True
        if any(isinstance(arg.value, SigmaString) for arg in args):
            return False
        return True

    def _string_array_expression(self, field_expr: str, field_type: str) -> str:
        """Resolve array expression for string membership.

        VARIANT uses JSON parsing; ARRAY<STRING>/ARRAY<VARIANT> uses raw/normalized arrays.
        """
        if field_type in self.variant_field_types:
            return self._variant_array_expression(field_expr)
        return self._array_string_expression(field_expr, field_type)

    def _stringify_membership_value(self, value, case_sensitive: bool) -> str:
        """Normalize values into comparable STRING SQL literals for membership tests."""
        if isinstance(value, SigmaString):
            return self.make_sql_string(value, case_sensitive=case_sensitive)
        if isinstance(value, SigmaNumber):
            return f"CAST({value} AS STRING)"
        if isinstance(value, SigmaBool):
            return f"CAST({self.bool_values[value.boolean]} AS STRING)"
        return str(value)

    def _build_membership_list(self, args, case_sensitive: bool) -> list[str]:
        return [self._stringify_membership_value(arg.value, case_sensitive) for arg in args]

    def _format_string_array_equality(
        self, field_expr: str, value_expr: str, case_sensitive: bool, field_type: str
    ) -> str:
        """Format equality against string-like arrays or VARIANT JSON arrays.

        Example:
            field_expr="tags", value_expr="'admin'" ->
            "exists(tags, x -> lower(x) = 'admin')"
        """
        array_expr = self._string_array_expression(field_expr, field_type)
        if case_sensitive:
            return f"array_contains({array_expr}, {value_expr})"
        return f"exists({array_expr}, x -> lower(x) = {value_expr})"

    def _format_string_array_in_list(
        self, field_expr: str, values_expr: str, case_sensitive: bool, field_type: str
    ) -> str:
        """Format list-membership for string-like arrays or VARIANT JSON arrays.

        Example:
            field_expr="tags", values_expr="'a','b'" ->
            "exists(tags, x -> lower(x) in ('a','b'))"
        """
        array_expr = self._string_array_expression(field_expr, field_type)
        if case_sensitive:
            return f"exists({array_expr}, x -> x in ({values_expr}))"
        return f"exists({array_expr}, x -> lower(x) in ({values_expr}))"

    def _array_numeric_cast(self, field_type: str) -> str:
        """Return numeric element type for ARRAY<INT> or ARRAY<BIGINT>."""
        return "BIGINT" if field_type == "ARRAY<BIGINT>" else "INT"

    def _format_array_numeric_equality(
        self, field_expr: str, value_expr: str, field_type: str
    ) -> str:
        """Format equality against numeric arrays.

        Example:
            field_expr="ids", value_expr="CAST('5' AS INT)" ->
            "array_contains(ids, CAST('5' AS INT))"
        """
        return f"array_contains({field_expr}, {value_expr})"

    def _format_array_numeric_in_list(
        self, field_expr: str, values_expr: str
    ) -> str:
        """Format list-membership against numeric arrays.

        Example:
            field_expr="ids", values_expr="1,2,3" ->
            "exists(ids, x -> x in (1,2,3))"
        """
        return f"exists({field_expr}, x -> x in ({values_expr}))"

    def _format_parent_array_equality(
        self,
        parent_path: str,
        leaf_name: str,
        value_expr: str,
        case_sensitive: bool,
        field_type: Optional[str],
    ) -> str:
        """Format equality against a leaf inside ARRAY<STRUCT>.

        Example:
            parent_path="actor.authorizations", leaf_name="decision" ->
            "exists(actor.authorizations, x -> lower(x.decision) = 'allow')"
        """
        parent_expr = self.escape_and_quote_field(parent_path)
        member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
        if (
            field_type in self.numeric_field_types
            or field_type in self.boolean_field_types
            or field_type in self.timestamp_field_types
        ):
            return (
                f"exists({parent_expr}, x -> "
                f"{self._cast_field_for_type(member_expr, field_type)} = "
                f"{self._cast_value_for_type(value_expr, field_type)})"
            )
        if case_sensitive:
            return f"exists({parent_expr}, x -> {member_expr} = {value_expr})"
        return f"exists({parent_expr}, x -> lower({member_expr}) = {value_expr})"

    def _format_parent_array_in_list(
        self,
        parent_path: str,
        leaf_name: str,
        values_expr: str,
        case_sensitive: bool,
        field_type: Optional[str],
    ) -> str:
        """Format list-membership against a leaf inside ARRAY<STRUCT>.

        Example:
            parent_path="actor.authorizations", leaf_name="decision" ->
            "exists(actor.authorizations, x -> lower(x.decision) in ('allow','deny'))"
        """
        parent_expr = self.escape_and_quote_field(parent_path)
        member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
        if case_sensitive:
            return f"exists({parent_expr}, x -> {member_expr} in ({values_expr}))"
        return f"exists({parent_expr}, x -> lower({member_expr}) in ({values_expr}))"

    def _build_string_match_expression(
        self,
        field_expr: str,
        cond: ConditionFieldEqualsValueExpression,
        case_sensitive: bool,
        state: ConversionState,
    ) -> str:
        """Build a string match expression with the provided field expression.

        We distinguish plain prefix/suffix/contains patterns from true wildcard
        patterns. Simple patterns map to startswith/endswith/contains (or LIKE in
        case-sensitive mode), while wildcard patterns fall back to regex.

        Example:
            value="adm*" -> "startswith(lower(field), lower('adm'))"
        """
        if (
            self.startswith_expression is not None
            and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[:-1].contains_special()
        ):
            # Simple prefix pattern: "foo*"
            if case_sensitive:
                expr = self.case_sensitive_startswith_expression
                plain_value = str(cond.value[:-1])
                value = self.quote_string(plain_value + "%")
            else:
                expr = self.startswith_expression
                value = self.make_sql_string(cond.value[:-1], case_sensitive=False)
        elif (
            self.endswith_expression is not None
            and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[1:].contains_special()
        ):
            # Simple suffix pattern: "*foo"
            if case_sensitive:
                expr = self.case_sensitive_endswith_expression
                plain_value = str(cond.value[1:])
                value = self.quote_string("%" + plain_value)
            else:
                expr = self.endswith_expression
                value = self.make_sql_string(cond.value[1:], case_sensitive=False)
        elif (
            self.contains_expression is not None
            and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
            and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
            and not cond.value[1:-1].contains_special()
        ):
            # Simple contains pattern: "*foo*"
            if case_sensitive:
                expr = self.case_sensitive_contains_expression
                plain_value = str(cond.value[1:-1])
                value = self.quote_string("%" + plain_value + "%")
            else:
                expr = self.contains_expression
                value = self.make_sql_string(cond.value[1:-1], case_sensitive=False)
        elif (
            self.wildcard_match_expression is not None
            and cond.value.contains_special()
        ):
            # Complex wildcard pattern: use regex match.
            expr = self.wildcard_match_expression
            value = self.convert_value_str(cond.value, state)
        else:
            # No wildcards; plain equality (case-sensitive or lowered).
            if case_sensitive:
                expr = self.case_sensitive_match_expression
                value = self.make_sql_string(cond.value, case_sensitive=True)
            else:
                expr = "lower({field}) = lower({value})"
                value = self.make_sql_string(cond.value, case_sensitive=False)

        return expr.format(field=field_expr, value=value)

    def _format_typed_equality(self, field: str, value_expr: str, field_type: str) -> str:
        field_expr = self._cast_field_for_type(self.escape_and_quote_field(field), field_type)
        typed_value = self._cast_value_for_type(value_expr, field_type)
        return f"{field_expr} = {typed_value}"

    
    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """
        Convert a string value, applying case-insensitive conversion if needed.
        
        Args:
            s: The Sigma string to convert.
            state: Current conversion state.
            
        Returns:
            The converted string value.
        """
        converted = super().convert_value_str(s, state)
        if converted.startswith("'") and converted.endswith("'"):
            inner = converted[1:-1]
            inner = self._normalize_sql_string_literal(inner)
            converted = self.quote_string(inner)
        else:
            converted = self._normalize_sql_string_literal(converted)
        # Only convert to lowercase if not case-sensitive
        if not isinstance(s, SigmaCasedString):
            converted = converted.casefold()
        return converted

    def _normalize_sql_string_literal(self, value: str) -> str:
        """Normalize SQL string literals for Databricks.

        Converts backslash-escaped single quotes into doubled quotes and escapes
        remaining backslashes so they are treated as literal characters.
        """
        if not value:
            return value

        result = []
        i = 0
        while i < len(value):
            if value[i] == "\\":
                j = i
                while j < len(value) and value[j] == "\\":
                    j += 1
                slash_count = j - i
                if j < len(value) and value[j] == "'":
                    if slash_count % 2 == 1:
                        literal_backslashes = slash_count - 1
                        if literal_backslashes:
                            result.append("\\" * literal_backslashes)
                        result.append("''")
                        i = j + 1
                        continue
                result.append("\\" * slash_count)
                i = j
                continue
            if value[i] == "'":
                result.append("''")
                i += 1
                continue
            result.append(value[i])
            i += 1

        normalized = "".join(result)
        return normalized.replace("\\", "\\\\")

    def _ip_string_to_int_expression(self, field_expr: str) -> str:
        """
        Generate Spark SQL expression to convert IP string to 32-bit integer.
        
        Converts an IPv4 address string (e.g., '192.168.1.1') to a 32-bit integer
        using the formula: (octet1 * 16777216) + (octet2 * 65536) + (octet3 * 256) + octet4
        
        Args:
            field_expr: The field expression containing the IP address string
            
        Returns:
            Spark SQL expression that evaluates to the IP as a BIGINT
            
        Example:
            Input: 'IpAddress'
            Output: '(CAST(split(IpAddress, '\\\\.')[0] AS BIGINT) * 16777216 + ...)'
        """
        return (
            f"(CAST(split({field_expr}, '\\\\.')[0] AS BIGINT) * 16777216 + "
            f"CAST(split({field_expr}, '\\\\.')[1] AS BIGINT) * 65536 + "
            f"CAST(split({field_expr}, '\\\\.')[2] AS BIGINT) * 256 + "
            f"CAST(split({field_expr}, '\\\\.')[3] AS BIGINT))"
        )
    
    def _parse_cidr_notation(self, cidr) -> tuple[int, int]:
        """
        Parse CIDR notation and return network address and mask as integers.
        
        Args:
            cidr: CIDR notation (SigmaCIDRExpression or string like '192.168.1.0/24', '10.0.0.0/8')
            
        Returns:
            Tuple of (network_int, mask_int) where:
            - network_int: The network address as a 32-bit integer
            - mask_int: The network mask as a 32-bit integer
            
        Raises:
            ValueError: If CIDR notation is invalid
            NotImplementedError: If IPv6 CIDR is provided
            
        Example:
            Input: '192.168.1.0/24'
            Output: (3232235776, 4294967040)
        """
        # Convert SigmaCIDRExpression to string if needed
        cidr_str = str(cidr.cidr) if hasattr(cidr, 'cidr') else str(cidr)
        
        # Check for IPv6 (contains colons)
        if ':' in cidr_str:
            raise NotImplementedError(
                f"IPv6 CIDR matching is not supported. Got: {cidr_str}. "
                "Only IPv4 CIDR notation is supported (e.g., '10.0.0.0/8')."
            )
        
        # Split CIDR into address and prefix length
        try:
            ip_str, prefix_str = cidr_str.split('/')
            prefix_length = int(prefix_str)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {cidr_str}. Expected format: 'IP/PREFIX' (e.g., '192.168.1.0/24')")
        
        # Validate prefix length
        if not 0 <= prefix_length <= 32:
            raise ValueError(f"Invalid prefix length in CIDR: {cidr_str}. Must be between 0 and 32.")
        
        # Parse IP address octets
        try:
            octets = ip_str.split('.')
            if len(octets) != 4:
                raise ValueError(f"Invalid IP address in CIDR: {cidr_str}. Expected 4 octets.")
            
            # Convert IP to 32-bit integer
            network_int = 0
            for i, octet_str in enumerate(octets):
                octet = int(octet_str)
                if not 0 <= octet <= 255:
                    raise ValueError(f"Invalid octet value in IP address: {octet}. Must be 0-255.")
                network_int = network_int * 256 + octet
        except (ValueError, AttributeError) as e:
            raise ValueError(f"Invalid IP address in CIDR: {cidr_str}. Error: {str(e)}")
        
        # Calculate network mask
        # For prefix length n, mask is: 0xFFFFFFFF << (32 - n)
        if prefix_length == 0:
            mask_int = 0
        else:
            mask_int = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
        
        return network_int, mask_int

    def _convert_condition_field_eq_val_str(
        self,
        cond: ConditionFieldEqualsValueExpression,
        state: ConversionState,
        case_sensitive: bool,
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions with optional case sensitivity.

        Order of handling:
        1) If the field lives under ARRAY<STRUCT>, route through `exists` and apply
           array-aware membership/equals handling at the leaf.
        2) If the field is an array/variant at the top level, use array membership
           helpers with proper normalization.
        3) If the field is typed numeric/boolean/timestamp, cast and compare.
        4) Fallback to plain string matching.

        Example:
            field="process.name", value="cmd*" ->
            "startswith(lower(process.name), lower('cmd'))"
        """
        if not isinstance(cond.value, SigmaString):
            raise TypeError(f"cond.value type isn't SigmaString: {type(cond.value)}")
        try:
            field_type = self._get_field_type(cond.field)

            parent_info = self._get_field_parent(cond.field)
            if parent_info and parent_info.get("parent_path"):
                # Leaf of ARRAY<STRUCT>: compare against each member `x`.
                leaf_name = self._normalize_field_key(cond.field).split(".")[-1]
                member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
                parent_expr = self.escape_and_quote_field(parent_info["parent_path"])
                if field_type in self.array_int_field_types:
                    # Leaf is an array of ints; match membership within the leaf array.
                    numeric_type = self._array_numeric_cast(field_type)
                    value_expr = f"CAST({self.make_sql_string(cond.value, case_sensitive=True)} AS {numeric_type})"
                    return f"exists({parent_expr}, x -> array_contains({member_expr}, {value_expr}))"
                if field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
                    # Leaf is an array of strings/variants; use array-aware equality.
                    value_expr = self.make_sql_string(cond.value, case_sensitive=case_sensitive)
                    return f"exists({parent_expr}, x -> {self._format_string_array_equality(member_expr, value_expr, case_sensitive, field_type)})"
                # Leaf is scalar; use string match on the member field.
                match_expr = self._build_string_match_expression(
                    member_expr,
                    cond,
                    case_sensitive,
                    state,
                )
                return f"exists({parent_expr}, x -> {match_expr})"

            if field_type in self.variant_field_types or field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
                value = self.make_sql_string(cond.value, case_sensitive=case_sensitive)
                return self._format_string_array_equality(
                    self.escape_and_quote_field(cond.field),
                    value,
                    case_sensitive,
                    field_type,
                )

            if field_type in self.array_int_field_types:
                numeric_type = self._array_numeric_cast(field_type)
                value = f"CAST({self.make_sql_string(cond.value, case_sensitive=True)} AS {numeric_type})"
                return self._format_array_numeric_equality(
                    self.escape_and_quote_field(cond.field),
                    value,
                    field_type,
                )

            if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
                value = self.make_sql_string(cond.value, case_sensitive=True)
                return self._format_typed_equality(cond.field, value, field_type)
            
            field_expr = self.escape_and_quote_field(cond.field)
            return self._build_string_match_expression(
                field_expr,
                cond,
                case_sensitive,
                state,
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the "
                                      "backend.")

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Case-insensitive string equality.

        Dispatches to `_convert_condition_field_eq_val_str` to share the full
        type/array/parent handling, only differing by the case-sensitivity flag.

        Example:
            field="user.name", value="Admin" ->
            "lower(user.name) = lower('admin')"
        """
        return self._convert_condition_field_eq_val_str(cond, state, case_sensitive=False)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Case-sensitive string equality.

        Uses the shared implementation with `case_sensitive=True` so all type
        and array handling remains identical to the insensitive path.

        Example:
            field="user.name", value="Admin" ->
            "user.name = 'Admin'"
        """
        return self._convert_condition_field_eq_val_str(cond, state, case_sensitive=True)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Regex match, with special handling for ARRAY<STRUCT> parents.

        Example:
            field="file.name", regex=".*\\.tmp" ->
            "file.name rlike '.*\\.tmp'"
        """
        parent_info = self._get_field_parent(cond.field)
        if parent_info and parent_info.get("parent_path"):
            # Apply regex to the member field inside the parent array.
            leaf_name = self._normalize_field_key(cond.field).split(".")[-1]
            member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
            parent_expr = self.escape_and_quote_field(parent_info["parent_path"])
            regex = self.convert_value_re(cond.value, state)
            if not regex.startswith("'"):
                # Ensure regex literal is quoted for rlike.
                regex = self.quote_string(regex)
            return f"exists({parent_expr}, x -> {member_expr} rlike {regex})"
        # Fallback to default regex handling for non-array fields.
        return super().convert_condition_field_eq_val_re(cond, state)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions with type awareness.

        Example:
            field="event.count", value=5 ->
            "CAST(event.count AS INT) = CAST(5 AS INT)"
        """
        field_type = self._get_field_type(cond.field)
        parent_info = self._get_field_parent(cond.field)
        if parent_info and parent_info.get("parent_path"):
            # Leaf under ARRAY<STRUCT>: compare against each member, with casting if typed.
            value_expr = self._stringify_membership_value(cond.value, True)
            leaf_name = self._normalize_field_key(cond.field).split(".")[-1]
            return self._format_parent_array_equality(
                parent_info["parent_path"],
                leaf_name,
                value_expr,
                True,
                field_type,
            )

        if field_type in self.variant_field_types or field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
            # Numeric compared against a string/variant array: stringify and compare per element.
            value_expr = self._stringify_membership_value(cond.value, True)
            return self._format_string_array_equality(
                self.escape_and_quote_field(cond.field),
                value_expr,
                True,
                field_type,
            )
        if field_type in self.array_int_field_types:
            # Numeric array: direct array membership check.
            return self._format_array_numeric_equality(
                self.escape_and_quote_field(cond.field),
                str(cond.value),
                field_type,
            )
        if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
            # Typed scalar comparison (casts applied inside `_format_typed_equality`).
            return self._format_typed_equality(cond.field, str(cond.value), field_type)
        # Fallback to base backend behavior for unknown types.
        return super().convert_condition_field_eq_val_num(cond, state)

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = bool value expressions with type awareness.

        Example:
            field="user.is_admin", value=true ->
            "CAST(user.is_admin AS BOOLEAN) = true"
        """
        field_type = self._get_field_type(cond.field)
        parent_info = self._get_field_parent(cond.field)
        if parent_info and parent_info.get("parent_path"):
            # Leaf under ARRAY<STRUCT>: compare against each member, with casting if typed.
            value = self._stringify_membership_value(cond.value, True)
            leaf_name = self._normalize_field_key(cond.field).split(".")[-1]
            return self._format_parent_array_equality(
                parent_info["parent_path"],
                leaf_name,
                value,
                True,
                field_type,
            )

        if field_type in self.variant_field_types or field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
            # Boolean compared against string/variant arrays: stringify and compare per element.
            value = self._stringify_membership_value(cond.value, True)
            return self._format_string_array_equality(
                self.escape_and_quote_field(cond.field),
                value,
                True,
                field_type,
            )
        if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
            # Typed scalar comparison (casts applied inside `_format_typed_equality`).
            value = self.bool_values[cond.value.boolean]
            return self._format_typed_equality(cond.field, value, field_type)
        # Fallback to base backend behavior for unknown types.
        return super().convert_condition_field_eq_val_bool(cond, state)

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Convert OR/AND lists into IN-style expressions with type awareness.

        Args:
            cond: The OR or AND condition to convert.
            state: Current conversion state.

        Returns:
            The converted query string or deferred expression.

        Examples:
            field="user.name" OR ['alice','bob'] ->
            "lower(user.name) in ('alice','bob')"
        """
        field_name = cond.args[0].field
        field_type = self._get_field_type(field_name)
        op = self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator

        parent_info = self._get_field_parent(field_name)
        if parent_info and parent_info.get("parent_path"):
            # Field is under ARRAY<STRUCT>: build an exists(...) over parent members.
            leaf_name = self._normalize_field_key(field_name).split(".")[-1]
            parent_expr = self.escape_and_quote_field(parent_info["parent_path"])
            member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
            if field_type in self.array_int_field_types:
                # Leaf is array of ints: check membership inside each leaf array.
                numeric_type = self._array_numeric_cast(field_type)
                values = []
                for arg in cond.args:
                    if isinstance(arg.value, SigmaString):
                        raw_value = self.make_sql_string(arg.value, case_sensitive=True)
                        values.append(f"CAST({raw_value} AS {numeric_type})")
                    else:
                        values.append(str(arg.value))
                return f"exists({parent_expr}, x -> exists({member_expr}, y -> y in ({self.list_separator.join(values)})))"
            if field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
                # Leaf is array of strings/variants: normalize and compare per element.
                case_sensitive = self._infer_case_sensitive(cond.args)
                values = self._build_membership_list(cond.args, case_sensitive)
                return (
                    f"exists({parent_expr}, x -> "
                    f"{self._format_string_array_in_list(member_expr, self.list_separator.join(values), case_sensitive, field_type)})"
                )
            if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
                # Leaf is typed scalar: cast values and compare per member.
                values = []
                for arg in cond.args:
                    if isinstance(arg.value, SigmaString):
                        raw_value = self.make_sql_string(arg.value, case_sensitive=True)
                    elif isinstance(arg.value, SigmaBool):
                        raw_value = self.bool_values[arg.value.boolean]
                    else:
                        raw_value = str(arg.value)
                    values.append(self._cast_value_for_type(raw_value, field_type))
                member_expr = self._cast_field_for_type(member_expr, field_type)
                return f"exists({parent_expr}, x -> {member_expr} in ({self.list_separator.join(values)}))"
            # Default: treat as string membership on the member field.
            case_sensitive = self._infer_case_sensitive(cond.args)
            values = self._build_membership_list(cond.args, case_sensitive)
            return self._format_parent_array_in_list(
                parent_info["parent_path"],
                leaf_name,
                self.list_separator.join(values),
                case_sensitive,
                field_type,
            )

        if field_type in self.variant_field_types or field_type in self.array_string_field_types or field_type in self.array_variant_field_types:
            # Top-level string/variant arrays use array membership helpers.
            case_sensitive = self._infer_case_sensitive(cond.args)
            values = self._build_membership_list(cond.args, case_sensitive)
            return self._format_string_array_in_list(
                self.escape_and_quote_field(field_name),
                self.list_separator.join(values),
                case_sensitive,
                field_type,
            )

        if field_type in self.array_int_field_types:
            # Top-level numeric arrays use element membership.
            numeric_type = self._array_numeric_cast(field_type)
            values = []
            for arg in cond.args:
                if isinstance(arg.value, SigmaString):
                    raw_value = self.make_sql_string(arg.value, case_sensitive=True)
                    values.append(f"CAST({raw_value} AS {numeric_type})")
                else:
                    values.append(str(arg.value))
            return self._format_array_numeric_in_list(
                self.escape_and_quote_field(field_name),
                self.list_separator.join(values),
            )

        if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
            # Typed scalar field: cast values then use IN with appropriate operator.
            field_expr = self._cast_field_for_type(self.escape_and_quote_field(field_name), field_type)
            values = []
            for arg in cond.args:
                if isinstance(arg.value, SigmaString):
                    raw_value = self.make_sql_string(arg.value, case_sensitive=True)
                    values.append(self._cast_value_for_type(raw_value, field_type))
                else:
                    values.append(str(arg.value))
            return f"{field_expr} {op} ({self.list_separator.join(values)})"

        # Fallback: default string IN conversion (legacy behavior).
        return self._convert_string_in_expression(cond, state)

    def _convert_string_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Default string IN expression conversion (preserves legacy behavior).

        Example:
            field="user.name" OR ['a','b'] ->
            "lower(user.name) in ('a','b')"
        """
        field = self.escape_and_quote_field(cond.args[0].field)
        if not any(isinstance(arg.value, SigmaCasedString) for arg in cond.args):
            field = f"LOWER({field})"

        return self.field_in_list_expression.format(
            field=field,
            op=(
                self.or_in_operator
                if isinstance(cond, ConditionOR)
                else self.and_in_operator
            ),
            list=self.list_separator.join(
                [
                    (
                        self.convert_value_str(arg.value, state)
                        if isinstance(arg.value, SigmaString)
                        else str(arg.value)
                    )
                    for arg in cond.args
                ]
            ),
        )

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of numeric/timestamp comparison operations with type awareness.

        Example:
            field="time", op="gte", value=1700000000 ->
            "try_to_timestamp(from_unixtime(1700000000)) >= ..."
        """
        field_expr = self.escape_and_quote_field(cond.field)
        field_type = self._get_field_type(cond.field)
        value_number = cond.value.number.number
        value_expr = value_number
        parent_info = self._get_field_parent(cond.field)
        if field_type in self.numeric_field_types or field_type in self.boolean_field_types:
            # Typed scalar: cast field to the expected numeric/boolean type.
            field_expr = self._cast_field_for_type(field_expr, field_type)
        if field_type in self.timestamp_field_types:
            # Timestamp compare: infer seconds vs millis from magnitude.
            field_expr = self._cast_field_for_type(field_expr, field_type)
            value_expr = (
                f"try_to_timestamp(from_unixtime({value_number} / 1000))"
                if value_number >= 1000000000000
                else f"try_to_timestamp(from_unixtime({value_number}))"
            )
        if parent_info and parent_info.get("parent_path"):
            # Leaf under ARRAY<STRUCT>: compare against each member.
            leaf_name = self._normalize_field_key(cond.field).split(".")[-1]
            member_expr = f"x.{self.escape_and_quote_field(leaf_name)}"
            if field_type in self.numeric_field_types or field_type in self.boolean_field_types or field_type in self.timestamp_field_types:
                # Apply the same type casting to the member field.
                member_expr = self._cast_field_for_type(member_expr, field_type)
            parent_expr = self.escape_and_quote_field(parent_info["parent_path"])
            return f"exists({parent_expr}, x -> {member_expr} {self.compare_operators[cond.value.op]} {value_expr})"
        # Non-array scalar comparison.
        return self.compare_op_expression.format(
            field=field_expr,
            operator=self.compare_operators[cond.value.op],
            value=value_expr,
        )
    
    def decide_convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> bool:
        """
        Determine if an OR or AND condition should be converted to an IN expression.
        
        Args:
            cond: The condition to evaluate.
            state: Current conversion state.
            
        Returns:
            True if the condition should be converted to an IN expression, False otherwise.

        Example:
            (field = 'a' OR field = 'b') -> True
        """
        # Check if conversion is enabled for this condition type
        if (
            not self.convert_or_as_in
            and isinstance(cond, ConditionOR)
        ) or (not self.convert_and_as_in and isinstance(cond, ConditionAND)):
            return False
        
        # All arguments must be field-equals-value expressions
        if not all(
            (isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args)
        ):
            return False
        
        # All arguments must reference the same field
        fields = {arg.field for arg in cond.args}
        if len(fields) != 1:
            return False
        
        # All values must be strings or numbers
        if not all(
            [isinstance(arg.value, (SigmaString, SigmaNumber)) for arg in cond.args]
        ):
            return False
        
        # Check if wildcards are allowed
        if not self.in_expressions_allow_wildcards and any(
            [
                arg.value.contains_special()
                for arg in cond.args
                if isinstance(arg.value, SigmaString)
            ]
        ):
            return False
        
        return True

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """
        Convert field equals CIDR value expression(s) to Spark SQL.
        Needed until Spark supports CIDR matching natively.
        
        Converts CIDR matching (single or multiple values) into bitwise comparisons
        that check if the IP address falls within the specified subnet(s).
        
        Args:
            cond: The field-equals-CIDR condition (single value or list)
            state: Current conversion state
            
        Returns:
            Spark SQL expression for CIDR matching:
            - Single CIDR: '(ip_expr & mask) = network /* CIDR: x.x.x.x/prefix */'
            - Multiple CIDRs: '((ip_expr & mask1) = net1 OR (ip_expr & mask2) = net2)'
            
        Raises:
            NotImplementedError: If any IPv6 CIDR is provided
            ValueError: If any CIDR notation is invalid
            
        Examples:
            Input: IpAddress|cidr: '10.0.0.0/8'
            Output: '((CAST(split(IpAddress, '\\.')[0] AS BIGINT) * 16777216 + ...) & 4278190080) = 167772160 /* CIDR: 10.0.0.0/8 */'
            
            Input: IpAddress|cidr: ['10.0.0.0/8', '192.168.0.0/16']
            Output: '((ip_expr & mask1) = net1 /* CIDR: 10.0.0.0/8 */ OR (ip_expr & mask2) = net2 /* CIDR: 192.168.0.0/16 */)'
        """
        field = self.escape_and_quote_field(cond.field)
        
        # Normalize to list for uniform processing
        cidrs = cond.value if isinstance(cond.value, list) else [cond.value]
        
        # Generate IP-to-integer conversion expression (reuse for all CIDRs)
        ip_int_expr = self._ip_string_to_int_expression(field)
        
        # Convert each CIDR to a comparison
        comparisons = []
        for cidr in cidrs:
            # Parse CIDR notation (raises NotImplementedError for IPv6)
            network_int, mask_int = self._parse_cidr_notation(cidr)
            
            # Generate bitwise AND comparison with CIDR comment
            network_masked = network_int & mask_int
            cidr_str = str(cidr.cidr) if hasattr(cidr, 'cidr') else str(cidr)
            comparisons.append(f"({ip_int_expr} & {mask_int}) = {network_masked} /* CIDR: {cidr_str} */")
        
        # Return single expression or OR-joined expressions
        if len(comparisons) == 1:
            return comparisons[0]
        else:
            return "(" + " OR ".join(comparisons) + ")"

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize query by adding SELECT/FROM structure and time filtering.
        
        Generates: 
        SELECT * FROM {schema}.{table} 
        WHERE {time_column} BETWEEN CURRENT_TIMESTAMP() - INTERVAL {time_filter} AND CURRENT_TIMESTAMP()
          AND ({query})
        
        """
        # Get table from custom attributes (set by pipeline)
        table = rule.custom_attributes.get('table')
        
        # Build fully-qualified table name
        if self.schema:
            fq_table = f"{self.schema}.{table}"
            if self.catalog:
                fq_table = f"{self.catalog}.{fq_table}"
        else:
            fq_table = table
        
        # Build WHERE clause with time filter
        where_clause = (
            f"{self.time_column} BETWEEN "
            f"CURRENT_TIMESTAMP() - INTERVAL {self.time_filter} AND CURRENT_TIMESTAMP() "
            f"AND ({query})"
        )

        # Generate final SQL
        sql = f"SELECT * FROM {fq_table} WHERE {where_clause}"
        
        # Validate generated SQL
        sql_errors = verify_databricks_sql(sql)
        if sql_errors:
            for error in sql_errors:
                error_msg = f"Rule '{rule.id}' generated invalid SQL: {error}"
                warnings.warn(error_msg, UserWarning)
                if self.collect_errors:
                    rule.errors.append(error_msg)
        
        return sql
    
    def finalize_query_lakewatch(
        self, rule: SigmaRule, query: str, 
        index: int, state: ConversionState
    ) -> str:
        """
        Finalize query for lakewatch output format.
        
        Converts a Sigma rule and its query into LakeWatch Detection Rule JSON.
        
        Args:
            rule: SigmaRule to convert
            query: Raw query string (WHERE clause)
            index: Query index
            state: Conversion state
            
        Returns:
            JSON string representing the LakeWatch rule
        """
        # Get the complete SQL query
        finalized_sql = self.finalize_query_default(rule, query, index, state)
        
        # Build and return LakeWatch rule as JSON
        return Rule.from_sigma_rule(rule, finalized_sql, is_correlation=False).to_json()
    
    def finalize_output_lakewatch(
        self, queries: List[str]
    ) -> List[str]:
        """
        Finalize output for lakewatch format.
        
        This is called after all queries are finalized. Since we already
        converted each query to JSON in finalize_query_lakewatch,
        we just return them as-is.
        
        Args:
            queries: List of JSON strings representing LakeWatch rules
            
        Returns:
            List of JSON strings (unchanged)
        """
        return queries

