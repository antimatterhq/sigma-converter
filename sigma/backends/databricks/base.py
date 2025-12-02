import re
import json
import warnings
from typing import Pattern, Union, ClassVar, Tuple, List, Dict, Any, Optional

from sigma.conditions import ConditionItem, ConditionOR, ConditionAND, ConditionNOT, \
    ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaString, SigmaCasedString, SigmaNumber
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
        time_filter: str = "24h",
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
        # Convert to lowercase for case-insensitive matching
        if not case_sensitive:
            converted = converted.lower()
        return self.quote_string(converted)
    
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
        # Only convert to lowercase if not case-sensitive
        if not isinstance(s, SigmaCasedString):
            converted = converted.casefold()
        return converted

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

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression,
                                           state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        if not isinstance(cond.value, SigmaString):
            raise TypeError(f"cond.value type isn't SigmaString: {type(cond.value)}")
        try:
            # Check if value is case-sensitive
            is_case_sensitive = isinstance(cond.value, SigmaCasedString)
            
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and not cond.value[:-1].contains_special()  # Remainder of string doesn't contain special characters
            ):
                if is_case_sensitive:
                    expr = self.case_sensitive_startswith_expression
                    # For case-sensitive LIKE, extract string value and add wildcard
                    plain_value = str(cond.value[:-1])
                    value = self.quote_string(plain_value + "%")
                else:
                    expr = self.startswith_expression
                    value = self.make_sql_string(cond.value[:-1], case_sensitive=False)
            elif (
                # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contain further
                # special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                if is_case_sensitive:
                    expr = self.case_sensitive_endswith_expression
                    # For case-sensitive LIKE, extract string value and add wildcard
                    plain_value = str(cond.value[1:])
                    value = self.quote_string("%" + plain_value)
                else:
                    expr = self.endswith_expression
                    value = self.make_sql_string(cond.value[1:], case_sensitive=False)
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                if is_case_sensitive:
                    expr = self.case_sensitive_contains_expression
                    # For case-sensitive LIKE, extract string value and add wildcards
                    plain_value = str(cond.value[1:-1])
                    value = self.quote_string("%" + plain_value + "%")
                else:
                    expr = self.contains_expression
                    value = self.make_sql_string(cond.value[1:-1], case_sensitive=False)
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None
                and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = self.convert_value_str(cond.value, state)
            else:  # We have just plain string
                if is_case_sensitive:
                    expr = self.case_sensitive_match_expression
                    value = self.make_sql_string(cond.value, case_sensitive=True)
                else:
                    expr = "lower({field}) = lower({value})"
                    value = self.make_sql_string(cond.value, case_sensitive=False)

            return expr.format(field=self.escape_and_quote_field(cond.field),
                               value=value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the "
                                      "backend.")

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """
        Convert a field-in-value-list condition, respecting case sensitivity.
        
        Args:
            cond: The OR or AND condition to convert.
            state: Current conversion state.
            
        Returns:
            The converted query string or deferred expression.
        """
        field = self.escape_and_quote_field(cond.args[0].field)
        # Check if any value is case-sensitive
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

