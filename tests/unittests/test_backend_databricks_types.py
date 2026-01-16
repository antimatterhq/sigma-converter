import pytest

from sigma.collection import SigmaCollection
from sigma.backends.databricks import DatabricksBackend


@pytest.fixture
def databricks_backend_no_validation():
    """Backend with validation mocked out for SQL generation testing."""
    backend = DatabricksBackend()

    def mock_convert(rule, output_format=None, **kwargs):
        # Call the grandparent's convert (TextQueryBackend) to bypass validation
        from sigma.conversion.base import TextQueryBackend
        return TextQueryBackend.convert(backend, rule, output_format, **kwargs)

    backend.convert = mock_convert
    return backend


def _convert_with_field_types(backend: DatabricksBackend, yaml_str: str, field_types: dict):
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = field_types
    return backend.convert(collection, output_format="default")[0]


def test_typed_int_equality_casts_string_value(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Int Equality
        status: test
        logsource:
            category: test
        detection:
            sel:
                process.pid: "42"
            condition: sel
        """,
        {"process.pid": "INT"},
    )
    assert "cast(process.pid as int) = cast('42' as int)" in sql.lower()


def test_typed_int_equality_numeric_value(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Int Equality Numeric
        status: test
        logsource:
            category: test
        detection:
            sel:
                process.pid: 42
            condition: sel
        """,
        {"process.pid": "INT"},
    )
    assert "cast(process.pid as int) = cast(42 as int)" in sql.lower()


def test_typed_timestamp_equality_uses_try_to_timestamp(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Timestamp Equality
        status: test
        logsource:
            category: test
        detection:
            sel:
                time: "2024-01-01T00:00:00Z"
            condition: sel
        """,
        {"time": "TIMESTAMP"},
    )
    assert "try_to_timestamp(time) = try_to_timestamp('2024-01-01t00:00:00z')" in sql.lower()


def test_typed_variant_contains_case_insensitive(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Variant Contains
        status: test
        logsource:
            category: test
        detection:
            sel:
                metadata.tags: Admin
            condition: sel
        """,
        {"metadata.tags": "VARIANT"},
    )
    assert "exists(from_json(try_cast(metadata.tags as string), 'array<string>'), x -> lower(x) = 'admin')" in sql.lower()


def test_typed_variant_contains_case_sensitive(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Variant Contains Cased
        status: test
        logsource:
            category: test
        detection:
            sel:
                metadata.tags|cased: Admin
            condition: sel
        """,
        {"metadata.tags": "VARIANT"},
    )
    assert "array_contains(from_json(try_cast(metadata.tags as string), 'array<string>'), 'admin')" in sql.lower()


def test_typed_int_in_list(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Int In List
        status: test
        logsource:
            category: test
        detection:
            sel:
                process.pid:
                    - 1
                    - 2
                    - 3
            condition: sel
        """,
        {"process.pid": "INT"},
    )
    assert "cast(process.pid as int) in (1, 2, 3)" in sql.lower()


def test_typed_variant_in_list(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Variant In List
        status: test
        logsource:
            category: test
        detection:
            sel:
                metadata.tags:
                    - Admin
                    - Root
            condition: sel
        """,
        {"metadata.tags": "VARIANT"},
    )
    assert "exists(from_json(try_cast(metadata.tags as string), 'array<string>'), x -> lower(x) in ('admin', 'root'))" in sql.lower()


def test_typed_variant_numeric_value_stringified(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Variant Numeric
        status: test
        logsource:
            category: test
        detection:
            sel:
                metadata.tags: 42
            condition: sel
        """,
        {"metadata.tags": "VARIANT"},
    )
    assert "array_contains(from_json(try_cast(metadata.tags as string), 'array<string>'), cast(42 as string))" in sql.lower()


def test_typed_variant_bool_value_stringified(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Variant Bool
        status: test
        logsource:
            category: test
        detection:
            sel:
                metadata.tags: true
            condition: sel
        """,
        {"metadata.tags": "VARIANT"},
    )
    assert "array_contains(from_json(try_cast(metadata.tags as string), 'array<string>'), cast(true as string))" in sql.lower()


def test_array_string_contains_case_insensitive(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Array String Contains
        status: test
        logsource:
            category: test
        detection:
            sel:
                answers.flags: Admin
            condition: sel
        """,
        {"answers.flags": "ARRAY<STRING>"},
    )
    assert "exists(answers.flags, x -> lower(x) = 'admin')" in sql.lower()


def test_array_int_contains(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Array Int Contains
        status: test
        logsource:
            category: test
        detection:
            sel:
                answers.flag_ids: 5
            condition: sel
        """,
        {"answers.flag_ids": "ARRAY<INT>"},
    )
    assert "array_contains(answers.flag_ids, 5)" in sql.lower()


def test_array_variant_contains_case_sensitive(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Array Variant Contains
        status: test
        logsource:
            category: test
        detection:
            sel:
                finding_info.analytic.related_analytics|cased: abc
            condition: sel
        """,
        {"finding_info.analytic.related_analytics": "ARRAY<VARIANT>"},
    )
    assert "array_contains(transform(finding_info.analytic.related_analytics, x -> cast(x as string)), 'abc')" in sql.lower()


def test_array_parent_object_string_match(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Match
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision: success
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "STRING"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> lower(x.decision) = lower('success'))" in sql.lower()


def test_array_parent_object_contains(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Contains
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision|contains: succ
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "STRING"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> contains(lower(x.decision), lower('succ')))" in sql.lower()


def test_array_parent_object_startswith(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Startswith
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision|startswith: suc
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "STRING"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> startswith(lower(x.decision), lower('suc')))" in sql.lower()


def test_array_parent_object_endswith(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Endswith
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision|endswith: cess
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "STRING"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> endswith(lower(x.decision), lower('cess')))" in sql.lower()


def test_array_parent_object_regex(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Regex
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision|re: suc.*ess
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "STRING"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> x.decision rlike 'suc.*ess')" in sql.lower()


def test_array_parent_object_array_string_membership(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Array String
    status: test
    logsource:
        category: test
    detection:
        sel:
            answers.flags: ok
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "answers.flags": "ARRAY<STRING>"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "answers.flags": {
            "parent_path": "answers",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(answers, x -> exists(x.flags, x -> lower(x) = 'ok'))" in sql.lower()


def test_array_parent_object_array_int_membership(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Array Int
    status: test
    logsource:
        category: test
    detection:
        sel:
            answers.flag_ids: '5'
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "answers.flag_ids": "ARRAY<INT>"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "answers.flag_ids": {
            "parent_path": "answers",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(answers, x -> array_contains(x.flag_ids, cast('5' as int)))" in sql.lower()


def test_array_parent_object_array_string_in_list(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Array String In List
    status: test
    logsource:
        category: test
    detection:
        sel1:
            answers.flags: ok
        sel2:
            answers.flags: warn
        condition: sel1 or sel2
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "answers.flags": "ARRAY<STRING>"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "answers.flags": {
            "parent_path": "answers",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(answers, x -> exists(x.flags, x -> lower(x) in ('ok', 'warn')))" in sql.lower()


def test_array_parent_object_array_int_in_list(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Array Int In List
    status: test
    logsource:
        category: test
    detection:
        sel1:
            answers.flag_ids: '5'
        sel2:
            answers.flag_ids: '7'
        condition: sel1 or sel2
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "answers.flag_ids": "ARRAY<INT>"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "answers.flag_ids": {
            "parent_path": "answers",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(answers, x -> exists(x.flag_ids, y -> y in (cast('5' as int), cast('7' as int))))" in sql.lower()


def test_array_parent_object_compare(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Compare
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.decision|gt: 5
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "INT"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> cast(x.decision as int) > 5)" in sql.lower()


def test_array_parent_object_compare_timestamp(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object Compare Timestamp
    status: test
    logsource:
        category: test
    detection:
        sel:
            actor.authorizations.created_time|gt: 1704067200
        condition: sel
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.created_time": "TIMESTAMP"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.created_time": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> try_to_timestamp(x.created_time) > try_to_timestamp(from_unixtime(1704067200)))" in sql.lower()


def test_array_parent_object_in_list_numeric(databricks_backend_no_validation: DatabricksBackend):
    yaml_str = """
    title: Array Parent Object In List Numeric
    status: test
    logsource:
        category: test
    detection:
        sel1:
            actor.authorizations.decision: 1
        sel2:
            actor.authorizations.decision: 2
        condition: 1 of sel*
    """
    from sigma.collection import SigmaCollection
    collection = SigmaCollection.from_yaml(yaml_str)
    collection.rules[0].custom_attributes["field_types"] = {
        "actor.authorizations.decision": "INT"
    }
    collection.rules[0].custom_attributes["field_parent_info"] = {
        "actor.authorizations.decision": {
            "parent_path": "actor.authorizations",
            "parent_type": "ARRAY<STRUCT>"
        }
    }
    sql = databricks_backend_no_validation.convert(collection, output_format="default")[0]
    assert "exists(actor.authorizations, x -> cast(x.decision as int) in (cast(1 as int), cast(2 as int)))" in sql.lower()


def test_typed_int_compare_op(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Int Compare
        status: test
        logsource:
            category: test
        detection:
            sel:
                process.pid|gt: 5
            condition: sel
        """,
        {"process.pid": "INT"},
    )
    assert "cast(process.pid as int) > 5" in sql.lower()


def test_typed_timestamp_compare_uses_epoch_seconds(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Timestamp Compare
        status: test
        logsource:
            category: test
        detection:
            sel:
                time|gt: 1704067200
            condition: sel
        """,
        {"time": "TIMESTAMP"},
    )
    assert "try_to_timestamp(time) > try_to_timestamp(from_unixtime(1704067200))" in sql.lower()


def test_typed_timestamp_compare_uses_epoch_millis(databricks_backend_no_validation: DatabricksBackend):
    sql = _convert_with_field_types(
        databricks_backend_no_validation,
        """
        title: Typed Timestamp Compare Millis
        status: test
        logsource:
            category: test
        detection:
            sel:
                time|gt: 1704067200000
            condition: sel
        """,
        {"time": "TIMESTAMP"},
    )
    assert "try_to_timestamp(time) > try_to_timestamp(from_unixtime(1704067200000 / 1000))" in sql.lower()
