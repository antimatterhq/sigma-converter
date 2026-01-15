from typing import Optional, List, Callable
import requests
import argparse
import yaml
import os
import json


class Field:
    """
    A simple field class to store field attributes and convert it into a SQL record for table creation.
    """

    def __str__(self) -> str:
        raise NotImplementedError("Subclasses must implement __str__")

    def name(self) -> str:
        raise NotImplementedError("Subclasses must implement name")

    def type(self) -> str:
        raise NotImplementedError("Subclasses must implement type")

    def set_tags(self, value) -> None:
        raise NotImplementedError("Subclasses must implement set_tags")

    def get_tags(self) -> dict:
        raise NotImplementedError("Subclasses must implement get_tags")

    def schema(self):
        raise NotImplementedError("Subclasses must implement schema")


class FieldPrimitive(Field):
    def __init__(
        self,
        name: str,
        type_name: str,
        description: str,
        is_array: bool,
        nullable: bool,
        render_comments: bool = False,
    ):
        """
        A primitive field is one that does not contain nested fields, such as a struct.
        :param name: The name of the field.
        :param type_name: The SQL-compatible type of the field.
        :param description: A field description if provided. Will be added as a COMMENT.
        :param is_array: A flag indicating whether the object is an array of types or not.
        :param nullable: A flag indicating whether the object is nullable or not.
        """
        self.field_name = name
        self.is_array = is_array
        self.nullable = nullable
        self.description = description
        self.type_name = type_name
        self._tags = None
        self.comments = render_comments

    def __str__(self):
        field = self.schema()
        if not self.nullable:
            field = f"{field} NOT NULL"
        if len(self.description) > 0 and self.comments:
            field = f"{field} COMMENT '{self.description}'"
        return field

    def schema(self):
        return f"{self.field_name} {self.type()}"

    def name(self) -> str:
        return self.field_name

    def type(self) -> str:
        if self.is_array:
            return f"ARRAY<{self.type_name}>"
        else:
            return self.type_name

    def set_tags(self, value: dict) -> None:
        self._tags = value

    def get_tags(self) -> dict:
        return self._tags


class FieldStruct(Field):
    def __init__(
        self,
        name: str,
        content: List[Field],
        description: str,
        is_array: bool,
        nullable: bool,
        render_comments: bool = False,
    ):
        """
        A helper object to handle struct type fields.
        :param name: The name of the field.
        :param type_name: The SQL-compatible type of the field.
        :param description: A field description if provided. Will be added as a COMMENT.
        :param is_array: A flag indicating whether the object is an array of types or not.
        :param nullable: A flag indicating whether the object is nullable or not.
        """
        self.field_name = name
        self.content = content
        self.description = description
        self.is_array = is_array
        self.nullable = nullable
        self._tags = None
        self.comments = render_comments

    def __str__(self):
        field = self.schema()
        if not self.nullable:
            field = f"{field} NOT NULL"
        if len(self.description) > 0 and self.comments:
            field = f"{field} COMMENT '{self.description}'"
        return field

    def schema(self):
        return f"{self.field_name} {self.type()}"

    def name(self) -> str:
        return self.field_name

    def type(self) -> str:
        field = f"STRUCT<{','.join([f'{x.name()}:{x.type()}' for x in self.content])}>"
        if self.is_array:
            field = f"ARRAY<{field}>"
        return field

    def set_tags(self, value: dict) -> None:
        self._tags = value

    def get_tags(self) -> dict:
        return self._tags


class Directory:
    def __init__(self):
        """
        A class to manage interactions with file system for fetching components
        of an OCSF schema.
        """
        self.protected_fields = ["time"]

        # Have this list be generated if we care for any of the associated events.
        self.extension_objects = {
            # Commented out to avoid adding extra Linux-specific fields to simplified process object
            # "process": {
            #     "object": "objects/process.json",
            #     "base_path": "extensions/linux",
            # },
        }

        self.root = "_ocsf_lite"

        events_path = f"{self.root}/events"
        event_types = next(os.walk(events_path))[1]
        self.events = []
        for event_type in event_types:
            self.events += [
                f"{event_type}/{x.removesuffix('.json')}"
                for x in os.listdir(f"{events_path}/{event_type}")
                if x != f"{event_type}.json"
            ]

        # We have flattened OCSF-lite, so every category now extends the base
        # class. Due to a naming mishap in the original OCSF, "findings" is
        # present as a category instead of the referenced "finding", so we need
        # to add it manually.
        self.categories = ["base_event"] + list(self.fetch_json("categories.json").get("attributes", []).keys()) + ["finding"]

    def fetch_json(self, path: str):
        """
        Fetch the JSON at a specified path.
        :param path: The path to the object in the OCSF git repo. Must include the '.json'
                     extension.

        :return: A python dict generated from json on the contents read from the file
        """

        with open(f"{self.root}/{path}", "r") as f:
            return json.load(f)

    def flatten_include(self, json: dict, base_path: str = None) -> dict:
        """
        The OCSF json objects may have a '$include' attribute, indicating a list of other files
        that should be merged with this object to get a complete representation of it. These are
        used to include includes such as 'cloud' or datetime'. For our purposes, we want to
        generate tables that support all includes. This helper function iterates over the objects
        listed in '$include' and recursively flattens them before extending the current object
        with the result. The '$include' attribute is then removed.

        :param json: The OCSF object in JSON.
        :param base_path: Optional base path if we are working with an extension. By default,
                          objects are relative to the root of the repo but with extensions they
                          are nested and need a base path added.
        :return: The OCSF object with all includes merged as attributes.
        """
        includes = []
        if "$include" not in json.get("attributes", []):
            return json
        for profile in json["attributes"]["$include"]:
            if base_path is not None:
                profile = f"{base_path}/{profile}"
            profile_data = self.fetch_json(profile)
            includes.append(profile)
            for attr in profile_data["attributes"]:
                profile_data["attributes"][attr]["profile"] = profile_data.get(
                    "name", ""
                )
                if attr not in json["attributes"]:
                    json["attributes"][attr] = profile_data["attributes"][attr]
        del json["attributes"]["$include"]
        # move this out of attributes as a record now that it is no longer an action
        json["include"] = includes
        return json

    def flatten_extends(
        self, event: dict, directory: str, caller: Callable[[str], dict]
    ) -> dict:
        """
        If this event extends any other event, fetch that event and merge it in. For merging, it
        is possible the current event contains an attribute also present in the event it extends.
        In this case we merge the two attributes, prioritizing any fields defined in the current
        event over the extended event.

        :param caller: The caller used to fetch the next event/object. Eg, `self.fetch_event` or
                       `self.fetch_object`
        :param event: The event to flatten.
        :param directory: The parent directory of the event. This is needed as includes are
                          relative to the current event location (except for 'base_event')
        :return: The event with the parent objects merged in.
        """
        if "extends" in event:
            if event["extends"] in self.categories:
                extension = caller("base_event")
            else:
                if directory != "":
                    new_path = f"{directory}/{event['extends']}"
                else:
                    new_path = f"{event['extends']}"
                extension = caller(new_path)

            flattened = self.flatten_include(extension)
            attrs = flattened.get("attributes", {})
            for key in attrs:
                # we set all profile and include fields to optional that are not protected
                if key not in self.protected_fields:
                    attrs[key]["requirement"] = "optional"
            event["attributes"] = {**attrs, **event["attributes"]}
            event["include"] = list(
                set(flattened.get("include", [])) | set(event.get("include", []))
            )
        return event

    def fetch_event(self, path: str) -> (dict, List[str]):
        """
        Helper function to fetch the event.
        :param path: path to the event within events, eg: `network/dns_activity`
        :return: A tuple containing the event object as well as a list of includes that were
                 flattened in.
        """
        event = self.flatten_include(self.fetch_json(f"events/{path}.json"))
        return self.flatten_extends(event, path.split("/")[0], self.fetch_event)

    def fetch_object(self, obj: str) -> dict:
        """
        Helper function to fetch an object type. Objects represent the type that a field and could
        resolve into and in turn can contain a list of fields that they are made up of. Objects
        are the mechanism used to allow the OCSF schema to define nested types which will resolve
        into structs.

        :param obj:  The name of the object
        :return: The JSON representation of the object,
        """

        # Handle object names with spaces by converting to underscores
        obj_filename = obj.replace(" ", "_")
        
        # Special case for "network connection information" -> "network_connection_info"
        if obj_filename == "network_connection_information":
            obj_filename = "network_connection_info"
            
        event = self.fetch_json(f"objects/{obj_filename}.json")
        event = self.flatten_include(event)
        event = self.flatten_extends(event, "", self.fetch_object)

        # check to see if the object is in an extension. if it is, fetch it and merge it in.
        if obj in self.extension_objects:
            base_path = self.extension_objects[obj]["base_path"]
            file = self.extension_objects[obj]["object"]
            path = f"{base_path}/{file}"
            extended_event = self.fetch_json(path)
            extended_event = self.flatten_include(extended_event, base_path)
            event["attributes"] = {
                **event["attributes"],
                **extended_event["attributes"],
            }

        return event


class OCSFDictionary:
    def __init__(self, directory: Directory, render_comments: bool = False):
        """
        In the OCSF schema there is a common dictionary file that records the mapping between
        every object type and its constituents. A field can be looked up in the dictionary to
        find its associated type which could be another record in the dictionary, an object,
        or a primitive type.

        :param directory: The directory object used to fetch resources from.
        """
        self.comments = render_comments
        self.directory = directory
        self.data = directory.fetch_json("dictionary.json")
        self.objects = {}
        self.categories = directory.fetch_json("categories.json").get("attributes", [])

        # Re-enable extensions dictionaries to define field types, but object extensions remain disabled
        # extend the base dictionary with fields from the windows and linux extensions.
        linux = directory.fetch_json("extensions/linux/dictionary.json")
        self.data["attributes"] = {
            **linux.get("attributes", {}),
            **self.data["attributes"],
        }
        self.data["types"] = {**linux.get("types", {}), **self.data["types"]}

        windows = directory.fetch_json("extensions/windows/dictionary.json")
        self.data["attributes"] = {
            **windows.get("attributes", {}),
            **self.data["attributes"],
        }
        self.data["types"] = {**windows.get("types", {}), **self.data["types"]}

        # A list of primitive types supported directly by Databricks if a lookup returns one of
        # these we stop searching.
        self.primitive_types = {
            "integer_t": "INT",
            "string_t": "STRING",
            "boolean_t": "BOOLEAN",
            "long_t": "LONG",
            "double_t": "DOUBLE",
            "float_t": "FLOAT",
            "timestamp_t": "TIMESTAMP",
            "datetime_t": "DATETIME",
            # "object": "VARIANT",  # Removed - object should be handled as nested structure
            "json_t": "VARIANT",
            "variant_t": "VARIANT",
        }

    def try_get_object(self, name: str) -> Optional[dict]:
        """
        Helper function to try fetch an object from OCSF. Objects are cached locally as there is a
        lot of reuse in the schemas.
        :param name: The name of the object, usually found as a field type.
        :return: The object Json if it exists, otherwise None. Will raise an error if the response
                 was not a 2XX or a 404.
        """
        if name in self.objects:
            return self.objects[name]

        # otherwise, lets try find it
        try:
            obj = self.directory.fetch_object(name)
            self.objects[name] = obj
            return obj
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise e

    def get_category(self, name: str) -> str:
        """
        Helper function to find the description of a category.
        :param name: The name of the category.
        :return: The category description.
        """
        for (key, category) in self.categories.items():
            if key == name:
                return category.get("caption", "")
        return ""

    def get_uid(self, name: str) -> int:
        """
        Helper function to find the OCSF UID of a category.
        :param name: The name of the category.
        :return: The category UID.
        """
        for (key, category) in self.categories.items():
            if key == name:
                return category.get("uid", 0)
        return 0

    def build_field(
        self, field: str, description: str = "", nullable: bool = False, ancestry=None
    ):
        """
        A helper function to process a field into a Field object. Ths is a function of the
        dictionary due to how heavily it interacts with it and is intended to work on attributes
        of an even. Each attribute is given a name that is also its type. This function then looks
        up that type in the dictionary to get its associated type. The associated type could be an
        object, another dictionary type, or a primitive type. The logic here is we repeatedly look
        up the field type returned from the dictionary until either it exists in our primitive
        type list, or it can no longer be found. If it's a primitive, a FieldPrimitive is
        generated. If it cannot be found, we treat the underlying type as an object and look it up
         We then create a FieldStruct with the resulting object, recursively calling this function
         on any children fields of the object.

         Due to how fields can be nested, it is possible to enter loops where an object can contain
         a field within is structure that has the same object type. For example:

         'ldap_user -> user -> manager -> user'.

         This will result in traversal loops unless addressed.Our solution is to propose the
         following restriction: Every object within a field can only occur once. If it is
         discovered again, the subsequent lookup is treated as a JSON string. We implement this by
         recording the ancestry of a field, logging all object types that preceded the current
         field in traversal.

        :param field: The field name to look up
        :param description: An optional description of the field.
        :param ancestry: Contains a list of all fields we have seen in this traversal. If we find
                         an object that exists in this list, we have a loop.
        :return: A Field object that represents the field.
        """
        if ancestry is None:
            ancestry = []
        
        # Look up field in dictionary
        if field not in self.data.get("attributes", []):
            raise AttributeError(f"{field} is not defined in the dictionary")
        attribute = self.data["attributes"][field]
        attribute_type = self.data["attributes"][field]["type"]
        is_array = attribute.get("is_array", False)
        if description == "":
            description = (
                self.data["attributes"][field].get("description", "").replace("'", "`")
            )

        # next, cycle through types and see what the underlying 'type' is for this field. If it resolves to a primitive
        # type we can return that.
        while True:
            if attribute_type in self.primitive_types:
                return FieldPrimitive(
                    field,
                    self.primitive_types[attribute_type],
                    description,
                    is_array,
                    nullable,
                    self.comments,
                )
            if attribute_type in self.data["types"]["attributes"]:
                if "type" in self.data["types"]["attributes"][attribute_type]:
                    t = self.data["types"]["attributes"][attribute_type]["type"]
                    if t == attribute_type:
                        raise Exception(
                            f"Circular reference in dictionary for type {t}"
                        )
                    attribute_type = t
                else:
                    break
            else:
                break

        # Check to see if we have seen this type already. If so, break out and make it a VARIANT/
        if attribute_type in ancestry:
            return FieldPrimitive(field, "VARIANT", description, is_array, nullable, self.comments)
        
        # Add depth limit to prevent excessive nesting - max depth of 5 levels
        if len(ancestry) >= 5:
            return FieldPrimitive(field, "VARIANT", description, is_array, nullable, self.comments)

        # If we ended on something that is not a primitive type, then we need to see if it's an object and if not, it's
        # probably an error.
        attribute_as_object = self.try_get_object(attribute_type)
        if attribute_as_object is None:
            raise AttributeError(
                f"field {field}(-> {attribute_as_object}) is not a known type"
            )

        obj_description = attribute_as_object.get("description", "")
        obj_fields = []
        
        for obj_field_name, obj_field_attr in attribute_as_object["attributes"].items():
            # Check if the object defines a type for this field
            if isinstance(obj_field_attr, dict) and "type" in obj_field_attr:
                field_type = obj_field_attr["type"]
                # Check if it's a primitive type (including variant_t)
                if field_type in self.primitive_types:
                    obj_fields.append(
                        FieldPrimitive(
                            obj_field_name,
                            self.primitive_types[field_type],
                            obj_field_attr.get("description", "").replace("'", "`"),
                            obj_field_attr.get("is_array", False),
                            True,  # nullable
                            self.comments
                        )
                    )
                else:
                    # Has a type but not primitive, use normal build_field
                    obj_fields.append(
                        self.build_field(
                            obj_field_name, 
                            obj_field_attr.get("description", "").replace("'", "`"), 
                            True, 
                            ancestry[:] + [attribute_type]
                        )
                    )
            else:
                # No type specified in object, fall back to dictionary lookup
                obj_fields.append(
                    self.build_field(
                        obj_field_name, 
                        obj_field_attr.get("description", obj_description).replace("'", "`"), 
                        True, 
                        ancestry[:] + [attribute_type]
                    )
                )
        # Commented out to remove _dt fields from lite schema
        # obj_fields = add_timestamp_dt(obj_fields, self.comments)
        return FieldStruct(field, obj_fields, description, is_array, nullable, self.comments)


def add_timestamp_dt(fields: List[Field], tags: dict = None, comments: bool = False) -> List[Field]:
    """
    As we are supporting all profiles, this includes the datetime profile. When present, this
    profile signals that every timestamp in the event should be paired with a `_dt` version for
    storing a datetime. This is not naturally supported in the json schema in OCSF and is something
    that must be handled separately. While technically optional, we support this in all classes
    generated.

    Note, this function does not recurse down the fields supplied, it only works at the top level.
    This is done so we don't nest tags.
    :param fields: The fields to check for timestamps.
    :param tags: An optional list of tags to apply to all ned datetime fields.
    :return: The supplied list with additional fields added for each timestamp found.
    """
    new_fields = []
    for field in fields:
        if field.type() == "TIMESTAMP":
            # we need to add another primitive field
            new_field = FieldPrimitive(
                f"{field.name()}_dt", "TIMESTAMP", "", False, True, comments
            )
            if tags is not None:
                new_field.set_tags(tags)
            new_fields.append(new_field)
        new_fields.append(field)
    return new_fields


class Table:
    def __init__(self, source: str, schema: str = "", description: str ="", render_tags: bool = False):
        """
        A helper object to store the logic for creating a table schema that can be deployed in
        databricks.
        :param source: The name of the OCSF event we will generate  a table for.
        :param description: AN optional description for the table.
        """
        self.source = source
        self.schema = schema
        self.attributes = None
        self.fields = []
        self.tags = {}
        self.name = ""
        self.description = description
        self.includes = []
        self.tags = render_tags

    def build(self, directory: Directory, dictionary: OCSFDictionary):
        """
        Fetch the event associated with this table and process it, constructing all the nested
        fields it contains.
        :param directory: The directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :return:
        """
        event = directory.fetch_event(self.source)
        self.includes = event.get("include", [])

        if "attributes" not in event:
            raise Exception(f"No attributes defined in the event {self.source}")
        if self.schema != "":
            self.name = f"{self.schema}.{event.get('name', '')}"
        else:
            self.name = event.get("name", "")

        category_uid = dictionary.get_uid(event.get("extends", ""))
        class_uid = event.get("uid", 0)
        attributes = event["attributes"]

        table_attributes = []
        for name, attr in sorted(attributes.items()):
            description = attr.get("description", "").replace("'", "`")
            tags = {
                "ocsf_class_id": category_uid * 1000 + class_uid,
                "ocsf_profile": attr.get("profile", ""),
                "ocsf_class_name": event.get("caption", ""),
                "ocsf_class_category": dictionary.get_category(
                    event.get("extends", "")
                ),
                "ocsf_group": attr.get("group", ""),
                "ocsf_requirement": attr.get("requirement", ""),
            }

            # We now allow all fields to be nullable. If we want to revert to OCSF, replace the
            # `True` below with `attr.get("requirement", "") != "required"`
            field = dictionary.build_field(name, description, True)
            field.set_tags(tags)
            table_attributes.append(field)
        tags = {
            "ocsf_class_id": category_uid * 1000 + class_uid,
            "ocsf_profile": "datetime",
            "ocsf_class_name": event.get("caption", ""),
            "ocsf_class_category": dictionary.get_category(event.get("extends", "")),
            "ocsf_group": "",
            "ocsf_requirement": "optional",
        }
        # Commented out to remove _dt fields from lite schema
        # self.attributes = add_timestamp_dt(table_attributes, tags)
        self.attributes = table_attributes

    def render_delete_table(self, directory: Directory, dictionary: OCSFDictionary) -> str:
        """
        Render a DROP TABLE IF EXISTS command to remove this table.
        :param directory: The directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :return: The sql command to delete this table.
        """
        if self.attributes is None:
            self.build(directory, dictionary)
        if self.name == "":
            raise Exception("Table name cannot be empty")

        return f"DROP TABLE IF EXISTS {self.name};"

    def render_create_table(
        self, directory: Directory, dictionary: OCSFDictionary, formatted: bool = True
    ) -> str:
        """
        Render the sql 'CREATE TABLE' DDL for this table. If the table has not been built, build it.
        :param directory: The directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :param formatted: Indicator whether we should format the string into multiple lines.
        :return: The sql command to create this table.
        """
        if self.attributes is None:
            self.build(directory, dictionary)
        if self.name == "":
            raise Exception("Table name cannot be empty")

        table_rows = [
            f"CREATE TABLE IF NOT EXISTS ${{datasources.gold}}.{self.name} (",
            "    dasl_id STRING NOT NULL COMMENT 'Unique ID generated and maintained by Antimatter for data lineage from ingestion throughout all medallion layers.',",
        ]
        if formatted:
            table_rows.append(
                ",\n".join([f"    {attribute}" for attribute in self.attributes])
            )
        else:
            table_rows.append(
                ", ".join([f"{attribute}" for attribute in self.attributes])
            )

        if len(self.description) > 0:
            table_rows.append(") USING DELTA")
            table_rows.append(f"COMMENT '{self.description}';")
        else:
            table_rows.append(") USING DELTA;")

        if formatted:
            return "\n".join(table_rows)
        else:
            return " ".join(table_rows)

    def render_tags(
        self, directory: Directory, dictionary: OCSFDictionary, formatted: bool = True
    ) -> List[str]:
        """
        Generate the commands to update the table with all the tags associated with the table
        columns.

        :param directory: The directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :return:  A list of ALTER TABLE commands to add tags to all table fields.
        """
        if self.attributes is None:
            self.build(directory, dictionary)

        if self.name == "":
            raise Exception("Table name cannot be empty")

        if self.attributes is None:
            self.build(directory, dictionary)

        updates = []
        for attribute in self.attributes:
            alter_rows = [
                f"ALTER TABLE ${{datasources.gold}}.{self.name}",
                f"ALTER COLUMN {attribute.name()}",
                "SET TAGS (",
            ]
            if formatted:
                alter_rows.append(
                    ",\n".join(
                        [
                            f"  '{tag}' = '{value}'"
                            for tag, value in attribute.get_tags().items()
                        ]
                    )
                )
                alter_rows.append(");")
                updates.append("\n".join(alter_rows))
            else:
                alter_rows.append(
                    ", ".join(
                        [
                            f"'{tag}' = '{value}'"
                            for tag, value in attribute.get_tags().items()
                        ]
                    )
                )
                alter_rows.append(");")
                updates.append(" ".join(alter_rows))
        return updates

    def render_to_strings(self, directory: Directory, dictionary: OCSFDictionary) -> List[str]:
        """
        Will render the table into a series of commands. Each command gets returned as a separate string.
        :param directory: The directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :return: A list of SQL commands needed to create the table.
        """
        res = [self.render_create_table(directory, dictionary, False)]
        if self.tags:
            res += self.render_tags(
                directory, dictionary, False
            )
        return res

    def render_to_file(self, path: str, directory: Directory, dictionary: OCSFDictionary):
        """
        Will render the table and all update operations into a sql file written to the supplied
        path. Note the path should not include the file name, that is generation based on the
        table name. Additionally, a delete file will also be added to remove the resource.

        :param path: Path to the directory the file should be written to.
        :param directory: The Directory handler for fetching resources.
        :param dictionary: The OCSF dictionary used to build fields.
        :return:
        """

        table = self.render_create_table(directory, dictionary)
        with open(f"{path}/create-table-{self.name}.sql", "w") as f:
            f.write(table)
            f.write("\n")
            if self.tags:
                f.write("\n\n".join(self.render_tags(directory, dictionary)))

        # with open(f"{path}/drop-table-{self.name}.sql", "w") as f:
        #     f.write(self.render_delete_table(directory, dictionary))

    def render_to_schema(self, directory: Directory, dictionary: OCSFDictionary) -> str:
        if self.attributes is None:
            self.build(directory, dictionary)
        if self.name == "":
            raise Exception("Table name cannot be empty")
        return ",".join([attribute.schema() for attribute in self.attributes])
    
    def render_to_ai_schema(self, directory: Directory, dictionary: OCSFDictionary) -> dict:
        """
        Render table schema in a format optimized for AI prompts.
        Keeps leaf-only 'fields' for compatibility and adds 'nodes' for full path typing.
        """
        if self.attributes is None:
            self.build(directory, dictionary)
        if self.name == "":
            raise Exception("Table name cannot be empty")
        
        def walk_fields(field: Field, prefix: str = "") -> tuple[list, list]:
            """Return (fields, nodes) for the given field subtree."""
            field_path = f"{prefix}.{field.name()}" if prefix else field.name()
            nodes = [{
                "path": field_path,
                "type": field.type(),
                "description": field.description
            }]
            fields = []
            
            if isinstance(field, FieldStruct):
                for child in field.content:
                    child_fields, child_nodes = walk_fields(child, field_path)
                    fields.extend(child_fields)
                    nodes.extend(child_nodes)
            else:
                fields.append({
                    "path": field_path,
                    "type": field.type(),
                    "description": field.description
                })
            
            return fields, nodes
        
        all_fields = []
        all_nodes = []
        for attribute in self.attributes:
            fields, nodes = walk_fields(attribute)
            all_fields.extend(fields)
            all_nodes.extend(nodes)
        
        # Deduplicate nodes by path (keep first occurrence)
        node_index = {}
        for node in all_nodes:
            node_index.setdefault(node["path"], node)
        
        return {
            "event_class": self.name,
            "description": self.description,
            "fields": all_fields,
            "nodes": list(node_index.values())
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-g",
        "--generate",
        nargs=2,
        metavar=("NAME", "PATH"),
        help="Generate a OCSF schema, use 'all' to generate all",
    )
    parser.add_argument(
        "--comments",
        dest="COMMENTS",
        action="store_true",
        default=False,
        help="Enable COMMENTS generation (default: False)",
    )
    parser.add_argument(
        "--tags",
        dest="TAGS",
        action="store_true",
        default=False,
        help="Enable TAGS generation (default: False)",
    )

    parser.add_argument(
        "-s",
        "--hints",
        help="Generate schema hints for an OCSF table, use 'all' to generate all",
    )
    parser.add_argument(
        "-l", "--list", help="List supported OCSF tables", action="store_true"
    )
    parser.add_argument(
        "-m",
        "--migration",
        nargs=3,
        metavar=("NAME", "PATH", "ID"),
        help="Generate a OCSF migrations file, use 'all' to generate all. The migration number provided will be the used for the prefix. The migration file is be called `0{number}_create_ocsf_tables.yaml`",
    )
    parser.add_argument(
        "--export-ai-schema",
        metavar="PATH",
        help="Export flattened JSON schema for AI mapping (creates ocsf_lite_ai_schema.json)",
    )

    args = parser.parse_args()

    if args.list:
        print("supported OCSF tables:")
        directory = Directory()
        for event in directory.events:
            print(f"  {event}")
        return

    if args.hints:
        name = args.hints
        directory = Directory()

        if name == "all":
            tables = [x for x in directory.events]
        else:
            if name not in directory.events:
                raise Exception(
                    f"Unsupported OCSF table '{name}'. Please use '--list' to see available options."
                )
            tables = [name]

        dictionary = OCSFDictionary(directory)
        for table in tables:
            print(f"Generating schema for: {table}")
            print(Table(table).render_to_schema(directory, dictionary))
        return

    if args.generate:
        name, file_path = args.generate
        directory = Directory()

        if name == "all":
            tables = [x for x in directory.events]
        else:
            if name not in directory.events:
                raise Exception(
                    f"Unsupported OCSF table '{name}'. Please use '--list' to see available options."
                )
            tables = [name]

        dictionary = OCSFDictionary(directory, args.COMMENTS)

        for table in tables:
            print(f"Generating schema for: {table}")
            Table(table, render_tags=args.TAGS).render_to_file(file_path, directory, dictionary)
        return

    if args.migration:
        name, file_path, n = args.migration
        number = int(n)
        directory = Directory()
        migration_schema = "${datasources.gold}"

        if name == "all":
            tables = [x for x in directory.events]
        else:
            if name not in directory.events:
                raise Exception(
                    f"Unsupported OCSF table '{name}'. Please use '--list' to see available options."
                )
            tables = [name]

        dictionary = OCSFDictionary(directory)

        for table in tables:
            print(f"Generating schema for: {table}")
            migration = {
                "statements": Table(table, migration_schema).render_to_strings(
                    directory, dictionary
                )
            }
            yaml.dump(
                migration,
                open(
                    f"{file_path}/{number:03d}_create_ocsf_table_{table.replace('/', '_')}.yaml",
                    "w",
                ),
            )
            number += 1

        return
    
    if args.export_ai_schema:
        file_path = args.export_ai_schema
        directory = Directory()
        dictionary = OCSFDictionary(directory)
        
        # Export all event classes
        all_schemas = []
        for event in directory.events:
            print(f"Exporting AI schema for: {event}")
            schema = Table(event).render_to_ai_schema(directory, dictionary)
            all_schemas.append(schema)
        
        # Write to JSON file
        output_file = f"{file_path}/ocsf_lite_ai_schema.json"
        with open(output_file, 'w') as f:
            json.dump(all_schemas, f, indent=2)
        
        print(f"   Total event classes: {len(all_schemas)}")
        return


if __name__ == "__main__":
    main()
