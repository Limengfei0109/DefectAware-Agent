from typing import Dict, List, Tuple


def validate_schema(value, schema: Dict, path: str = "$") -> List[str]:
    """Validate the JSON Schema subset used by Agent tool definitions."""
    errors: List[str] = []
    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
    }
    if expected_type and not type_matches.get(expected_type, True):
        return [f"{path}: expected {expected_type}"]

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: value is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: value is above maximum")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}.{name}: required property is missing")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{path}.{name}: additional property is not allowed")
        for name, item in value.items():
            if name in properties:
                errors.extend(validate_schema(item, properties[name], f"{path}.{name}"))

    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(validate_schema(item, schema["items"], f"{path}[{index}]"))
    return errors


def validate_tool_call(call: Dict, schemas: List[Dict]) -> Tuple[bool, List[str]]:
    name = str(call.get("name", ""))
    schema = next((item for item in schemas if item.get("name") == name), None)
    if schema is None:
        return False, [f"Unknown or unavailable tool: {name}"]
    args = call.get("args", {})
    errors = validate_schema(args, schema.get("parameters", {}), "$.args")
    return not errors, errors
