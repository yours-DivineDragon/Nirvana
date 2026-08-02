from __future__ import annotations

import json
import re
import sysconfig
from functools import lru_cache
from pathlib import Path
from typing import Any


class ContractValidationError(ValueError):
    pass


@lru_cache(maxsize=None)
def _schema(name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+\.schema\.json", name):
        raise ValueError(f"unsafe schema name: {name}")
    repository_schema = Path(__file__).resolve().parents[2] / "schemas" / name
    installed_schema = (
        Path(sysconfig.get_path("data")) / "share" / "nirvana" / "schemas" / name
    )
    for candidate in (repository_schema, installed_schema):
        if candidate.is_file():
            value = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                return value
    raise ValueError(f"Nirvana runtime schema is unavailable: {name}")


def validate_contract(value: Any, name: str) -> None:
    """Validate Nirvana's supported JSON-Schema subset without runtime dependencies."""

    _validate(value, _schema(name), name, "$", name)


def _validate(value: Any, schema: dict[str, Any], schema_name: str, path: str, root: str) -> None:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        target_name, separator, fragment = reference.partition("#")
        target_name = target_name or schema_name
        target: Any = _schema(target_name)
        if separator and fragment:
            if not fragment.startswith("/"):
                _fail(path, f"unsupported schema reference: {reference}")
            for part in fragment[1:].split("/"):
                key = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or key not in target:
                    _fail(path, f"unresolved schema reference: {reference}")
                target = target[key]
        if not isinstance(target, dict):
            _fail(path, f"schema reference is not an object: {reference}")
        _validate(value, target, target_name, path, root)
        return

    if "const" in schema and value != schema["const"]:
        _fail(path, f"must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        _fail(path, f"must be one of {schema['enum']!r}")
    expected_type = schema.get("type")
    if expected_type is not None:
        types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_is_type(value, item) for item in types):
            _fail(path, f"must have type {types!r}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [item for item in required if item not in value]
        if missing:
            _fail(path, f"lacks required fields: {missing}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, item in value.items():
                child_path = f"{path}.{key}"
                if key in properties:
                    _validate(item, properties[key], schema_name, child_path, root)
                    continue
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    _fail(child_path, "is not an allowed field")
                if isinstance(additional, dict):
                    _validate(item, additional, schema_name, child_path, root)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            _fail(path, f"requires at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            _fail(path, f"allows at most {schema['maxItems']} items")
        if schema.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(set(encoded)) != len(encoded):
                _fail(path, "requires unique items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate(item, item_schema, schema_name, f"{path}[{index}]", root)
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            _fail(path, f"requires at least {schema['minLength']} characters")
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            _fail(path, f"does not match {schema['pattern']!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            _fail(path, f"must be at least {schema['minimum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            _fail(path, f"must be greater than {schema['exclusiveMinimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            _fail(path, f"must be at most {schema['maximum']}")


def _is_type(value: Any, expected: str) -> bool:
    checks = {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }
    if expected not in checks:
        raise ValueError(f"unsupported schema type in {expected!r}")
    return checks[expected]


def _fail(path: str, message: str) -> None:
    raise ContractValidationError(f"schema validation failed at {path}: {message}")
