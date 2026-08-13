from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OPENAPI = Path(__file__).with_name("openapi.json")
OUTPUT = Path(__file__).parent.parent / "frontend" / "src" / "api" / "schema.d.ts"


def ts_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return f"components['schemas']['{schema['$ref'].split('/')[-1]}']"
    if "anyOf" in schema:
        return " | ".join(ts_type(item) for item in schema["anyOf"])
    if "enum" in schema:
        return " | ".join(json.dumps(value) for value in schema["enum"])
    kind = schema.get("type")
    if kind == "string":
        return "string"
    if kind in {"integer", "number"}:
        return "number"
    if kind == "boolean":
        return "boolean"
    if kind == "null":
        return "null"
    if kind == "array":
        return f"Array<{ts_type(schema.get('items', {}))}>"
    if kind == "object":
        if "additionalProperties" in schema:
            value = schema["additionalProperties"]
            return f"Record<string, {ts_type(value) if isinstance(value, dict) else 'unknown'}>"
        return "Record<string, unknown>"
    return "unknown"


def generate() -> None:
    document = json.loads(OPENAPI.read_text(encoding="utf-8"))
    schemas: dict[str, Any] = document["components"]["schemas"]
    lines = [
        "// Generated from backend/openapi.json. Do not edit manually.",
        "export interface components {",
        "  schemas: {",
    ]
    for name, schema in sorted(schemas.items()):
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        if properties:
            lines.append(f"    {json.dumps(name)}: {{")
            for prop_name, prop_schema in properties.items():
                optional = "" if prop_name in required else "?"
                lines.append(f"      {json.dumps(prop_name)}{optional}: {ts_type(prop_schema)}")
            lines.append("    }")
        else:
            lines.append(f"    {json.dumps(name)}: {ts_type(schema)}")
    lines.extend(["  }", "}", ""])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    generate()
