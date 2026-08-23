from __future__ import annotations

from generate_ts_types import ts_type


def test_openapi_null_is_emitted_as_typescript_null_not_unknown() -> None:
    assert ts_type({"type": "null"}) == "null"
    assert ts_type({"anyOf": [{"type": "string"}, {"type": "null"}]}) == "string | null"
    assert (
        ts_type(
            {
                "anyOf": [
                    {"$ref": "#/components/schemas/EntityType"},
                    {"type": "null"},
                ]
            }
        )
        == "components['schemas']['EntityType'] | null"
    )
