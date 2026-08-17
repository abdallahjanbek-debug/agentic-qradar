"""The investigation output contract.

Enforced with output_config.format rather than asking for JSON in the prompt and
parsing hopefully. Structured outputs require additionalProperties: false and an
explicit `required` list on every object, and do not support numeric range or
string length constraints -- so `confidence` is a plain number here and is
range-checked after parsing.
"""

VERDICTS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATE", "INCONCLUSIVE"]

ACTIONS = [
    "CLOSE_AS_FALSE_POSITIVE",
    "ESCALATE_TO_L2",
    "MONITOR",
    "NEEDS_HUMAN_REVIEW",
]

INVESTIGATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict", "confidence", "summary", "narrative", "key_findings",
        "evidence", "indicators", "recommended_action", "mitre_techniques",
        "reasoning_gaps",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": VERDICTS},
        "confidence": {
            "type": "number",
            "description": "Confidence in the verdict, from 0.0 to 1.0.",
        },
        "summary": {
            "type": "string",
            "description": "One line an analyst can read at a glance.",
        },
        "narrative": {
            "type": "string",
            "description": "What happened and why this verdict follows from the evidence.",
        },
        "key_findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The handful of points that drove the verdict.",
        },
        "evidence": {
            "type": "array",
            "description": "Each claim tied to the events that support it.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["observation", "supporting_events"],
                "properties": {
                    "observation": {"type": "string"},
                    "supporting_events": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Indices into the provided event sample.",
                    },
                },
            },
        },
        "indicators": {
            "type": "object",
            "additionalProperties": False,
            "required": ["source_ips", "destination_ips", "usernames", "hostnames"],
            "properties": {
                "source_ips": {"type": "array", "items": {"type": "string"}},
                "destination_ips": {"type": "array", "items": {"type": "string"}},
                "usernames": {"type": "array", "items": {"type": "string"}},
                "hostnames": {"type": "array", "items": {"type": "string"}},
            },
        },
        "recommended_action": {"type": "string", "enum": ACTIONS},
        "mitre_techniques": {
            "type": "array",
            "items": {"type": "string"},
            "description": "MITRE ATT&CK technique IDs, e.g. T1110.001. May be empty.",
        },
        "reasoning_gaps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "What could not be determined from the evidence provided.",
        },
    },
}


def validate(result: dict) -> dict:
    """Post-parse checks the JSON schema cannot express."""
    confidence = result.get("confidence")
    if not isinstance(confidence, (int, float)):
        raise ValueError("confidence missing or not numeric")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("confidence {} outside 0.0-1.0".format(confidence))
    if result.get("verdict") not in VERDICTS:
        raise ValueError("unknown verdict {!r}".format(result.get("verdict")))
    return result
