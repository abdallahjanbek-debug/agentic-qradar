"""Anthropic provider.

Request parameters are built PER MODEL. claude-haiku-4-5 predates
output_config.effort and adaptive thinking and returns a 400 if either is sent, so
the triage gate and the deep investigation cannot share a parameter block.
"""

import json

from qpylib import qpylib

from .. import config
from . import schema

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LLMError(Exception):
    pass


class RefusalError(LLMError):
    """Safety classifiers declined the request.

    Returned as HTTP 200 with stop_reason == "refusal", not an exception -- SOC
    triage prompts are exactly the shape that trips cyber-category classifiers, so
    this is checked before reading response content.
    """


class AnthropicProvider:

    def __init__(self, api_key: str):
        import anthropic  # imported lazily so the app loads without the dep vendored
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key)

    # ── validation ──────────────────────────────────────────────────────────

    def validate(self) -> dict:
        """Authenticate the key without spending tokens, and return the model list.

        Distinguishes three outcomes so a locked-down console is diagnosable:
        network/proxy unreachable, key rejected, valid.
        """
        try:
            page = self.client.models.list()
            models = [m.id for m in page]
            return {"ok": True, "status": "valid", "models": models}
        except self._anthropic.AuthenticationError as error:
            return {"ok": False, "status": "key_rejected", "detail": str(error)}
        except self._anthropic.PermissionDeniedError as error:
            return {"ok": False, "status": "key_rejected", "detail": str(error)}
        except self._anthropic.APIConnectionError as error:
            return {"ok": False, "status": "unreachable", "detail": str(error)}
        except Exception as error:
            return {"ok": False, "status": "error", "detail": str(error)}

    # ── requests ────────────────────────────────────────────────────────────

    def _build_params(self, model: str, max_tokens: int, effort: str,
                      output_schema: dict) -> dict:
        params = {
            "model": model,
            "max_tokens": max_tokens,
            "output_config": {
                "format": {"type": "json_schema", "schema": output_schema}
            },
        }
        if not config.uses_legacy_params(model):
            params["output_config"]["effort"] = effort
            params["thinking"] = {"type": "adaptive"}
        return params

    def investigate(self, system_prompt: str, user_content: str, model: str,
                    max_tokens: int, effort: str, fallbacks_enabled: bool) -> tuple:
        """Run one investigation. Returns (result_dict, usage_dict, raw_response)."""
        params = self._build_params(model, max_tokens, effort,
                                    schema.INVESTIGATION_SCHEMA)
        params["system"] = [
            {
                "type": "text",
                "text": system_prompt,
                # The stable prefix ends here. Everything offense-specific is in
                # the user turn below.
                "cache_control": {"type": "ephemeral"},
            }
        ]
        params["messages"] = [{"role": "user", "content": user_content}]

        if fallbacks_enabled and not config.uses_legacy_params(model):
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
            response = self.client.beta.messages.create(**params)
        else:
            response = self.client.messages.create(**params)

        usage = self._usage(response, model, effort)

        if response.stop_reason == "refusal":
            detail = ""
            if getattr(response, "stop_details", None):
                detail = getattr(response.stop_details, "category", "") or ""
            raise RefusalError("declined by safety classifiers ({})".format(detail))

        if response.stop_reason == "max_tokens":
            raise LLMError("response truncated at max_tokens; output is not valid JSON")

        text = next((b.text for b in response.content if b.type == "text"), None)
        if not text:
            raise LLMError("no text block in response (stop_reason={})".format(
                response.stop_reason))

        try:
            result = schema.validate(json.loads(text))
        except (ValueError, TypeError) as error:
            raise LLMError("invalid investigation payload: {}".format(error))

        return result, usage, text

    # ── usage / cost ────────────────────────────────────────────────────────

    @staticmethod
    def _usage(response, model: str, effort: str) -> dict:
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0

        served_by = getattr(response, "model", model)
        price_in, price_out = config.PRICING.get(served_by, config.PRICING.get(model, (0, 0)))
        # Cached input bills at roughly 0.1x.
        billable_in = input_tokens + cache_read * 0.1
        cost_micros = int(
            (billable_in / 1_000_000.0 * price_in + output_tokens / 1_000_000.0 * price_out)
            * 1_000_000
        )

        if cache_read == 0 and input_tokens > 2000:
            qpylib.log(
                "socai: no cache read on a large prompt -- check for a volatile "
                "value in the system prefix",
                level="WARNING",
            )

        return {
            "model": model,
            "served_by_model": served_by,
            "effort": None if config.uses_legacy_params(model) else effort,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read,
            "cost_usd_micros": cost_micros,
            "stop_reason": getattr(response, "stop_reason", None),
        }
