"""
Gemini LLM client wrapper: retry logic, rate-limit handling, JSON parsing.

This module needs a real GEMINI_API_KEY to actually call the model - that
part cannot be tested in an offline sandbox. What CAN and IS tested without
a live key: the retry-delay parsing logic and JSON-fence stripping (see
tests/test_llm_client.py), since those are pure string/data functions with
no network dependency.
"""

from __future__ import annotations

import json
import re
import time

from . import config


def get_client():
    """Create a Gemini client. Requires GEMINI_API_KEY to be set."""
    from google import genai
    return genai.Client(api_key=config.get_api_key())


def get_types():
    """Return google.genai.types (imported lazily so the offline tests and
    the verification harness can run without the SDK installed)."""
    from google.genai import types as genai_types
    return genai_types


def strip_json_fence(text: str) -> str:
    """Remove markdown code-fence wrapping (```json ... ```) if present."""
    return re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL).strip()


def extract_retry_delay(exc: Exception, default: float = 30.0) -> float:
    """Parse the retryDelay Gemini's API returns inside a 429 error body.
    Error body shape: {'details': [..., {'@type': '.../RetryInfo',
    'retryDelay': '17s'}, ...]}
    Falls back to *default* seconds if parsing fails for any reason.
    """
    try:
        body = getattr(exc, "args", [{}])[0]
        if isinstance(body, str):
            body = json.loads(body)
        details = body.get("error", body).get("details", [])
        for d in details:
            delay_str = d.get("retryDelay", "")
            if delay_str:
                return float(delay_str.rstrip("s")) + 2  # small safety buffer
    except Exception:
        pass
    return default


def call_llm_for_json(client, prompt: str, fallback: dict, *, sleep: bool = True) -> dict:
    """Call Gemini, parse the JSON response, return the parsed dict.
    On unrecoverable failure, returns *fallback*.

    429 RESOURCE_EXHAUSTED is handled specially: the API's own retryDelay
    is respected and the attempt is NOT counted against MAX_RETRIES, since
    throttling isn't a failure of the call itself.
    """
    attempt = 0
    while attempt < config.MAX_RETRIES:
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL, contents=prompt
            )
            raw = strip_json_fence(response.text.strip())
            return json.loads(raw)

        except json.JSONDecodeError:
            return {
                **fallback,
                "confidence": "low",
                "reason": "Parsed from malformed Gemini response.",
                "detection_method": "llm_fallback",
                "_raw": getattr(response, "text", "")[:200],
            }

        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                wait = extract_retry_delay(e)
                if sleep:
                    print(f"    Rate-limited, sleeping {wait:.0f}s (attempt not consumed)...")
                    time.sleep(wait)
                # do NOT increment attempt - rate limiting isn't a failure
            else:
                attempt += 1
                print(f"    LLM attempt {attempt}/{config.MAX_RETRIES} failed: {err_str[:120]}")
                if attempt < config.MAX_RETRIES and sleep:
                    time.sleep(config.RETRY_DELAY_SECONDS * attempt)

    return {**fallback, "detection_method": "failed"}
