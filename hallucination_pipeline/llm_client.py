"""
Gemini LLM client wrapper: retry logic, rate-limit handling, JSON parsing.

This module needs a real GEMINI_API_KEY to actually call the model - that
part cannot be tested in an offline sandbox. What CAN and IS tested without
a live key: the retry-delay parsing logic and JSON-fence stripping (see
tests/test_llm_client.py), since those are pure string/data functions with
no network dependency.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import types
from datetime import datetime, timezone
from pathlib import Path

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

        except CallLimitReached:
            raise

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


# ── content-addressed LLM cache ───────────────────────────────────────────
#
# Every call is keyed by SHA-256(model, params, prompt). The raw response text,
# the model version string the API reports, and token usage are appended to a
# jsonl file as soon as they arrive, so (a) a crashed run resumes for free and
# (b) re-running the same config makes zero API calls. Errors are never cached
# (a retry must reach the API), and neither are empty responses.

def params_to_dict(cfg) -> dict:
    """Turn a generate_content `config` (None, dict, google.genai pydantic model,
    or the test fake's object) into plain JSON data for hashing and logging."""
    if cfg is None:
        return {}
    if isinstance(cfg, dict):
        return {k: params_to_dict(v) if not isinstance(v, (str, int, float, bool, list, type(None))) else v
                for k, v in cfg.items()}
    if hasattr(cfg, "model_dump"):
        return cfg.model_dump(exclude_none=True, mode="json")
    if hasattr(cfg, "kw"):  # tests/fakes.py stand-in for GenerateContentConfig
        return params_to_dict(dict(cfg.kw))
    raise TypeError(f"Cannot serialise LLM call config of type {type(cfg).__name__}")


def cache_key(model: str, params: dict, prompt: str) -> str:
    blob = json.dumps({"model": model, "params": params, "prompt": prompt}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _usage_dict(usage) -> dict:
    fields = ("prompt_token_count", "candidates_token_count", "thoughts_token_count", "total_token_count")
    return {f: int(getattr(usage, f, 0) or 0) for f in fields}


class LLMCache:
    """Append-only jsonl store: one line per successful LLM call."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.entries: dict[str, dict] = {}
        self.skipped_lines = 0
        if self.path.exists():
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        self.entries[entry["key"]] = entry
                    except (json.JSONDecodeError, KeyError):
                        self.skipped_lines += 1   # e.g. a line cut short by a crash
            if self.skipped_lines:
                print(f"    LLM cache: skipped {self.skipped_lines} unreadable line(s) in {self.path}")

    def get(self, key: str) -> dict | None:
        return self.entries.get(key)

    def put(self, entry: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
        self.entries[entry["key"]] = entry


class CachedResponse:
    """What a cache hit returns: looks like a google.genai response."""

    def __init__(self, entry: dict):
        self.text = entry["text"]
        self.model_version = entry.get("model_version")
        self.usage_metadata = types.SimpleNamespace(**entry.get("usage", {}))
        self.cache_key = entry["key"]
        self.cache_hit = True


class CallLimitReached(RuntimeError):
    """Raised before an API call that would exceed the run's max_calls. The retry loops in this
    module re-raise it instead of retrying, so a run stops cleanly; the cache keeps every answer
    received, so re-running continues where it stopped."""


class DryRunResponse:
    """Returned for a call that is not in the cache during a dry run: no API call is made."""

    text = "{}"
    model_version = None
    usage_metadata = None
    dry = True
    cache_hit = False
    cache_key = None
    call_params = None


def _is_rate_limit(exc: Exception) -> bool:
    return "429" in str(exc) or "RESOURCE_EXHAUSTED" in str(exc)


_STAGE_FIELDS = ("api_calls", "api_errors", "rate_limit_errors", "cache_hits", "would_call")


class CachedClient:
    """Drop-in replacement for genai.Client that caches every call.

    `default_params` (e.g. {"temperature": 0.0}) are merged under any config the
    caller passes; `enforced_params` (e.g. {"thinking_config": {"thinking_budget": 0}},
    DECISIONS D13) are merged over it, so they hold for every call whatever the caller
    asked for. The final params are part of every cache key, stored with every cache
    entry, and returned on the response as `call_params`.

    `stage` (set by the runner) labels the counts: per stage, API calls, errors, rate-limit
    errors (each one is a wait), cache hits, tokens. `max_calls` stops the run with
    CallLimitReached before the call that would exceed it. `dry_run` makes no API call at all:
    cache hits are served as usual, every other distinct call is counted as `would_call` and
    answered with a DryRunResponse.
    """

    def __init__(self, inner, cache: LLMCache, default_params: dict | None = None,
                 enforced_params: dict | None = None, *, max_calls: int | None = None, dry_run: bool = False):
        self.inner = inner
        self.cache = cache
        self.default_params = dict(default_params or {})
        self.enforced_params = dict(enforced_params or {})
        self.max_calls = max_calls
        self.dry_run = dry_run
        self.enforced_overrides = 0     # calls whose own config disagreed with an enforced param
        self.models = self          # so callers can keep writing client.models.generate_content(...)
        self.stage = "unstaged"
        self.per_stage: dict[str, dict] = {}
        self._dry_keys: set[str] = set()
        self.model_versions: set[str] = set()
        self.models_requested: set[str] = set()

    def _counts(self) -> dict:
        if self.stage not in self.per_stage:
            self.per_stage[self.stage] = {**{f: 0 for f in _STAGE_FIELDS},
                                          "tokens": {"prompt_token_count": 0, "candidates_token_count": 0,
                                                     "thoughts_token_count": 0, "total_token_count": 0}}
        return self.per_stage[self.stage]

    def _total(self, field: str) -> int:
        return sum(s[field] for s in self.per_stage.values())

    @property
    def api_calls(self) -> int:
        return self._total("api_calls")

    @property
    def api_errors(self) -> int:
        return self._total("api_errors")

    @property
    def cache_hits(self) -> int:
        return self._total("cache_hits")

    @property
    def tokens(self) -> dict:
        out = {"prompt_token_count": 0, "candidates_token_count": 0, "thoughts_token_count": 0,
               "total_token_count": 0}
        for s in self.per_stage.values():
            for k, v in s["tokens"].items():
                out[k] += v
        return out

    def generate_content(self, model: str, contents: str, config=None):
        counts = self._counts()
        requested = params_to_dict(config)
        if any(k in requested and requested[k] != v for k, v in self.enforced_params.items()):
            self.enforced_overrides += 1
        params = {**self.default_params, **requested, **self.enforced_params}
        key = cache_key(model, params, contents)
        self.models_requested.add(model)
        hit = self.cache.get(key)
        if hit is not None:
            counts["cache_hits"] += 1
            if hit.get("model_version"):
                self.model_versions.add(hit["model_version"])
            response = CachedResponse(hit)
            response.call_params = hit["params"]
            return response
        if self.dry_run:
            if key not in self._dry_keys:           # an identical later call would be a cache hit
                self._dry_keys.add(key)
                counts["would_call"] += 1
            return DryRunResponse()
        if self.max_calls is not None and self.api_calls >= self.max_calls:
            raise CallLimitReached(f"max_calls = {self.max_calls} reached in stage {self.stage!r}")

        counts["api_calls"] += 1
        try:
            response = self.inner.models.generate_content(model=model, contents=contents, config=params or None)
        except Exception as e:
            counts["api_errors"] += 1
            if _is_rate_limit(e):
                counts["rate_limit_errors"] += 1
            raise
        usage = _usage_dict(getattr(response, "usage_metadata", None))
        for k, v in usage.items():
            counts["tokens"][k] += v
        version = getattr(response, "model_version", None)
        if version:
            self.model_versions.add(version)
        if getattr(response, "text", None):
            self.cache.put({
                "key": key, "model": model, "params": params,
                "prompt_sha256": hashlib.sha256(contents.encode("utf-8")).hexdigest(),
                "prompt": contents, "text": response.text, "model_version": version, "usage": usage,
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
        response.cache_key = key
        response.cache_hit = False
        response.call_params = params
        return response

    def stats(self) -> dict:
        return {
            "api_calls": self.api_calls, "api_errors": self.api_errors, "cache_hits": self.cache_hits,
            "rate_limit_errors": self._total("rate_limit_errors"),
            "tokens": self.tokens,
            "per_stage": {k: {**v, "tokens": dict(v["tokens"])} for k, v in self.per_stage.items()},
            "max_calls": self.max_calls,
            "models_requested": sorted(self.models_requested),
            "model_versions_returned": sorted(self.model_versions),
            "default_params": self.default_params,
            "enforced_params": self.enforced_params,
            "enforced_overrides": self.enforced_overrides,
        }


MAX_RATE_LIMIT_WAITS = 20


def generate_text(client, model: str, prompt: str, *, sleep: bool = True) -> tuple[object | None, list[str]]:
    """One generation call with retries. Returns (response or None, list of error messages).
    429 rate limits wait for the API's retryDelay and do not use up an attempt
    (but at most MAX_RATE_LIMIT_WAITS of them, so a dead quota cannot hang the run)."""
    errors: list[str] = []
    attempt = 0
    while attempt < config.MAX_RETRIES and len(errors) - attempt < MAX_RATE_LIMIT_WAITS:
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            if not getattr(response, "text", None):
                raise ValueError("empty response text")
            return response, errors
        except CallLimitReached:
            raise
        except Exception as e:  # noqa: BLE001
            err = str(e)
            errors.append(err[:200])
            if "429" in err or "RESOURCE_EXHAUSTED" in err:
                if sleep:
                    time.sleep(extract_retry_delay(e))
                continue
            attempt += 1
            if attempt < config.MAX_RETRIES and sleep:
                time.sleep(config.RETRY_DELAY_SECONDS * attempt)
    return None, errors
