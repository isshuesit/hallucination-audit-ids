"""
Run configuration: one TOML file -> one validated RunConfig -> one run_id.

The config hash covers every setting that can change a result (data sampling,
model, temperature, prompts, detection configs, mitigation arms). It excludes
[paths]: where files live does not change results, and the dataset itself is
fingerprinted separately in the manifest.

Unknown keys are rejected, so a typo cannot silently fall back to a default.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .policy import ESCALATE_CLEAN

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "fresh_run.toml"

DETECTION_CONFIGS = ("C0", "C1", "C2", "C3")
POLICIES = ("strict", "lenient")
MITIGATION_ARMS = ("M0", "M-prompt", "M-auto", "M-auto+val", "M-gold")

# section -> {key: (type, required)}
_SCHEMA: dict[str, dict[str, tuple[type | tuple[type, ...], bool]]] = {
    "run": {"name": (str, True)},
    "data": {"per_class_cap": (int, True), "seed": (int, True), "benign_control_n": (int, True)},
    "generation": {"model": (str, True), "temperature": ((int, float), True), "prompt": (str, True),
                   "thinking_budget": (int, True)},
    "detection": {"configs": (list, True), "policies": (list, True), "escalate_clean": (str, True)},
    "mitigation": {"arms": (list, True)},
    "paths": {"raw_dir": (str, True), "runs_dir": (str, True), "cache_dir": (str, True)},
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RunConfig:
    raw: dict            # the validated TOML content (paths as written)
    base_dir: Path       # relative paths resolve against this

    # ── convenient typed accessors ──
    @property
    def name(self) -> str:
        return self.raw["run"]["name"]

    @property
    def per_class_cap(self) -> int:
        return self.raw["data"]["per_class_cap"]

    @property
    def seed(self) -> int:
        return self.raw["data"]["seed"]

    @property
    def benign_control_n(self) -> int:
        return self.raw["data"]["benign_control_n"]

    @property
    def model(self) -> str:
        return self.raw["generation"]["model"]

    @property
    def generate_prompt(self) -> str:
        return self.raw["generation"]["prompt"]

    @property
    def default_llm_params(self) -> dict:
        """Applied to every LLM call unless the caller sets its own value (D4 temperature)."""
        return {"temperature": float(self.raw["generation"]["temperature"])}

    @property
    def enforced_llm_params(self) -> dict:
        """Forced on every LLM call, overriding the caller (D13: thinking_budget)."""
        return {"thinking_config": {"thinking_budget": self.raw["generation"]["thinking_budget"]}}

    @property
    def generation_params(self) -> dict:
        """What a generation call is sent (defaults + enforced); part of every cache key."""
        return {**self.default_llm_params, **self.enforced_llm_params}

    def path(self, key: str) -> Path:
        p = Path(self.raw["paths"][key])
        return p if p.is_absolute() else (self.base_dir / p)

    @property
    def raw_dir(self) -> Path:
        return self.path("raw_dir")

    @property
    def runs_dir(self) -> Path:
        return self.path("runs_dir")

    @property
    def cache_dir(self) -> Path:
        return self.path("cache_dir")

    # ── identity ──
    def experiment_settings(self) -> dict:
        """Everything that can change a result (all sections except [paths])."""
        return {k: v for k, v in self.raw.items() if k != "paths"}

    @property
    def config_hash(self) -> str:
        blob = json.dumps(self.experiment_settings(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @property
    def run_id(self) -> str:
        return f"{self.name}-{self.config_hash[:8]}"


def _validate(raw: dict) -> None:
    unknown_sections = set(raw) - set(_SCHEMA)
    if unknown_sections:
        raise ConfigError(f"Unknown config section(s): {sorted(unknown_sections)}")
    for section, fields in _SCHEMA.items():
        values = raw.get(section)
        if not isinstance(values, dict):
            raise ConfigError(f"Missing config section [{section}]")
        unknown = set(values) - set(fields)
        if unknown:
            raise ConfigError(f"Unknown key(s) in [{section}]: {sorted(unknown)}")
        for key, (typ, required) in fields.items():
            if key not in values:
                if required:
                    raise ConfigError(f"Missing required key [{section}].{key}")
                continue
            v = values[key]
            if isinstance(v, bool) or not isinstance(v, typ):
                raise ConfigError(f"[{section}].{key} has the wrong type: {v!r}")

    if not raw["run"]["name"].replace("_", "").replace("-", "").isalnum():
        raise ConfigError("[run].name may contain only letters, digits, '-' and '_'")
    if raw["data"]["per_class_cap"] < 1:
        raise ConfigError("[data].per_class_cap must be >= 1")
    if raw["data"]["benign_control_n"] < 0:
        raise ConfigError("[data].benign_control_n must be >= 0")
    if raw["generation"]["thinking_budget"] < 0:
        raise ConfigError("[generation].thinking_budget must be >= 0 (D13 pins it explicitly)")
    if not 0.0 <= raw["generation"]["temperature"] <= 2.0:
        raise ConfigError("[generation].temperature must be between 0 and 2")
    for key, allowed in (("configs", DETECTION_CONFIGS), ("policies", POLICIES)):
        bad = [x for x in raw["detection"][key] if x not in allowed]
        if bad or not raw["detection"][key]:
            raise ConfigError(f"[detection].{key} must be a non-empty subset of {allowed}; got {bad or '[]'}")
    if raw["detection"]["escalate_clean"] not in ESCALATE_CLEAN:
        raise ConfigError(f"[detection].escalate_clean must be one of {ESCALATE_CLEAN}")
    bad = [x for x in raw["mitigation"]["arms"] if x not in MITIGATION_ARMS]
    if bad:
        raise ConfigError(f"[mitigation].arms must be a subset of {MITIGATION_ARMS}; got {bad}")


def config_from_dict(raw: dict, base_dir: Path = PROJECT_ROOT) -> RunConfig:
    raw = copy.deepcopy(raw)
    _validate(raw)
    return RunConfig(raw=raw, base_dir=Path(base_dir))


def load_run_config(path: Path | str = DEFAULT_CONFIG_PATH, base_dir: Path = PROJECT_ROOT) -> RunConfig:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return config_from_dict(raw, base_dir)
