"""Configuration loader.

Defaults are designed to make the safe choice without configuration.
Users can override via ~/.config/nodeguard/config.toml or --config <path>.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

from pydantic import BaseModel, Field


class LlmLocalConfig(BaseModel):
    endpoint: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:7b-instruct"


class LlmCloudConfig(BaseModel):
    provider: str | None = None  # "anthropic" | "openai" | "google" | "deepseek" | "groq"
    api_key_env: str | None = None  # Env var name holding the key (BYO)
    model: str | None = None
    cost_warn_threshold_usd: float = 0.05


class LlmConfig(BaseModel):
    enabled: bool = False  # OFF by default. Conscious opt-in.
    provider: str = "local"  # local-first
    warn_before_external: bool = True
    local: LlmLocalConfig = Field(default_factory=LlmLocalConfig)
    cloud: LlmCloudConfig = Field(default_factory=LlmCloudConfig)


class ScannerConfig(BaseModel):
    default_layers: str = "0,1,2,3,4"  # Layers shipped in the current version.
    fail_on: str = "suspicious"  # "none" | "suspicious" | "malicious"


class EcosystemConfig(BaseModel):
    plugins: list[str] = Field(default_factory=lambda: ["comfyui"])


class VulnerabilityDbConfig(BaseModel):
    primary: str = "osv"  # OSV.dev — OSS por default
    secondary: str | None = None  # "snyk" (opt-in BYO key)
    socket: bool = False  # opt-in BYO key


class SemgrepConfig(BaseModel):
    enabled: bool = True
    ruleset: str = "nodeguard-rules-comfyui"


class TelemetryConfig(BaseModel):
    """Telemetry is permanently disabled by policy. Field exists for clarity."""

    enabled: bool = False  # SIEMPRE false. No se puede activar.


class UpdatesConfig(BaseModel):
    auto_check: bool = True
    auto_apply: bool = False


class Config(BaseModel):
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    ecosystem: EcosystemConfig = Field(default_factory=EcosystemConfig)
    llm: LlmConfig = Field(default_factory=LlmConfig)
    vulnerability_db: VulnerabilityDbConfig = Field(default_factory=VulnerabilityDbConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    updates: UpdatesConfig = Field(default_factory=UpdatesConfig)


def default_config_path() -> Path:
    """Return the default config path, respecting XDG_CONFIG_HOME on Linux."""
    if os.name == "nt":  # Windows
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "nodeguard" / "config.toml"


def load_config(path: Path | None = None) -> Config:
    """Load configuration from a TOML file, falling back to defaults.

    Args:
        path: Explicit path to a config file. If None, uses default location.
              If default location doesn't exist, returns Config with defaults.

    Returns:
        A validated Config instance.
    """
    if path is None:
        path = default_config_path()
        if not path.exists():
            return Config()

    with path.open("rb") as f:
        data = tomllib.load(f)

    # Enforce the immutable telemetry policy regardless of what the file says
    if "telemetry" in data:
        data["telemetry"]["enabled"] = False

    return Config(**data)
