"""Configuration management for ThreatForge SOC platform."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Central configuration manager for ThreatForge."""

    _instance = None
    _config: Dict[str, Any] = {}

    DEFAULT_CONFIG = {
        "server": {
            "host": "0.0.0.0",
            "port": 8443,
            "debug": False,
            "cors_origins": ["*"],
        },
        "database": {
            "path": "data/threatforge.db",
            "backup_interval": 3600,
        },
        "logging": {
            "level": "INFO",
            "file": "logs/threatforge.log",
            "max_size": 10485760,
            "backup_count": 5,
        },
        "network": {
            "interface": None,
            "capture_timeout": 60,
            "max_packets": 10000,
        },
        "alerts": {
            "email_enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "alert_email": "",
            "webhook_url": "",
        },
        "threat_intel": {
            "update_interval": 3600,
            "feeds": [],
        },
        "forensics": {
            "sandbox_enabled": False,
            "analysis_timeout": 300,
            "max_artifact_size": 104857600,
        },
    }

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self) -> None:
        config_file = Path("config.json")
        self._config = self.DEFAULT_CONFIG.copy()
        if config_file.exists():
            try:
                with open(config_file, "r") as f:
                    user_config = json.load(f)
                self._deep_merge(self._config, user_config)
            except (json.JSONDecodeError, IOError):
                pass

    def _deep_merge(self, base: dict, override: dict) -> None:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def save(self) -> None:
        config_file = Path("config.json")
        with open(config_file, "w") as f:
            json.dump(self._config, f, indent=2)

    @property
    def server_host(self) -> str:
        return self.get("server.host", "0.0.0.0")

    @property
    def server_port(self) -> int:
        return self.get("server.port", 8443)

    @property
    def database_path(self) -> str:
        return self.get("database.path", "data/threatforge.db")

    @property
    def debug(self) -> bool:
        return self.get("server.debug", False)
