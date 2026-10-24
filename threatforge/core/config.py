"""Configuration management for ThreatForge SOC platform."""

import json
from pathlib import Path
from typing import Any, Dict
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_3600 = 3600
CONST_5000 = 5000
CONST_8443 = 8443
CONST_64000 = 64000
CONST_10485760 = 10485760
CONST_67108864 = 67108864



class LoggingConfig:
    """Logging configuration with proper attribute access."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def level(self) -> str:
        return self._data.get("level", "INFO")

    @property
    def enable_console(self) -> bool:
        return self._data.get("enable_console", True)

    @property
    def enable_file(self) -> bool:
        return self._data.get("enable_file", True)

    @property
    def enable_syslog(self) -> bool:
        return self._data.get("enable_syslog", False)

    @property
    def format(self) -> str:
        return self._data.get("format", "text")

    @property
    def log_dir(self) -> str:
        return self._data.get("log_dir", "logs")

    @property
    def filename(self) -> str:
        return self._data.get("filename", "threatforge.log")

    @property
    def max_bytes(self) -> int:
        return self._data.get("max_bytes", CONST_10485760)

    @property
    def backup_count(self) -> int:
        return self._data.get("backup_count", CONST_5)

    @property
    def json_indent(self) -> int:
        return self._data.get("json_indent", 2)

    @property
    def syslog_address(self) -> str:
        return self._data.get("syslog_address", "/dev/log")


class DatabaseConfig:
    """Database configuration with proper attribute access."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def path(self) -> str:
        return self._data.get("path", "data/threatforge.db")

    @property
    def backup_path(self) -> str:
        return self._data.get("backup_path", "data/backups")

    @property
    def busy_timeout(self) -> int:
        return self._data.get("busy_timeout", CONST_5000)

    @property
    def journal_size_limit(self) -> int:
        return self._data.get("journal_size_limit", CONST_67108864)

    @property
    def cache_size(self) -> int:
        return self._data.get("cache_size", -CONST_64000)


class Config:
    """Central configuration manager for ThreatForge."""

    _instance = None
    _config: Dict[str, Any] = {}

    DEFAULT_CONFIG = {
        "server": {
            "host": "0.0.0.0",
            "port": CONST_8443,
            "debug": False,
            "cors_origins": ["*"],
        },
        "database": {
            "path": "data/threatforge.db",
            "backup_path": "data/backups",
            "backup_interval": CONST_3600,
            "busy_timeout": CONST_5000,
            "journal_size_limit": CONST_67108864,
            "cache_size": -CONST_64000,
        },
        "logging": {
            "level": "INFO",
            "enable_console": True,
            "enable_file": True,
            "enable_syslog": False,
            "format": "text",
            "log_dir": "logs",
            "filename": "threatforge.log",
            "max_bytes": CONST_10485760,
            "backup_count": CONST_5,
            "json_indent": 2,
            "syslog_address": "/dev/log",
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
            "update_interval": CONST_3600,
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
        return self.get("server.port", CONST_8443)

    @property
    def database_path(self) -> str:
        return self.get("database.path", "data/threatforge.db")

    @property
    def database(self) -> DatabaseConfig:
        return DatabaseConfig(self._config.get("database", {}))

    @property
    def logging(self) -> LoggingConfig:
        return LoggingConfig(self._config.get("logging", {}))

    @property
    def debug(self) -> bool:
        return self.get("server.debug", False)
