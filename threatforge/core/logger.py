"""
Structured logging module for ThreatForge SOC platform.

Provides JSON-formatted logging with rotation, multiple outputs
(console, file, syslog), and structured metadata.
"""

import json
import logging
import logging.handlers
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from threatforge.core.config import Config


class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON."""

    def __init__(self, indent: Optional[int] = None):
        super().__init__()
        self.indent = indent

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
            "process": record.process,
        }

        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        return json.dumps(log_entry, default=str, indent=self.indent)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)
        logger_name = record.name
        message = record.getMessage()

        if self.use_colors and sys.stderr.isatty():
            color = self.COLORS.get(record.levelname, "")
            level = f"{color}{level}{self.RESET}"

        parts = [timestamp, level, f"[{logger_name}]", message]

        if record.exc_info and record.exc_info[1]:
            parts.append(f"\n{traceback.format_exception(*record.exc_info)}")

        return " ".join(parts)


class Logger:
    """
    Centralized logger for ThreatForge.

    Supports structured JSON logging, console output with colors,
    file rotation, and optional syslog forwarding.
    """

    def __init__(self, name: str = "threatforge", config: Optional[Config] = None):
        self.config = config or Config()
        self.name = name
        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, self.config.logging.level.upper()))
        self._logger.propagate = False

        if not self._logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Configure all log handlers based on config."""
        log_config = self.config.logging

        if log_config.enable_console:
            self._add_console_handler(log_config)

        if log_config.enable_file:
            self._add_file_handler(log_config)

        if log_config.enable_syslog:
            self._add_syslog_handler(log_config)

    def _add_console_handler(self, log_config: Any) -> None:
        """Add console handler with color support."""
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(getattr(logging, log_config.level.upper()))

        if log_config.format == "json":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(TextFormatter(use_colors=True))

        self._logger.addHandler(handler)

    def _add_file_handler(self, log_config: Any) -> None:
        """Add rotating file handler."""
        log_dir = Path(log_config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / log_config.filename

        handler = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=log_config.max_bytes,
            backupCount=log_config.backup_count,
            encoding="utf-8",
        )
        handler.setLevel(getattr(logging, log_config.level.upper()))
        handler.setFormatter(JSONFormatter(indent=log_config.json_indent))

        self._logger.addHandler(handler)

    def _add_syslog_handler(self, log_config: Any) -> None:
        """Add syslog handler."""
        handler = logging.handlers.SysLogHandler(
            address=log_config.syslog_address,
        )
        handler.setLevel(getattr(logging, log_config.level.upper()))
        handler.setFormatter(JSONFormatter())

        self._logger.addHandler(handler)

    def _log(self, level: int, message: str, **kwargs: Any) -> None:
        """Internal logging method with extra data support."""
        extra = {}
        if kwargs:
            extra["extra_data"] = kwargs

        self._logger.log(level, message, extra=extra, exc_info=False)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a debug message."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log an info message."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning message."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log an error message."""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log a critical message."""
        self._log(logging.CRITICAL, message, **kwargs)

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log an error with exception info."""
        extra = {}
        if kwargs:
            extra["extra_data"] = kwargs

        self._logger.exception(message, extra=extra)

    def child(self, name: str) -> "Logger":
        """Create a child logger with a sub-name."""
        child_config = Config()
        child_config.logging = self.config.logging
        return Logger(f"{self.name}.{name}", child_config)

    def set_level(self, level: str) -> None:
        """Change the log level at runtime."""
        self._logger.setLevel(getattr(logging, level.upper()))

    def add_context(self, **context: Any) -> logging.LoggerAdapter:
        """Return a logger adapter with default context fields."""
        return logging.LoggerAdapter(self._logger, context)

    def log_incident(self, incident_id: str, action: str, description: str = "") -> None:
        """Log an incident action."""
        self.info(
            f"Incident {action}: {description}",
            incident_id=incident_id,
            action=action,
        )

    def log_threat(self, threat_type: str, value: str, confidence: int = 0) -> None:
        """Log a threat detection."""
        self.warning(
            f"Threat detected: {threat_type} - {value} (confidence: {confidence}%)",
            threat_type=threat_type,
            value=value,
            confidence=confidence,
        )

    def log_forensics(self, artifact_name: str, action: str) -> None:
        """Log a forensics action."""
        self.info(
            f"Forensics: {action} on {artifact_name}",
            artifact=artifact_name,
            action=action,
        )

    def log_server(self, message: str) -> None:
        """Log a server event."""
        self.info(message)
