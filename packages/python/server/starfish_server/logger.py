"""Structured logging for Starfish server operations."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

LogLevel = Literal["debug", "info", "warn", "error"]

_LEVEL_MAP = {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}


@dataclass
class LogEntry:
    """Structured log entry."""
    level: LogLevel
    message: str
    timestamp: float = field(default_factory=lambda: time.time() * 1000)
    extra: dict[str, Any] = field(default_factory=dict)


class ServerLogger:
    """Structured server logger interface."""

    def log(self, entry: LogEntry) -> None:
        raise NotImplementedError


class ConsoleLogger(ServerLogger):
    """Console logger with human-readable output."""

    def __init__(self, min_level: LogLevel = "info") -> None:
        self._min_order = list(_LEVEL_MAP.keys()).index(min_level)

    def log(self, entry: LogEntry) -> None:
        order = list(_LEVEL_MAP.keys()).index(entry.level)
        if order < self._min_order:
            return
        prefix = f"[Starfish:{entry.level.upper()}]"
        extra = f" {json.dumps(entry.extra)}" if entry.extra else ""
        print(f"{prefix} {entry.message}{extra}")


class JsonLogger(ServerLogger):
    """JSON-line logger for structured log aggregation."""

    def __init__(self, min_level: LogLevel = "info") -> None:
        self._min_order = list(_LEVEL_MAP.keys()).index(min_level)

    def log(self, entry: LogEntry) -> None:
        order = list(_LEVEL_MAP.keys()).index(entry.level)
        if order < self._min_order:
            return
        output = {"level": entry.level, "message": entry.message, "timestamp": entry.timestamp, **entry.extra}
        print(json.dumps(output))


class NoopLogger(ServerLogger):
    """No-op logger (discards all entries)."""

    def log(self, entry: LogEntry) -> None:
        pass
