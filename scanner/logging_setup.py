"""Structured logging helpers.

Every scan log line is emitted as single-line JSON containing at least
``event``, ``content_hash``, ``policy_version``, ``decision`` and
``basis`` so judgments are explainable and greppable.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("scanner")
    if not any(getattr(h, "_scanner_handler", False) for h in root.handlers):
        handler._scanner_handler = True  # type: ignore[attr-defined]
        root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith("scanner") else f"scanner.{name}")


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured event with arbitrary fields (hash/version/basis...)."""
    logger.info(event, extra={"extra_fields": fields})
