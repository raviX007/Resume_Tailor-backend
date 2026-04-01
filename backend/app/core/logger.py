"""Structured logging for the resume-tailor service."""

import logging
import os
import sys
import json
from datetime import datetime, timezone

from app.middleware import request_id_var


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "request_id": request_id_var.get("-"),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[41m",  # Red background
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        rid = request_id_var.get("-")
        return f"{color}{timestamp} [{record.levelname:8s}]{self.RESET} {record.name} [{rid}]: {record.getMessage()}"


def setup_logger(name: str = "resume-tailor") -> logging.Logger:
    """Set up and return the application logger."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    _logger = logging.getLogger(name)
    _logger.setLevel(getattr(logging, log_level, logging.INFO))

    if _logger.handlers:
        return _logger

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ConsoleFormatter())
    _logger.addHandler(console)

    return _logger


logger = setup_logger()
