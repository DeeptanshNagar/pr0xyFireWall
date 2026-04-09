"""
Logger module - Structured Logging

Logs all requests with timestamp, decision, and reason.
"""

from .logger import ProxyLogger, LogLevel, get_logger, set_logger

__all__ = ["ProxyLogger", "LogLevel", "get_logger", "set_logger"]
