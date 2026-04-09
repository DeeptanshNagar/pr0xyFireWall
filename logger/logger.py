"""
Logging Module

Structured logging system for the proxy firewall.
Logs all requests with timestamp, client info, decision, and reason.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime
from enum import Enum
from typing import Optional, TextIO

# Handle imports with fallback
try:
    from engine.decision_engine import Decision, DecisionResult
    from parser.request_parser import Request
except ImportError:
    import sys
    sys.path.insert(0, '..')
    from engine.decision_engine import Decision, DecisionResult
    from parser.request_parser import Request


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class ProxyLogger:
    """
    Thread-safe logger for the proxy firewall.
    
    Outputs structured logs in clean format:
    [ALLOW] 192.168.1.10 GET /home
    [BLOCK] 192.168.1.10 POST /admin (Reason: Sensitive endpoint)
    """
    
    # Color codes for terminal output
    COLORS = {
        "ALLOW": "\033[92m",      # Green
        "BLOCK": "\033[91m",      # Red
        "INFO": "\033[94m",       # Blue
        "WARNING": "\033[93m",    # Yellow
        "ERROR": "\033[91m",      # Red
        "RESET": "\033[0m",       # Reset
        "GRAY": "\033[90m"        # Gray for timestamps
    }
    
    def __init__(
        self,
        output: TextIO = sys.stdout,
        use_colors: bool = True,
        min_level: LogLevel = LogLevel.INFO,
        show_timestamp: bool = True
    ):
        """
        Initialize logger.
        
        Args:
            output: Output stream (default: stdout)
            use_colors: Enable colored output
            min_level: Minimum log level to display
            show_timestamp: Show timestamps in logs
        """
        self.output = output
        self.use_colors = use_colors and hasattr(output, 'isatty') and output.isatty()
        self.min_level = min_level
        self.show_timestamp = show_timestamp
        self._lock = threading.Lock()
        self._request_count = 0
        self._blocked_count = 0
        self._allowed_count = 0
    
    def _color(self, color_name: str) -> str:
        """Get color code if colors enabled."""
        if self.use_colors:
            return self.COLORS.get(color_name, "")
        return ""
    
    def _reset(self) -> str:
        """Get reset code if colors enabled."""
        return self._color("RESET")
    
    def _format_timestamp(self) -> str:
        """Format current timestamp."""
        now = datetime.now()
        return f"{self._color('GRAY')}[{now.strftime('%Y-%m-%d %H:%M:%S')}] {self._reset()}"
    
    def _write(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        """Thread-safe write to output."""
        if level.value < self.min_level.value:
            return
        
        with self._lock:
            prefix = ""
            if self.show_timestamp:
                prefix = self._format_timestamp()
            
            self.output.write(f"{prefix}{message}\n")
            self.output.flush()
    
    def log_request(
        self,
        client_ip: str,
        method: str,
        path: str,
        decision: Decision | str,
        reason: str = "",
        score: int = 0
    ) -> None:
        """
        Log a request with its decision.
        
        Args:
            client_ip: Client IP address
            method: HTTP method
            path: Request path
            decision: ALLOW or BLOCK
            reason: Reason for block (if applicable)
            score: Threat score
        """
        # Update counters
        with self._lock:
            self._request_count += 1
            if isinstance(decision, Decision):
                if decision == Decision.ALLOW:
                    self._allowed_count += 1
                else:
                    self._blocked_count += 1
            else:
                if decision == "ALLOW":
                    self._allowed_count += 1
                else:
                    self._blocked_count += 1
        
        # Format decision string
        decision_str = decision.name if isinstance(decision, Decision) else decision
        
        # Build log message
        color = self._color("ALLOW") if decision_str == "ALLOW" else self._color("BLOCK")
        
        message = f"{color}[{decision_str}]{self._reset()} {client_ip} {method} {path}"
        
        # Add reason for blocked requests
        if decision_str == "BLOCK" and reason:
            message += f" {self._color('GRAY')}(Reason: {reason}){self._reset()}"
        
        # Add score if non-zero
        if score > 0:
            message += f" {self._color('GRAY')}[Score: {score}]{self._reset()}"
        
        self._write(message, LogLevel.INFO)
    
    def log_decision_result(
        self,
        client_ip: str,
        method: str,
        path: str,
        result: DecisionResult
    ) -> None:
        """
        Log a request using a DecisionResult object.
        
        Args:
            client_ip: Client IP address
            method: HTTP method
            path: Request path
            result: DecisionResult from decision engine
        """
        self.log_request(
            client_ip=client_ip,
            method=method,
            path=path,
            decision=result.decision,
            reason=result.reason,
            score=result.score
        )
    
    def info(self, message: str) -> None:
        """Log info message."""
        colored = f"{self._color('INFO')}[INFO]{self._reset()}"
        self._write(f"{colored} {message}", LogLevel.INFO)
    
    def warning(self, message: str) -> None:
        """Log warning message."""
        colored = f"{self._color('WARNING')}[WARN]{self._reset()}"
        self._write(f"{colored} {message}", LogLevel.WARNING)
    
    def error(self, message: str) -> None:
        """Log error message."""
        colored = f"{self._color('ERROR')}[ERROR]{self._reset()}"
        self._write(f"{colored} {message}", LogLevel.ERROR)
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        if self.min_level.value <= LogLevel.DEBUG.value:
            self._write(f"[DEBUG] {message}", LogLevel.DEBUG)
    
    def startup(self, port: int, config: Optional[dict] = None) -> None:
        """Log startup message."""
        banner = f"""
{self._color('INFO')}╔══════════════════════════════════════════════════════════════╗
║                      pr0xywall Firewall                      ║
║               Layer 7 Application-Level Proxy                ║
╚══════════════════════════════════════════════════════════════╝{self._reset()}
        """
        self._write(banner, LogLevel.INFO)
        self.info(f"Proxy server starting on port {port}")
        
        if config:
            for key, value in config.items():
                self.info(f"  {key}: {value}")
        
        self.info("Waiting for connections...")
        self._write("-" * 60, LogLevel.INFO)
    
    def shutdown(self) -> None:
        """Log shutdown message with statistics."""
        self._write("-" * 60, LogLevel.INFO)
        self.info("Proxy server shutting down")
        
        with self._lock:
            stats = f"""
{self._color('INFO')}Statistics:{self._reset()}
  Total requests: {self._request_count}
  Allowed: {self._allowed_count}
  Blocked: {self._blocked_count}
  Block rate: {(self._blocked_count / max(self._request_count, 1) * 100):.1f}%
            """
            self._write(stats, LogLevel.INFO)
    
    def get_stats(self) -> dict:
        """Get logging statistics."""
        with self._lock:
            return {
                "total_requests": self._request_count,
                "allowed": self._allowed_count,
                "blocked": self._blocked_count,
                "block_rate": self._blocked_count / max(self._request_count, 1)
            }


# Global logger instance for convenience
_default_logger: Optional[ProxyLogger] = None


def get_logger() -> ProxyLogger:
    """Get or create default logger instance."""
    global _default_logger
    if _default_logger is None:
        _default_logger = ProxyLogger()
    return _default_logger


def set_logger(logger: ProxyLogger) -> None:
    """Set the default logger instance."""
    global _default_logger
    _default_logger = logger
