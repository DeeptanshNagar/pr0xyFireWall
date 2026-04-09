#!/usr/bin/env python3
"""
pr0xywall - Layer 7 Application-Level Proxy Firewall

A production-grade HTTP/1.1 proxy server with deep packet inspection,
rule-based filtering, rate limiting, and threat scoring.

Usage:
    python main.py --port 8080
    python main.py --port 8080 --threshold 30
    python main.py --port 8080 --rate-limit 20

Author: pr0xywall
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from typing import Optional

# Import project modules
from engine.decision_engine import DecisionEngine
from logger.logger import ProxyLogger
from proxy.server import ProxyServer
from ratelimit.limiter import RateLimitConfig, RateLimiter
from rules.rules import RuleSet, Severity


class ProxyWall:
    """
    Main application class for pr0xywall.
    
    Orchestrates all components: proxy server, decision engine,
    rate limiting, and logging.
    """
    
    VERSION = "1.0.0"
    
    def __init__(self):
        """Initialize pr0xywall application."""
        self.proxy_server: Optional[ProxyServer] = None
        self.decision_engine: Optional[DecisionEngine] = None
        self.logger: Optional[ProxyLogger] = None
        self.running = False
        
        # Configuration
        self.config = {
            "host": "0.0.0.0",
            "port": 8080,
            "threshold": 25,
            "rate_limit": 10,
            "burst_size": 20,
            "block_duration": 60,
            "colors": True
        }
    
    def setup(
        self,
        port: int = 8080,
        threshold: int = 25,
        rate_limit: float = 10.0,
        burst_size: int = 20,
        block_duration: int = 60,
        colors: bool = True
    ) -> None:
        """
        Setup pr0xywall with configuration.
        
        Args:
            port: Proxy listen port
            threshold: Rule scoring threshold for blocking
            rate_limit: Requests per second limit
            burst_size: Burst request limit
            block_duration: Seconds to block after limit exceeded
            colors: Enable colored output
        """
        self.config.update({
            "port": port,
            "threshold": threshold,
            "rate_limit": rate_limit,
            "burst_size": burst_size,
            "block_duration": block_duration,
            "colors": colors
        })
        
        # Setup logger
        self.logger = ProxyLogger(use_colors=colors)
        
        # Setup rate limiter
        rate_config = RateLimitConfig(
            requests_per_second=rate_limit,
            burst_size=burst_size,
            block_duration=block_duration
        )
        rate_limiter = RateLimiter(config=rate_config)
        
        # Setup rule set with threshold
        rule_set = RuleSet(score_threshold=threshold)
        
        # Setup decision engine
        self.decision_engine = DecisionEngine(
            rule_set=rule_set,
            rate_limiter=rate_limiter,
            enable_rate_limiting=True
        )
        
        # Setup proxy server
        self.proxy_server = ProxyServer(
            host=self.config["host"],
            port=port,
            decision_engine=self.decision_engine,
            logger=self.logger
        )
        
        self.running = True
    
    def run(self) -> None:
        """Run the proxy server."""
        if not self.proxy_server:
            raise RuntimeError("ProxyWall not setup. Call setup() first.")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Print startup info
        self._print_startup_info()
        
        try:
            self.proxy_server.start()
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Fatal error: {e}")
            raise
    
    def shutdown(self) -> None:
        """Shutdown pr0xywall gracefully."""
        self.running = False
        
        if self.logger:
            self.logger.info("Shutting down pr0xywall...")
        
        if self.proxy_server:
            self.proxy_server.stop()
        
        sys.exit(0)
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        if self.logger:
            self.logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()
    
    def _print_startup_info(self) -> None:
        """Print startup configuration."""
        if not self.logger:
            return
        
        self.logger.info(f"pr0xywall v{self.VERSION}")
        self.logger.info(f"Configuration:")
        self.logger.info(f"  Listen port: {self.config['port']}")
        self.logger.info(f"  Score threshold: {self.config['threshold']}")
        self.logger.info(f"  Rate limit: {self.config['rate_limit']} req/sec")
        self.logger.info(f"  Burst size: {self.config['burst_size']}")
        self.logger.info(f"  Block duration: {self.config['block_duration']}s")
        
        # Print rule summary
        if self.decision_engine:
            summary = self.decision_engine.get_rule_summary()
            self.logger.info(f"Rules loaded: {summary['total_rules']} total, "
                           f"{summary['enabled_rules']} enabled")
    
    def get_stats(self) -> dict:
        """Get application statistics."""
        stats = {
            "version": self.VERSION,
            "running": self.running,
            "config": self.config
        }
        
        if self.proxy_server:
            stats["server"] = self.proxy_server.get_stats()
        
        if self.decision_engine and self.decision_engine.rate_limiter:
            stats["rate_limiter"] = self.decision_engine.rate_limiter.get_summary()
        
        if self.logger:
            stats["logging"] = self.logger.get_stats()
        
        return stats


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="pr0xywall",
        description="Layer 7 Application-Level Proxy Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Run on default port 8080
  python main.py --port 9090              # Run on port 9090
  python main.py --threshold 30           # Set score threshold to 30
  python main.py --rate-limit 20          # Allow 20 req/sec per IP
  python main.py --no-color               # Disable colored output

For more information, visit: https://github.com/pr0xywall/pr0xywall
        """
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Proxy server port (default: 8080)"
    )
    
    parser.add_argument(
        "--host", "-H",
        type=str,
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=25,
        help="Rule scoring threshold for blocking (default: 25)"
    )
    
    parser.add_argument(
        "--rate-limit", "-r",
        type=float,
        default=10.0,
        help="Requests per second limit per IP (default: 10)"
    )
    
    parser.add_argument(
        "--burst-size", "-b",
        type=int,
        default=20,
        help="Burst request limit (default: 20)"
    )
    
    parser.add_argument(
        "--block-duration",
        type=int,
        default=60,
        help="Seconds to block after limit exceeded (default: 60)"
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="%(prog)s 1.0.0"
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Create and setup pr0xywall
    app = ProxyWall()
    
    try:
        app.setup(
            port=args.port,
            threshold=args.threshold,
            rate_limit=args.rate_limit,
            burst_size=args.burst_size,
            block_duration=args.block_duration,
            colors=not args.no_color
        )
        
        # Run the server
        app.run()
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
