"""
pr0xywall - Layer 7 Application-Level Proxy Firewall

A production-grade HTTP/1.1 proxy server with deep packet inspection,
rule-based filtering, rate limiting, and threat scoring.

Modules:
    proxy: HTTP proxy server implementation
    parser: HTTP request parsing
    rules: Rule engine with scoring system
    engine: Decision engine
    ratelimit: Rate limiting with thread safety
    logger: Structured logging
    utils: Utility functions

Example:
    from main import ProxyWall
    
    app = ProxyWall()
    app.setup(port=8080)
    app.run()

Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "pr0xywall"
__license__ = "MIT"

from main import ProxyWall

__all__ = ["ProxyWall"]
