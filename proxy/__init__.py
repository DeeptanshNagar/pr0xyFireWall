"""
Proxy module - HTTP/1.1 Proxy Server

Handles incoming connections and forwards requests to target servers.
"""

from .server import ProxyServer, ProxyHandler

__all__ = ["ProxyServer", "ProxyHandler"]
