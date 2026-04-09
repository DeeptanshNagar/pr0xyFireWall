"""
Proxy Server Module

HTTP/1.1 Proxy Server with Layer 7 inspection.
Handles concurrent connections using threading.
Forwards allowed requests to destination servers.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from typing import Optional, Tuple

# Handle imports with fallback
try:
    from parser.request_parser import Request, RequestParser
    from engine.decision_engine import DecisionEngine, Decision
    from logger.logger import ProxyLogger, get_logger
    from utils.helpers import build_error_response, extract_host_from_headers
except ImportError:
    import sys
    sys.path.insert(0, '..')
    from parser.request_parser import Request, RequestParser
    from engine.decision_engine import DecisionEngine, Decision
    from logger.logger import ProxyLogger, get_logger
    from utils.helpers import build_error_response, extract_host_from_headers


class ProxyHandler(threading.Thread):
    """
    Handler for individual proxy connections.
    
    Each connection is handled in a separate thread for concurrency.
    Parses request, evaluates rules, and forwards or blocks.
    """
    
    # Buffer size for data transfer
    BUFFER_SIZE = 8192
    
    # Socket timeout in seconds
    SOCKET_TIMEOUT = 30
    
    def __init__(
        self,
        client_socket: socket.socket,
        client_address: Tuple[str, int],
        decision_engine: DecisionEngine,
        logger: Optional[ProxyLogger] = None
    ):
        """
        Initialize proxy handler.
        
        Args:
            client_socket: Client connection socket
            client_address: (ip, port) tuple
            decision_engine: Decision engine for rule evaluation
            logger: Logger instance
        """
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.client_address = client_address
        self.client_ip = client_address[0]
        self.decision_engine = decision_engine
        self.logger = logger or get_logger()
        
        # Target server socket
        self.target_socket: Optional[socket.socket] = None
        
        # Request data
        self.request: Optional[Request] = None
        self.request_data: bytes = b""
        
        # Running flag
        self.running = True
    
    def run(self) -> None:
        """Main handler loop."""
        try:
            self.client_socket.settimeout(self.SOCKET_TIMEOUT)
            self._handle_connection()
        except socket.timeout:
            self.logger.debug(f"Connection timeout for {self.client_ip}")
        except Exception as e:
            self.logger.debug(f"Handler error for {self.client_ip}: {e}")
        finally:
            self._cleanup()
    
    def _handle_connection(self) -> None:
        """Handle the client connection."""
        # Receive request data
        self.request_data = self._receive_request()
        
        if not self.request_data:
            return
        
        # Parse the request
        try:
            self.request = RequestParser.parse_from_socket(
                self.request_data, 
                self.client_address
            )
        except ValueError as e:
            self.logger.warning(f"Failed to parse request from {self.client_ip}: {e}")
            self._send_error(400, "Bad Request", str(e))
            return
        
        # Evaluate request through decision engine
        result = self.decision_engine.evaluate(self.request)
        
        # Log the request
        self.logger.log_decision_result(
            self.client_ip,
            self.request.method,
            self.request.path,
            result
        )
        
        # Handle decision
        if result.is_blocked():
            self._send_error(403, "Forbidden", result.reason)
            return
        
        # Forward the request
        self._forward_request()
    
    def _receive_request(self) -> bytes:
        """
        Receive HTTP request from client.
        
        Returns:
            Raw request bytes
        """
        data = b""
        
        while True:
            try:
                chunk = self.client_socket.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                
                data += chunk
                
                # Check if we have complete HTTP headers
                if b"\r\n\r\n" in data:
                    # Check for Content-Length to read body
                    headers_end = data.find(b"\r\n\r\n") + 4
                    headers = data[:headers_end].decode('utf-8', errors='ignore')
                    
                    # Parse Content-Length
                    content_length = 0
                    for line in headers.split('\r\n'):
                        if line.lower().startswith('content-length:'):
                            try:
                                content_length = int(line.split(':')[1].strip())
                            except (ValueError, IndexError):
                                pass
                            break
                    
                    # If we have all the body data, we're done
                    if len(data) >= headers_end + content_length:
                        break
                    
                    # Continue reading body
                    remaining = content_length - (len(data) - headers_end)
                    while remaining > 0:
                        chunk = self.client_socket.recv(min(self.BUFFER_SIZE, remaining))
                        if not chunk:
                            break
                        data += chunk
                        remaining -= len(chunk)
                    break
                
                # Prevent excessive data
                if len(data) > 1024 * 1024:  # 1MB limit
                    self.logger.warning(f"Request too large from {self.client_ip}")
                    break
                    
            except socket.error:
                break
        
        return data
    
    def _forward_request(self) -> None:
        """Forward request to target server and relay response."""
        if not self.request:
            return
        
        # Determine target host
        target_host = self._get_target_host()
        if not target_host:
            self._send_error(400, "Bad Request", "Cannot determine target host")
            return
        
        target_port = 80  # Default HTTP port
        
        # Parse host:port if present
        if ':' in target_host:
            parts = target_host.split(':')
            target_host = parts[0]
            try:
                target_port = int(parts[1])
            except ValueError:
                pass
        
        try:
            # Connect to target server
            self.target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target_socket.settimeout(self.SOCKET_TIMEOUT)
            self.target_socket.connect((target_host, target_port))
            
            # Send request to target
            self.target_socket.sendall(self.request_data)
            
            # Relay response back to client
            self._relay_response()
            
        except socket.gaierror:
            self._send_error(502, "Bad Gateway", f"Cannot resolve {target_host}")
        except socket.error as e:
            self._send_error(502, "Bad Gateway", f"Cannot connect to target: {e}")
        except Exception as e:
            self._send_error(500, "Internal Server Error", str(e))
    
    def _get_target_host(self) -> Optional[str]:
        """
        Determine target host from request.
        
        Returns:
            Target host string or None
        """
        # First, check Host header
        if self.request:
            host = self.request.get_header('Host')
            if host:
                return host
        
        # Try to extract from raw request
        try:
            headers = self.request_data.split(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')
            for line in headers.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        
        return None
    
    def _relay_response(self) -> None:
        """Relay response from target server to client."""
        if not self.target_socket:
            return
        
        try:
            while True:
                # Use select for non-blocking read
                readable, _, _ = select.select(
                    [self.target_socket], [], [], self.SOCKET_TIMEOUT
                )
                
                if not readable:
                    break
                
                data = self.target_socket.recv(self.BUFFER_SIZE)
                if not data:
                    break
                
                self.client_socket.sendall(data)
        except socket.error:
            pass
        except Exception as e:
            self.logger.debug(f"Relay error: {e}")
    
    def _send_error(self, code: int, status: str, reason: str) -> None:
        """
        Send error response to client.
        
        Args:
            code: HTTP status code
            status: Status text
            reason: Error reason
        """
        try:
            response = build_error_response(code, reason)
            self.client_socket.sendall(response)
        except socket.error:
            pass
    
    def _cleanup(self) -> None:
        """Clean up sockets."""
        self.running = False
        
        try:
            self.client_socket.close()
        except socket.error:
            pass
        
        if self.target_socket:
            try:
                self.target_socket.close()
            except socket.error:
                pass


class ProxyServer:
    """
    HTTP/1.1 Proxy Server with Layer 7 firewall capabilities.
    
    Listens for incoming connections and spawns handler threads.
    Integrates with decision engine for request filtering.
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        decision_engine: Optional[DecisionEngine] = None,
        logger: Optional[ProxyLogger] = None
    ):
        """
        Initialize proxy server.
        
        Args:
            host: Bind address
            port: Listen port
            decision_engine: Decision engine instance
            logger: Logger instance
        """
        self.host = host
        self.port = port
        self.decision_engine = decision_engine or DecisionEngine()
        self.logger = logger or get_logger()
        
        # Server socket
        self.server_socket: Optional[socket.socket] = None
        
        # Running flag
        self.running = False
        
        # Connection tracking
        self._lock = threading.Lock()
        self._active_handlers: list[ProxyHandler] = []
        self._total_connections = 0
    
    def start(self) -> None:
        """Start the proxy server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.running = True
            
            # Log startup
            config = self.decision_engine.get_rule_summary()
            self.logger.startup(self.port, config)
            
            # Accept connections
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create and start handler
                    handler = ProxyHandler(
                        client_socket,
                        client_address,
                        self.decision_engine,
                        self.logger
                    )
                    
                    with self._lock:
                        self._active_handlers.append(handler)
                        self._total_connections += 1
                    
                    handler.start()
                    
                    # Clean up finished handlers
                    self._cleanup_handlers()
                    
                except socket.timeout:
                    continue
                except OSError:
                    if self.running:
                        raise
                    break
                    
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            raise
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the proxy server."""
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except socket.error:
                pass
            self.server_socket = None
        
        # Wait for handlers to finish
        with self._lock:
            for handler in self._active_handlers:
                handler.running = False
                try:
                    handler.client_socket.close()
                except socket.error:
                    pass
        
        self.logger.shutdown()
    
    def _cleanup_handlers(self) -> None:
        """Remove finished handler threads."""
        with self._lock:
            self._active_handlers = [
                h for h in self._active_handlers 
                if h.is_alive()
            ]
    
    def get_stats(self) -> dict:
        """Get server statistics."""
        with self._lock:
            return {
                "total_connections": self._total_connections,
                "active_connections": len(self._active_handlers),
                "host": self.host,
                "port": self.port,
                "running": self.running
            }
