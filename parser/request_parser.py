"""
HTTP Request Parser Module

Parses raw HTTP requests into structured Request objects for Layer 7 inspection.
Extracts: client IP, method, path, headers, body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse


@dataclass
class Request:
    """
    Structured HTTP Request object for Layer 7 inspection.
    
    Attributes:
        client_ip: IP address of the client
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        path: Request path (e.g., /index.html)
        version: HTTP version (e.g., HTTP/1.1)
        headers: Dictionary of HTTP headers
        body: Request body/payload
        raw_request: Original raw request string
    """
    client_ip: str = ""
    method: str = ""
    path: str = ""
    version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_request: str = ""
    
    def get_header(self, name: str) -> Optional[str]:
        """Get header value case-insensitively."""
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return None
    
    def get_user_agent(self) -> str:
        """Get User-Agent header or empty string."""
        return self.get_header("User-Agent") or ""
    
    def get_content_type(self) -> str:
        """Get Content-Type header or empty string."""
        return self.get_header("Content-Type") or ""
    
    def has_body(self) -> bool:
        """Check if request has a body."""
        return len(self.body) > 0
    
    def __repr__(self) -> str:
        return f"Request({self.method} {self.path} from {self.client_ip})"


class RequestParser:
    """
    HTTP/1.1 Request Parser.
    
    Parses raw HTTP request bytes/strings into structured Request objects.
    Handles standard HTTP/1.1 format with proper header and body extraction.
    """
    
    # Regex for parsing request line: METHOD PATH HTTP/VERSION
    REQUEST_LINE_PATTERN = re.compile(
        r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(.+?)\s+HTTP/(\d\.\d)$"
    )
    
    @classmethod
    def parse(cls, raw_data: bytes | str, client_ip: str = "unknown") -> Request:
        """
        Parse raw HTTP request data into a Request object.
        
        Args:
            raw_data: Raw HTTP request as bytes or string
            client_ip: Client IP address
            
        Returns:
            Parsed Request object
            
        Raises:
            ValueError: If request format is invalid
        """
        # Convert bytes to string if needed
        if isinstance(raw_data, bytes):
            try:
                raw_string = raw_data.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                raw_string = raw_data.decode('latin-1', errors='replace')
        else:
            raw_string = raw_data
        
        request = Request(client_ip=client_ip, raw_request=raw_string)
        
        # Split headers from body
        parts = raw_string.split('\r\n\r\n', 1)
        header_section = parts[0] if parts else raw_string
        request.body = parts[1] if len(parts) > 1 else ""
        
        # Parse header lines
        lines = header_section.split('\r\n')
        if not lines:
            raise ValueError("Empty request")
        
        # Parse request line (first line)
        cls._parse_request_line(lines[0], request)
        
        # Parse headers (remaining lines)
        cls._parse_headers(lines[1:], request)
        
        return request
    
    @classmethod
    def _parse_request_line(cls, line: str, request: Request) -> None:
        """Parse the HTTP request line."""
        match = cls.REQUEST_LINE_PATTERN.match(line.strip())
        if not match:
            raise ValueError(f"Invalid request line format: {line[:50]}")
        
        request.method = match.group(1)
        raw_target = match.group(2)
        request.version = f"HTTP/{match.group(3)}"
        
        # When clients use a proxy, they often send the absolute URI
        if raw_target.startswith("http://") or raw_target.startswith("https://"):
            parsed = urlparse(raw_target)
            request.path = parsed.path or "/"
            if parsed.query:
                request.path += "?" + parsed.query
        else:
            request.path = raw_target
    
    @classmethod
    def _parse_headers(cls, header_lines: list[str], request: Request) -> None:
        """Parse HTTP headers from lines."""
        for line in header_lines:
            line = line.strip()
            if not line:
                continue
            
            # Header format: Name: Value
            if ':' in line:
                name, value = line.split(':', 1)
                request.headers[name.strip()] = value.strip()
    
    @classmethod
    def parse_from_socket(cls, data: bytes, client_address: tuple) -> Request:
        """
        Parse request from socket data with client address.
        
        Args:
            data: Raw bytes from socket
            client_address: (ip, port) tuple from socket
            
        Returns:
            Parsed Request object
        """
        client_ip = client_address[0] if client_address else "unknown"
        return cls.parse(data, client_ip)


def create_request(
    method: str,
    path: str,
    client_ip: str = "127.0.0.1",
    headers: Optional[Dict[str, str]] = None,
    body: str = ""
) -> Request:
    """
    Helper function to create a Request object programmatically.
    
    Useful for testing and rule validation.
    
    Args:
        method: HTTP method
        path: Request path
        client_ip: Client IP address
        headers: Optional headers dictionary
        body: Optional request body
        
    Returns:
        Constructed Request object
    """
    return Request(
        client_ip=client_ip,
        method=method.upper(),
        path=path,
        headers=headers or {},
        body=body
    )
