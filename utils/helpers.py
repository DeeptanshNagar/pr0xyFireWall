"""
Utility Helpers Module

Common utility functions for the proxy firewall.
Includes HTTP response builders, validation functions, and helpers.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.parse
from typing import Dict, Optional, Tuple


def build_http_response(
    status_code: int = 200,
    status_text: str = "OK",
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    content_type: str = "text/html"
) -> bytes:
    """
    Build a complete HTTP response.
    
    Args:
        status_code: HTTP status code
        status_text: HTTP status text
        headers: Additional headers
        body: Response body
        content_type: Content-Type header
        
    Returns:
        Complete HTTP response as bytes
    """
    # Default headers
    response_headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body.encode('utf-8'))),
        "Connection": "close",
        "Server": "pr0xywall/1.0"
    }
    
    # Add custom headers
    if headers:
        response_headers.update(headers)
    
    # Build response line
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    
    # Add headers
    for name, value in response_headers.items():
        response += f"{name}: {value}\r\n"
    
    # Empty line before body
    response += "\r\n"
    
    # Add body
    response += body
    
    return response.encode('utf-8')


def build_error_response(
    status_code: int,
    reason: str,
    include_reason: bool = True
) -> bytes:
    """
    Build an error response (403, 429, etc.).
    
    Args:
        status_code: HTTP error code
        reason: Reason for the error
        include_reason: Whether to include reason in body
        
    Returns:
        HTTP error response as bytes
    """
    status_texts = {
        403: "Forbidden",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable"
    }
    
    status_text = status_texts.get(status_code, "Error")
    
    if include_reason:
        body = f"""<!DOCTYPE html>
<html>
<head>
    <title>{status_code} {status_text}</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        h1 {{ color: #d32f2f; }}
        .reason {{ background: #f5f5f5; padding: 15px; border-radius: 5px; display: inline-block; }}
    </style>
</head>
<body>
    <h1>{status_code} {status_text}</h1>
    <div class="reason">
        <p><strong>Request blocked by pr0xywall</strong></p>
        <p>Reason: {reason}</p>
    </div>
    <hr>
    <p><em>pr0xywall Layer 7 Firewall</em></p>
</body>
</html>"""
    else:
        body = f"{status_code} {status_text}"
    
    return build_http_response(
        status_code=status_code,
        status_text=status_text,
        body=body,
        content_type="text/html"
    )


def parse_url(url: str) -> Tuple[str, int, str]:
    """
    Parse a URL into (host, port, path).
    
    Args:
        url: URL to parse
        
    Returns:
        Tuple of (host, port, path)
    """
    # Add scheme if missing
    if '://' not in url:
        url = 'http://' + url
    
    parsed = urllib.parse.urlparse(url)
    
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or "/"
    
    if parsed.query:
        path += "?" + parsed.query
    
    return host, port, path


def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address.
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is in private range.
    
    Args:
        ip: IP address string
        
    Returns:
        True if private IP
    """
    private_patterns = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^0\.",
        r"^::1$",
        r"^fc00:",
        r"^fe80:"
    ]
    
    return any(re.match(pattern, ip) for pattern in private_patterns)


def sanitize_path(path: str) -> str:
    """
    Sanitize a path to prevent path traversal attacks.
    
    Args:
        path: Raw path string
        
    Returns:
        Sanitized path
    """
    # Decode URL encoding
    decoded = urllib.parse.unquote(path)
    
    # Remove null bytes
    decoded = decoded.replace('\x00', '')
    
    # Normalize path
    normalized = urllib.parse.urlparse(decoded).path
    
    # Prevent path traversal
    parts = normalized.split('/')
    safe_parts = []
    for part in parts:
        if part == '..':
            if safe_parts:
                safe_parts.pop()
        elif part and part != '.':
            safe_parts.append(part)
    
    return '/' + '/'.join(safe_parts)


def extract_host_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Extract target host from HTTP headers.
    
    Args:
        headers: HTTP headers dictionary
        
    Returns:
        Host string or None
    """
    # Check Host header
    host = headers.get('Host') or headers.get('host')
    if host:
        # Remove port if present
        return host.split(':')[0]
    
    return None


def format_bytes(size: int) -> str:
    """
    Format byte size to human readable string.
    
    Args:
        size: Size in bytes
        
    Returns:
        Human readable string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to max length.
    
    Args:
        s: Input string
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def mask_sensitive_data(data: str, patterns: list[str] = None) -> str:
    """
    Mask sensitive data in strings (passwords, tokens, etc.).
    
    Args:
        data: Input string
        patterns: List of sensitive field names
        
    Returns:
        Masked string
    """
    if patterns is None:
        patterns = ['password', 'token', 'secret', 'api_key', 'apikey', 'key']
    
    result = data
    for pattern in patterns:
        # Match pattern=value or pattern: value
        regex = rf"({pattern}[=:])[^&\s]+"
        result = re.sub(regex, r"\1***", result, flags=re.IGNORECASE)
    
    return result


def create_json_response(data: dict, status_code: int = 200) -> bytes:
    """
    Create a JSON HTTP response.
    
    Args:
        data: Data to serialize
        status_code: HTTP status code
        
    Returns:
        HTTP response as bytes
    """
    body = json.dumps(data, indent=2)
    return build_http_response(
        status_code=status_code,
        body=body,
        content_type="application/json"
    )


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


def print_banner():
    """Print the pr0xywall banner."""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Colors.BOLD}                    pr0xywall Firewall                        {Colors.RESET}{Colors.CYAN}║
║{Colors.DIM}              Layer 7 Application-Level Proxy                   {Colors.RESET}{Colors.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)
