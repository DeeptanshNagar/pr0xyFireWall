"""
Utils module - Utility Functions

Common utility functions for the proxy firewall.
"""

from .helpers import (
    build_http_response,
    build_error_response,
    parse_url,
    is_valid_ip,
    is_private_ip,
    sanitize_path,
    extract_host_from_headers,
    format_bytes,
    truncate_string,
    mask_sensitive_data,
    create_json_response,
    Colors,
    print_banner
)

__all__ = [
    "build_http_response",
    "build_error_response",
    "parse_url",
    "is_valid_ip",
    "is_private_ip",
    "sanitize_path",
    "extract_host_from_headers",
    "format_bytes",
    "truncate_string",
    "mask_sensitive_data",
    "create_json_response",
    "Colors",
    "print_banner"
]
