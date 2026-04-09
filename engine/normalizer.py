"""
Normalization Module

Cleans up request data by resolving obfuscation, standardizing whitespace,
and removing noise prior to evaluation.
"""

from __future__ import annotations
import urllib.parse
import re
from typing import Tuple, Dict

class Normalizer:
    """Normalizes HTTP request components for cleaner detection."""
    
    @classmethod
    def _percent(cls, text: str) -> str:
        """Decode URL-encoded parameters."""
        if not text:
            return ""
        try:
            return urllib.parse.unquote_plus(text)
        except Exception:
            return text

    @classmethod
    def _multispace(cls, text: str) -> str:
        """Collapse multiple spaces and typical whitespace characters into a single space."""
        if not text:
            return ""
        return re.sub(r'\s+', ' ', text)

    @classmethod
    def _strip_noise(cls, text: str) -> str:
        """Strip null bytes, non-printable characters, and force lowercase."""
        if not text:
            return ""
        # Remove null bytes
        text = text.replace('\x00', '')
        # Basic removal of non-printable ASCII noise (keeping tabs/newlines via \s if not handled)
        text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        return text.strip().lower()

    @classmethod
    def normalize_string(cls, text: str) -> str:
        """Apply all normalizations."""
        text = cls._percent(text)
        text = cls._strip_noise(text)
        text = cls._multispace(text)
        return text

    @classmethod
    def normalize_tuple(cls, raw_tuple: Tuple[str, str, Dict[str, str], str]) -> Tuple[str, str, Dict[str, str], str]:
        """
        Normalize a full request tuple.
        Returns: (method, path, headers, body)
        """
        method, path, headers, body = raw_tuple
        
        norm_method = method.upper() # method stays uppercase usually, doesn't need deep normalization
        norm_path = cls.normalize_string(path)
        norm_body = cls.normalize_string(body)
        
        norm_headers = {}
        for k, v in headers.items():
            norm_headers[k.lower()] = cls.normalize_string(v)
            
        return (norm_method, norm_path, norm_headers, norm_body)
