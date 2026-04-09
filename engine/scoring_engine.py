"""
Scoring Engine Module

Evaluates normalized tuples against explicit, high-priority threat categories.
Assigns scores and reasons for detected patterns.
"""

from __future__ import annotations
import re
from typing import Tuple, Dict, List

class ScoringEngine:
    """Explicit score-based detection on normalized Request tuples."""
    
    # Precompiled regexes for performance
    SQLI_PATTERN = re.compile(r"(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+.+set|'|--|\bselect\b.*\bfrom\b)", re.IGNORECASE)
    XSS_PATTERN = re.compile(r"(<script|javascript:|onerror=|onload=|eval\(|document\.cookie)", re.IGNORECASE)
    CMD_PATTERN = re.compile(r"(/bin/sh|/bin/bash|cmd\.exe|powershell|\bexec\b|;\s*ls\b|;\s*cat\b|`.*`)", re.IGNORECASE)
    PATH_PATTERN = re.compile(r"(\.\./|\.\.\\|/etc/passwd|windows\\system32|boot\.ini)", re.IGNORECASE)
    UA_PATTERN = re.compile(r"(sqlmap|nmap|nikto|hydra|dirb|dirbuster|curl|wget)", re.IGNORECASE)

    @classmethod
    def evaluate(cls, norm_tuple: Tuple[str, str, Dict[str, str], str]) -> Tuple[int, List[str]]:
        """
        Evaluate the normalized tuple.
        Returns (total_score, list_of_reasons)
        """
        method, path, headers, body = norm_tuple
        
        total_score = 0
        reasons = []

        # Target areas to scan for general patterns
        targets = [path, body]
        
        # SQLi
        for target in targets:
            if cls.SQLI_PATTERN.search(target):
                total_score += 20
                reasons.append("SQL Injection pattern detected")
                break # count once per request
                
        # XSS
        for target in targets:
            if cls.XSS_PATTERN.search(target):
                total_score += 15
                reasons.append("XSS pattern detected")
                break
                
        # Command Injection
        for target in targets:
            if cls.CMD_PATTERN.search(target):
                total_score += 25
                reasons.append("Command Injection pattern detected")
                break
                
        # Path Traversal
        for target in targets:
            if cls.PATH_PATTERN.search(target):
                total_score += 15
                reasons.append("Path Traversal pattern detected")
                break
                
        # Malicious User-Agent
        ua = headers.get('user-agent', '')
        if cls.UA_PATTERN.search(ua):
            total_score += 10
            reasons.append("Suspicious User-Agent detected")
            
        return total_score, reasons
