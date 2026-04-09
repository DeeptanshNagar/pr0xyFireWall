"""
Rule Engine Module

Implements flexible rule system for Layer 7 inspection.
Supports: method blocking, path blocking, keyword detection, header inspection.
Includes scoring system for cumulative threat assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, List, Optional, Pattern

# Import with fallback for standalone usage
try:
    from parser.request_parser import Request
except ImportError:
    import sys
    sys.path.insert(0, '..')
    from parser.request_parser import Request


class RuleType(Enum):
    """Types of inspection rules."""
    METHOD_BLOCK = auto()      # Block specific HTTP methods
    PATH_BLOCK = auto()        # Block specific paths/patterns
    KEYWORD_BODY = auto()      # Detect keywords in body
    HEADER_CHECK = auto()      # Check headers for suspicious values
    RATE_LIMIT = auto()        # Rate limiting (handled externally)


class Severity(Enum):
    """Severity levels for rule matches."""
    LOW = 5
    MEDIUM = 10
    HIGH = 20
    CRITICAL = 50


@dataclass
class RuleResult:
    """Result of a rule evaluation."""
    matched: bool
    rule_name: str
    severity: Severity
    score: int
    reason: str = ""
    
    def __bool__(self) -> bool:
        return self.matched


@dataclass
class Rule:
    """
    Firewall rule definition.
    
    Attributes:
        name: Rule identifier
        rule_type: Type of rule
        severity: Severity level (determines score)
        condition: Function that evaluates request
        reason_template: Template for block reason message
        enabled: Whether rule is active
    """
    name: str
    rule_type: RuleType
    severity: Severity
    condition: Callable[[Request], bool]
    reason_template: str = "Rule matched: {name}"
    enabled: bool = True
    
    def evaluate(self, request: Request) -> RuleResult:
        """Evaluate this rule against a request."""
        if not self.enabled:
            return RuleResult(False, self.name, self.severity, 0)
        
        matched = self.condition(request)
        if matched:
            reason = self.reason_template.format(name=self.name)
            return RuleResult(
                matched=True,
                rule_name=self.name,
                severity=self.severity,
                score=self.severity.value,
                reason=reason
            )
        return RuleResult(False, self.name, self.severity, 0)


class RuleSet:
    """
    Collection of rules for Layer 7 inspection.
    
    Provides methods to add, remove, and evaluate rules.
    Implements scoring system for cumulative threat assessment.
    """
    
    # Default scoring threshold
    DEFAULT_SCORE_THRESHOLD = 25
    
    def __init__(self, score_threshold: int = DEFAULT_SCORE_THRESHOLD):
        """
        Initialize rule set.
        
        Args:
            score_threshold: Cumulative score threshold for blocking
        """
        self.rules: List[Rule] = []
        self.score_threshold = score_threshold
        self._compile_default_rules()
    
    def _compile_default_rules(self) -> None:
        """Compile default security rules."""
        # Block dangerous HTTP methods
        self.add_method_block_rule(
            name="block_trace",
            methods=["TRACE"],
            severity=Severity.MEDIUM,
            reason="TRACE method blocked (security risk)"
        )
        
        # Block sensitive endpoints
        self.add_path_block_rule(
            name="block_admin",
            paths=["/admin", "/admin/", "/administrator", "/administrator/"],
            severity=Severity.CRITICAL,
            reason="Access to admin endpoint blocked"
        )
        
        self.add_path_block_rule(
            name="block_config",
            paths=["/config", "/.env", "/.git", "/.htaccess", "/config.php"],
            severity=Severity.CRITICAL,
            reason="Access to configuration files blocked"
        )
        
        # Block SQL injection patterns in body
        self.add_keyword_rule(
            name="detect_sql_injection",
            keywords=[
                "' OR '1'='1",
                "' OR 1=1 --",
                "DROP TABLE",
                "UNION SELECT",
                "INSERT INTO",
                "DELETE FROM"
            ],
            severity=Severity.CRITICAL,
            reason="SQL injection pattern detected"
        )
        
        # Block sensitive data exposure
        self.add_keyword_rule(
            name="detect_password_leak",
            keywords=["password=", "passwd=", "pwd="],
            severity=Severity.MEDIUM,
            reason="Potential password exposure detected"
        )
        
        self.add_keyword_rule(
            name="detect_token_leak",
            keywords=["token=", "api_key=", "secret=", "apikey="],
            severity=Severity.MEDIUM,
            reason="Potential token/key exposure detected"
        )
        
        # Block suspicious User-Agents
        self.add_user_agent_rule(
            name="block_sqlmap",
            patterns=[r"sqlmap", r"Sqlmap", r"SQLMap"],
            severity=Severity.CRITICAL,
            reason="SQLMap scanner detected"
        )
        
        self.add_user_agent_rule(
            name="block_nmap",
            patterns=[r"nmap", r"Nmap", r"NMAP"],
            severity=Severity.CRITICAL,
            reason="Nmap scanner detected"
        )
        
        self.add_user_agent_rule(
            name="block_bots",
            patterns=[r"bot", r"crawler", r"spider", r"scanner"],
            severity=Severity.LOW,
            reason="Automated tool detected"
        )
    
    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule to the set."""
        self.rules.append(rule)
    
    def add_method_block_rule(
        self,
        name: str,
        methods: List[str],
        severity: Severity = Severity.MEDIUM,
        reason: str = "Method blocked",
        enabled: bool = True
    ) -> None:
        """Add a rule to block specific HTTP methods."""
        methods_upper = [m.upper() for m in methods]
        
        rule = Rule(
            name=name,
            rule_type=RuleType.METHOD_BLOCK,
            severity=severity,
            condition=lambda req, m=methods_upper: req.method in m,
            reason_template=reason,
            enabled=enabled
        )
        self.add_rule(rule)
    
    def add_path_block_rule(
        self,
        name: str,
        paths: List[str],
        severity: Severity = Severity.HIGH,
        reason: str = "Path blocked",
        enabled: bool = True,
        regex: bool = False
    ) -> None:
        """Add a rule to block specific paths."""
        if regex:
            compiled_patterns = [re.compile(p, re.IGNORECASE) for p in paths]
            condition = lambda req, p=compiled_patterns: any(
                pattern.search(req.path) for pattern in p
            )
        else:
            path_set = set(paths)
            condition = lambda req, p=path_set: req.path in p or req.path.rstrip('/') in p
        
        rule = Rule(
            name=name,
            rule_type=RuleType.PATH_BLOCK,
            severity=severity,
            condition=condition,
            reason_template=reason,
            enabled=enabled
        )
        self.add_rule(rule)
    
    def add_keyword_rule(
        self,
        name: str,
        keywords: List[str],
        severity: Severity = Severity.MEDIUM,
        reason: str = "Keyword detected",
        enabled: bool = True,
        case_sensitive: bool = False
    ) -> None:
        """Add a rule to detect keywords in request body."""
        if case_sensitive:
            keyword_set = set(keywords)
            condition = lambda req, k=keyword_set: any(
                kw in req.body for kw in k
            )
        else:
            keyword_set = [kw.lower() for kw in keywords]
            condition = lambda req, k=keyword_set: any(
                kw in req.body.lower() for kw in k
            )
        
        rule = Rule(
            name=name,
            rule_type=RuleType.KEYWORD_BODY,
            severity=severity,
            condition=condition,
            reason_template=reason,
            enabled=enabled
        )
        self.add_rule(rule)
    
    def add_user_agent_rule(
        self,
        name: str,
        patterns: List[str],
        severity: Severity = Severity.MEDIUM,
        reason: str = "Suspicious User-Agent",
        enabled: bool = True
    ) -> None:
        """Add a rule to check User-Agent header."""
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        def check_ua(req: Request, p=compiled_patterns) -> bool:
            ua = req.get_user_agent()
            return any(pattern.search(ua) for pattern in p)
        
        rule = Rule(
            name=name,
            rule_type=RuleType.HEADER_CHECK,
            severity=severity,
            condition=check_ua,
            reason_template=reason,
            enabled=enabled
        )
        self.add_rule(rule)
    
    def add_custom_header_rule(
        self,
        name: str,
        header_name: str,
        patterns: List[str],
        severity: Severity = Severity.MEDIUM,
        reason: str = "Suspicious header value",
        enabled: bool = True
    ) -> None:
        """Add a rule to check any header for suspicious patterns."""
        compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        def check_header(req: Request, h=header_name, p=compiled_patterns) -> bool:
            value = req.get_header(h) or ""
            return any(pattern.search(value) for pattern in p)
        
        rule = Rule(
            name=name,
            rule_type=RuleType.HEADER_CHECK,
            severity=severity,
            condition=check_header,
            reason_template=reason,
            enabled=enabled
        )
        self.add_rule(rule)
    
    def evaluate(self, request: Request) -> tuple[bool, int, List[str]]:
        """
        Evaluate all rules against a request.
        
        Args:
            request: The HTTP request to evaluate
            
        Returns:
            Tuple of (should_block, total_score, list_of_reasons)
        """
        total_score = 0
        reasons = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            result = rule.evaluate(request)
            if result.matched:
                total_score += result.score
                reasons.append(result.reason)
        
        should_block = total_score >= self.score_threshold
        return should_block, total_score, reasons
    
    def enable_rule(self, name: str) -> bool:
        """Enable a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                rule.enabled = False
                return True
        return False
    
    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name."""
        for i, rule in enumerate(self.rules):
            if rule.name == name:
                del self.rules[i]
                return True
        return False
    
    def list_rules(self) -> List[dict]:
        """List all rules with their status."""
        return [
            {
                "name": r.name,
                "type": r.rule_type.name,
                "severity": r.severity.name,
                "score": r.severity.value,
                "enabled": r.enabled
            }
            for r in self.rules
        ]
    
    def set_threshold(self, threshold: int) -> None:
        """Update the scoring threshold."""
        self.score_threshold = threshold
    
    def clear_rules(self) -> None:
        """Remove all rules."""
        self.rules.clear()
