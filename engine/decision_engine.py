"""
Decision Engine Module

Evaluates requests against rules and rate limiting to make ALLOW/BLOCK decisions.
Central orchestrator that combines rule evaluation with rate limit checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, TYPE_CHECKING

# Handle imports with fallback for standalone usage
try:
    from parser.request_parser import Request
    from rules.rules import RuleSet
    from ratelimit.limiter import RateLimiter
except ImportError:
    import sys
    sys.path.insert(0, '..')
    from parser.request_parser import Request
    from rules.rules import RuleSet
    from ratelimit.limiter import RateLimiter


class Decision(Enum):
    """Decision outcomes for request evaluation."""
    ALLOW = auto()
    BLOCK = auto()


@dataclass
class DecisionResult:
    """
    Result of decision engine evaluation.
    
    Attributes:
        decision: ALLOW or BLOCK
        reason: Human-readable reason for the decision
        score: Threat score from rule evaluation
        rate_limited: Whether rate limiting was triggered
        rule_matches: List of matched rule names
    """
    decision: Decision
    reason: str
    score: int = 0
    rate_limited: bool = False
    rule_matches: List[str] = None
    
    def __post_init__(self):
        if self.rule_matches is None:
            self.rule_matches = []
    
    def is_allowed(self) -> bool:
        """Check if request is allowed."""
        return self.decision == Decision.ALLOW
    
    def is_blocked(self) -> bool:
        """Check if request is blocked."""
        return self.decision == Decision.BLOCK
    
    def __str__(self) -> str:
        status = "ALLOW" if self.is_allowed() else "BLOCK"
        return f"[{status}] {self.reason} (Score: {self.score})"


class DecisionEngine:
    """
    Central decision engine for the proxy firewall.
    
    Combines rule-based inspection with rate limiting to make
    final ALLOW/BLOCK decisions for each request.
    """
    
    def __init__(
        self,
        rule_set: Optional[RuleSet] = None,
        rate_limiter: Optional[RateLimiter] = None,
        enable_rate_limiting: bool = True
    ):
        """
        Initialize the decision engine.
        
        Args:
            rule_set: RuleSet instance for rule evaluation
            rate_limiter: RateLimiter instance for rate limiting
            enable_rate_limiting: Whether to enable rate limiting
        """
        self.rule_set = rule_set or RuleSet()
        self.rate_limiter = rate_limiter
        self.enable_rate_limiting = enable_rate_limiting
        
        # Create default rate limiter if not provided and enabled
        if self.enable_rate_limiting and self.rate_limiter is None:
            from ratelimit.limiter import RateLimiter
            self.rate_limiter = RateLimiter()
    
    def evaluate(self, request: Request) -> DecisionResult:
        """
        Evaluate a request and return decision.
        
        Evaluation order:
        1. Check rate limiting (if enabled)
        2. Evaluate security rules
        3. Combine results and return decision
        
        Args:
            request: The HTTP request to evaluate
            
        Returns:
            DecisionResult with decision and metadata
        """
        # Step 1: Check rate limiting first
        if self.enable_rate_limiting and self.rate_limiter:
            allowed, rate_info = self.rate_limiter.check_request(
                request.client_ip,
                request.path
            )
            if not allowed:
                return DecisionResult(
                    decision=Decision.BLOCK,
                    reason=f"Rate limit exceeded: {rate_info}",
                    score=0,
                    rate_limited=True
                )
        
        # Step 2: Evaluate security rules
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        # Step 3: Make final decision
        if should_block:
            # Combine all reasons
            if len(reasons) == 1:
                reason = reasons[0]
            else:
                reason = f"Multiple threats detected: {'; '.join(reasons[:3])}"
            
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=reason,
                score=score,
                rate_limited=False,
                rule_matches=reasons
            )
        
        return DecisionResult(
            decision=Decision.ALLOW,
            reason="Request passed all checks",
            score=score,
            rate_limited=False
        )
    
    def quick_allow(self, request: Request) -> bool:
        """
        Quick check if request should be allowed.
        
        Args:
            request: The HTTP request to check
            
        Returns:
            True if allowed, False if blocked
        """
        result = self.evaluate(request)
        return result.is_allowed()
    
    def get_rule_summary(self) -> dict:
        """Get summary of configured rules."""
        rules = self.rule_set.list_rules()
        enabled_count = sum(1 for r in rules if r["enabled"])
        
        return {
            "total_rules": len(rules),
            "enabled_rules": enabled_count,
            "disabled_rules": len(rules) - enabled_count,
            "score_threshold": self.rule_set.score_threshold,
            "rate_limiting_enabled": self.enable_rate_limiting
        }
    
    def update_rule_threshold(self, threshold: int) -> None:
        """Update the rule scoring threshold."""
        self.rule_set.set_threshold(threshold)
    
    def enable_rate_limit(self) -> None:
        """Enable rate limiting."""
        self.enable_rate_limiting = True
        if self.rate_limiter is None:
            from ratelimit.limiter import RateLimiter
            self.rate_limiter = RateLimiter()
    
    def disable_rate_limit(self) -> None:
        """Disable rate limiting."""
        self.enable_rate_limiting = False
