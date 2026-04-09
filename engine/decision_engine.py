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
    from engine.normalizer import Normalizer
    from engine.scoring_engine import ScoringEngine
except ImportError:
    import sys
    sys.path.insert(0, '..')
    from parser.request_parser import Request
    from rules.rules import RuleSet
    from ratelimit.limiter import RateLimiter
    from engine.normalizer import Normalizer
    from engine.scoring_engine import ScoringEngine


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
    
    def _print_detailed_output(self, raw_tuple, norm_tuple, matched_rules, attack_reasons, total_score, decision_str):
        print("\n" + "="*50)
        print("🔍 DETAILED CONSOLE OUTPUT 🔍")
        print("="*50)
        print(f"1. EXTRACTED TUPLE:\n   Method: {raw_tuple[0]}\n   Path: {raw_tuple[1]}")
        print(f"2. NORMALIZED FIELDS:\n   Method: {norm_tuple[0]}\n   Path: {norm_tuple[1]}\n   Body: {norm_tuple[3]}")
        print(f"3. MATCHED RULES: {', '.join(matched_rules) if matched_rules else 'None'}")
        print(f"4. ATTACK REASONS: {', '.join(attack_reasons) if attack_reasons else 'None'}")
        print(f"5. TOTAL SCORE: {total_score}")
        print(f"6. FINAL DECISION: {decision_str}")
        print("="*50 + "\n")

    def evaluate(self, request: Request) -> DecisionResult:
        """
        Evaluate a request and return decision.
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
        
        # Extract tuple
        raw_tuple = (request.method, request.path, request.headers, request.body)
        
        # Normalize
        norm_tuple = Normalizer.normalize_tuple(raw_tuple)
        
        # Scoring Engine Explicit Detectors
        detector_score, detector_reasons = ScoringEngine.evaluate(norm_tuple)
        
        # Existing Rules evaluation
        rule_block, rule_score, rule_reasons = self.rule_set.evaluate(request)
        
        total_score = detector_score + rule_score
        all_reasons = detector_reasons + rule_reasons
        
        decision_str = "BLOCK" if total_score >= self.rule_set.score_threshold else "ALLOW"
        
        # Console output
        self._print_detailed_output(
            raw_tuple, norm_tuple, rule_reasons, detector_reasons, total_score, decision_str
        )
        
        # Step 3: Make final decision
        if total_score >= self.rule_set.score_threshold:
            if len(all_reasons) == 1:
                reason = all_reasons[0]
            else:
                reason = f"Multiple threats detected: {'; '.join(all_reasons[:3])}"
            
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=reason,
                score=total_score,
                rate_limited=False,
                rule_matches=all_reasons
            )
        
        return DecisionResult(
            decision=Decision.ALLOW,
            reason="Request passed all checks",
            score=total_score,
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
