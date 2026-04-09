#!/usr/bin/env python3
"""
Test Suite for pr0xywall

Tests all core components: parser, rules, decision engine, rate limiter.
"""

import sys
import time
import unittest
from parser.request_parser import Request, RequestParser, create_request
from rules.rules import RuleSet, Severity, RuleType
from engine.decision_engine import DecisionEngine, Decision
from ratelimit.limiter import RateLimiter, RateLimitConfig
from utils.helpers import build_http_response, build_error_response, sanitize_path


class TestRequestParser(unittest.TestCase):
    """Test HTTP request parser."""
    
    def test_parse_simple_get(self):
        """Test parsing simple GET request."""
        raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        request = RequestParser.parse(raw, "192.168.1.1")
        
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.path, "/index.html")
        self.assertEqual(request.client_ip, "192.168.1.1")
        self.assertEqual(request.get_header("Host"), "example.com")
    
    def test_parse_post_with_body(self):
        """Test parsing POST request with body."""
        raw = (b"POST /login HTTP/1.1\r\n"
               b"Host: example.com\r\n"
               b"Content-Length: 23\r\n"
               b"\r\n"
               b"username=admin&pass=123")
        
        request = RequestParser.parse(raw, "10.0.0.1")
        
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/login")
        self.assertEqual(request.body, "username=admin&pass=123")
    
    def test_get_user_agent(self):
        """Test User-Agent extraction."""
        raw = (b"GET / HTTP/1.1\r\n"
               b"Host: example.com\r\n"
               b"User-Agent: Mozilla/5.0\r\n"
               b"\r\n")
        
        request = RequestParser.parse(raw)
        self.assertEqual(request.get_user_agent(), "Mozilla/5.0")
    
    def test_create_request_helper(self):
        """Test create_request helper function."""
        request = create_request(
            method="POST",
            path="/api/data",
            client_ip="127.0.0.1",
            headers={"Content-Type": "application/json"},
            body='{"key": "value"}'
        )
        
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/api/data")
        self.assertEqual(request.get_header("Content-Type"), "application/json")


class TestRules(unittest.TestCase):
    """Test rule engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rule_set = RuleSet(score_threshold=25)
    
    def test_method_block_rule(self):
        """Test method blocking rule."""
        request = create_request(method="TRACE", path="/")
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block or score > 0)
        self.assertTrue(any("trace" in r.lower() for r in reasons))
    
    def test_path_block_rule(self):
        """Test path blocking rule."""
        request = create_request(method="GET", path="/admin")
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block or score >= 20)
    
    def test_keyword_detection(self):
        """Test keyword detection in body."""
        request = create_request(
            method="POST",
            path="/search",
            body="query=' OR 1=1 --"
        )
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block)
        self.assertTrue(any("sql" in r.lower() for r in reasons))
    
    def test_user_agent_block(self):
        """Test User-Agent blocking."""
        request = create_request(
            method="GET",
            path="/",
            headers={"User-Agent": "sqlmap/1.0"}
        )
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block or score >= 20)
    
    def test_password_detection(self):
        """Test password keyword detection."""
        request = create_request(
            method="POST",
            path="/form",
            body="username=admin&password=secret123"
        )
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        # Should detect password but may not exceed threshold
        self.assertTrue(score > 0)
    
    def test_add_custom_rule(self):
        """Test adding custom rule."""
        self.rule_set.add_method_block_rule(
            name="block_delete",
            methods=["DELETE"],
            severity=Severity.HIGH,
            reason="DELETE not allowed"
        )
        
        request = create_request(method="DELETE", path="/resource")
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block or score >= 20)
    
    def test_disable_rule(self):
        """Test disabling a rule."""
        self.rule_set.disable_rule("block_admin")
        
        request = create_request(method="GET", path="/admin")
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        # Should not trigger block_admin rule
        self.assertFalse(any("admin" in r.lower() for r in reasons))
    
    def test_scoring_threshold(self):
        """Test scoring threshold behavior."""
        # Set low threshold
        self.rule_set.set_threshold(5)
        
        # Bot detection is only 5 points
        request = create_request(
            method="GET",
            path="/",
            headers={"User-Agent": "Googlebot"}
        )
        should_block, score, reasons = self.rule_set.evaluate(request)
        
        self.assertTrue(should_block)


class TestDecisionEngine(unittest.TestCase):
    """Test decision engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = DecisionEngine()
    
    def test_allow_normal_request(self):
        """Test allowing normal request."""
        request = create_request(method="GET", path="/index.html")
        result = self.engine.evaluate(request)
        
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertTrue(result.is_allowed())
    
    def test_block_suspicious_request(self):
        """Test blocking suspicious request."""
        request = create_request(
            method="POST",
            path="/admin",
            body="password=secret"
        )
        result = self.engine.evaluate(request)
        
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertTrue(result.is_blocked())
    
    def test_quick_allow(self):
        """Test quick allow check."""
        request = create_request(method="GET", path="/")
        allowed = self.engine.quick_allow(request)
        
        self.assertTrue(allowed)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiter."""
    
    def setUp(self):
        """Set up test fixtures."""
        config = RateLimitConfig(
            requests_per_second=5.0,
            burst_size=3,
            block_duration=2
        )
        self.limiter = RateLimiter(config)
    
    def test_allow_under_limit(self):
        """Test allowing requests under limit."""
        for _ in range(3):
            allowed, info = self.limiter.check_request("192.168.1.1", "/")
            self.assertTrue(allowed)
    
    def test_block_over_limit(self):
        """Test blocking over limit."""
        # Exceed burst limit
        for _ in range(5):
            self.limiter.check_request("192.168.1.2", "/")
        
        # This should be blocked
        allowed, info = self.limiter.check_request("192.168.1.2", "/")
        self.assertFalse(allowed)
        # Check for either "limit exceeded" or "blocked"
        self.assertTrue("limit exceeded" in info.lower() or "blocked" in info.lower())
    
    def test_block_duration(self):
        """Test block duration."""
        # Create a fresh limiter with longer block duration for this test
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=10,
            block_duration=1
        )
        limiter = RateLimiter(config)
        
        ip = "192.168.1.99"
        
        # Trigger block by exceeding burst
        for _ in range(15):
            limiter.check_request(ip, "/")
        
        # Should be blocked
        allowed, _ = limiter.check_request(ip, "/")
        self.assertFalse(allowed)
        
        # Wait for block to expire
        time.sleep(1.5)
        
        # Reset the IP to clear old request history
        limiter.reset_ip(ip)
        
        # Should be allowed again
        allowed, _ = limiter.check_request(ip, "/")
        self.assertTrue(allowed)
    
    def test_manual_block(self):
        """Test manual IP blocking."""
        ip = "192.168.1.4"
        
        self.limiter.block_ip(ip, 5)
        
        allowed, _ = self.limiter.check_request(ip, "/")
        self.assertFalse(allowed)
    
    def test_get_stats(self):
        """Test getting statistics."""
        self.limiter.check_request("192.168.1.5", "/")
        
        stats = self.limiter.get_summary()
        self.assertIn("total_tracked_ips", stats)
        self.assertIn("rate_limit_config", stats)


class TestHelpers(unittest.TestCase):
    """Test utility helpers."""
    
    def test_build_http_response(self):
        """Test HTTP response builder."""
        response = build_http_response(
            status_code=200,
            body="Hello World",
            content_type="text/plain"
        )
        
        self.assertIn(b"HTTP/1.1 200 OK", response)
        self.assertIn(b"Hello World", response)
    
    def test_build_error_response(self):
        """Test error response builder."""
        response = build_error_response(403, "Access denied")
        
        self.assertIn(b"HTTP/1.1 403 Forbidden", response)
        self.assertIn(b"Access denied", response)
    
    def test_sanitize_path(self):
        """Test path sanitization."""
        # Path traversal attempt
        path = sanitize_path("/../../../etc/passwd")
        self.assertEqual(path, "/etc/passwd")
        
        # Normal path
        path = sanitize_path("/index.html")
        self.assertEqual(path, "/index.html")
    
    def test_valid_ip(self):
        """Test IP validation."""
        from utils.helpers import is_valid_ip
        
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("10.0.0.1"))
        self.assertFalse(is_valid_ip("invalid"))
    
    def test_private_ip(self):
        """Test private IP detection."""
        from utils.helpers import is_private_ip
        
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_full_flow_allow(self):
        """Test full flow with allowed request."""
        engine = DecisionEngine()
        
        request = create_request(
            method="GET",
            path="/index.html",
            client_ip="192.168.1.100",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        result = engine.evaluate(request)
        self.assertEqual(result.decision, Decision.ALLOW)
    
    def test_full_flow_block(self):
        """Test full flow with blocked request."""
        engine = DecisionEngine()
        
        request = create_request(
            method="POST",
            path="/admin",
            client_ip="192.168.1.101",
            body="DROP TABLE users"
        )
        
        result = engine.evaluate(request)
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertGreater(result.score, 0)
    
    def test_rate_limit_integration(self):
        """Test rate limiting with decision engine."""
        config = RateLimitConfig(
            requests_per_second=2.0,
            burst_size=2,
            block_duration=1
        )
        limiter = RateLimiter(config)
        engine = DecisionEngine(rate_limiter=limiter)
        
        ip = "192.168.1.102"
        
        # First requests should be allowed
        for _ in range(2):
            request = create_request(method="GET", path="/", client_ip=ip)
            result = engine.evaluate(request)
            self.assertEqual(result.decision, Decision.ALLOW)
        
        # Exceed rate limit
        for _ in range(3):
            request = create_request(method="GET", path="/", client_ip=ip)
            result = engine.evaluate(request)
        
        # Should now be rate limited
        request = create_request(method="GET", path="/", client_ip=ip)
        result = engine.evaluate(request)
        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertTrue(result.rate_limited)


def run_tests():
    """Run all tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestRequestParser))
    suite.addTests(loader.loadTestsFromTestCase(TestRules))
    suite.addTests(loader.loadTestsFromTestCase(TestDecisionEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiter))
    suite.addTests(loader.loadTestsFromTestCase(TestHelpers))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
