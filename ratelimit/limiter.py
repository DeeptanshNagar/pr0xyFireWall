"""
Rate Limiting Module

Implements stateful rate limiting with thread-safe data structures.
Tracks requests per IP with configurable limits and time windows.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class RateLimitConfig:
    """
    Configuration for rate limiting.
    
    Attributes:
        requests_per_second: Maximum requests allowed per second
        requests_per_minute: Maximum requests allowed per minute
        burst_size: Allow short bursts up to this size
        block_duration: Seconds to block after limit exceeded
    """
    requests_per_second: float = 10.0
    requests_per_minute: float = 100.0
    burst_size: int = 20
    block_duration: int = 60
    
    def __post_init__(self):
        # Calculate minimum interval between requests
        self.min_interval = 1.0 / self.requests_per_second if self.requests_per_second > 0 else 0


@dataclass
class ClientStats:
    """
    Statistics for a single client IP.
    
    Tracks request timestamps for sliding window rate limiting.
    """
    requests: list[float] = field(default_factory=list)
    blocked_until: float = 0.0
    total_requests: int = 0
    blocked_count: int = 0
    
    def is_blocked(self, current_time: float) -> bool:
        """Check if client is currently blocked."""
        if current_time < self.blocked_until:
            return True
        # Reset block if expired
        if self.blocked_until > 0 and current_time >= self.blocked_until:
            self.blocked_until = 0
        return False
    
    def block(self, duration: int, current_time: float) -> None:
        """Block client for specified duration."""
        self.blocked_until = current_time + duration
        self.blocked_count += 1
    
    def add_request(self, current_time: float) -> None:
        """Record a new request timestamp."""
        self.requests.append(current_time)
        self.total_requests += 1
    
    def cleanup_old_requests(self, window_seconds: float, current_time: float) -> None:
        """Remove request timestamps outside the window."""
        cutoff = current_time - window_seconds
        self.requests = [t for t in self.requests if t > cutoff]


class RateLimiter:
    """
    Thread-safe rate limiter for HTTP requests.
    
    Implements sliding window rate limiting with per-IP tracking.
    Uses thread-safe data structures for concurrent access.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config or RateLimitConfig()
        
        # Thread-safe storage for client statistics
        self._clients: Dict[str, ClientStats] = defaultdict(ClientStats)
        self._lock = threading.RLock()
        
        # Cleanup tracking
        self._last_cleanup = time.time()
        self._cleanup_interval = 60.0  # Cleanup every 60 seconds
    
    def check_request(
        self,
        client_ip: str,
        path: str = ""
    ) -> Tuple[bool, str]:
        """
        Check if a request should be allowed based on rate limits.
        
        Args:
            client_ip: Client IP address
            path: Request path (for logging/debugging)
            
        Returns:
            Tuple of (allowed, info_message)
        """
        current_time = time.time()
        
        # Periodic cleanup of old entries
        self._maybe_cleanup(current_time)
        
        with self._lock:
            stats = self._clients[client_ip]
            
            # Check if client is currently blocked
            if stats.is_blocked(current_time):
                remaining = int(stats.blocked_until - current_time)
                return False, f"Blocked for {remaining} more seconds"
            
            # Clean up old requests for this client
            stats.cleanup_old_requests(60.0, current_time)
            
            # Check per-second rate limit
            recent_requests = len([t for t in stats.requests 
                                   if current_time - t <= 1.0])
            
            if recent_requests >= self.config.requests_per_second:
                stats.block(self.config.block_duration, current_time)
                return False, f"Rate limit exceeded: {recent_requests} req/sec"
            
            # Check burst limit
            if len(stats.requests) >= self.config.burst_size:
                stats.block(self.config.block_duration, current_time)
                return False, f"Burst limit exceeded: {self.config.burst_size}"
            
            # Check per-minute rate limit
            if self.config.requests_per_minute > 0:
                minute_requests = len(stats.requests)
                if minute_requests >= self.config.requests_per_minute:
                    stats.block(self.config.block_duration, current_time)
                    return False, f"Per-minute limit exceeded"
            
            # Record this request
            stats.add_request(current_time)
            
            # Return allowed with current rate info
            rate_info = f"{recent_requests + 1} req/sec"
            return True, rate_info
    
    def _maybe_cleanup(self, current_time: float) -> None:
        """Periodically clean up old client entries."""
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._lock:
            # Remove clients with no recent activity and not blocked
            cutoff = current_time - 300  # 5 minutes of inactivity
            to_remove = [
                ip for ip, stats in self._clients.items()
                if not stats.is_blocked(current_time) and (
                    not stats.requests or 
                    (stats.requests and max(stats.requests) < cutoff)
                )
            ]
            for ip in to_remove:
                del self._clients[ip]
            
            self._last_cleanup = current_time
    
    def get_client_stats(self, client_ip: str) -> Optional[dict]:
        """
        Get statistics for a specific client.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Dictionary with client statistics or None
        """
        with self._lock:
            stats = self._clients.get(client_ip)
            if not stats:
                return None
            
            current_time = time.time()
            recent_count = len([t for t in stats.requests 
                               if current_time - t <= 1.0])
            
            return {
                "ip": client_ip,
                "total_requests": stats.total_requests,
                "recent_requests_1s": recent_count,
                "is_blocked": stats.is_blocked(current_time),
                "blocked_count": stats.blocked_count,
                "blocked_until": stats.blocked_until if stats.blocked_until > current_time else None
            }
    
    def get_all_stats(self) -> Dict[str, dict]:
        """Get statistics for all tracked clients."""
        with self._lock:
            return {
                ip: self.get_client_stats(ip) 
                for ip in self._clients.keys()
            }
    
    def block_ip(self, client_ip: str, duration_seconds: int) -> None:
        """
        Manually block an IP address.
        
        Args:
            client_ip: IP to block
            duration_seconds: Block duration in seconds
        """
        with self._lock:
            stats = self._clients[client_ip]
            stats.block(duration_seconds, time.time())
    
    def unblock_ip(self, client_ip: str) -> bool:
        """
        Manually unblock an IP address.
        
        Args:
            client_ip: IP to unblock
            
        Returns:
            True if IP was unblocked, False if not found
        """
        with self._lock:
            stats = self._clients.get(client_ip)
            if stats:
                stats.blocked_until = 0
                return True
            return False
    
    def reset_ip(self, client_ip: str) -> bool:
        """
        Reset all statistics for an IP.
        
        Args:
            client_ip: IP to reset
            
        Returns:
            True if IP was found and reset
        """
        with self._lock:
            if client_ip in self._clients:
                del self._clients[client_ip]
                return True
            return False
    
    def get_summary(self) -> dict:
        """Get summary statistics."""
        with self._lock:
            total_clients = len(self._clients)
            blocked_clients = sum(
                1 for s in self._clients.values() 
                if s.is_blocked(time.time())
            )
            total_requests = sum(s.total_requests for s in self._clients.values())
            
            return {
                "total_tracked_ips": total_clients,
                "currently_blocked": blocked_clients,
                "total_requests_tracked": total_requests,
                "rate_limit_config": {
                    "requests_per_second": self.config.requests_per_second,
                    "requests_per_minute": self.config.requests_per_minute,
                    "burst_size": self.config.burst_size,
                    "block_duration": self.config.block_duration
                }
            }
    
    def update_config(self, config: RateLimitConfig) -> None:
        """Update rate limiting configuration."""
        with self._lock:
            self.config = config
