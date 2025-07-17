import os
import secrets
import logging
import time
from typing import Dict, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

class AuthConfig:
    """Authentication configuration and utilities."""
    
    def __init__(self):
        self.api_key = os.getenv('MCP_API_KEY')
        self.require_auth = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'
        
        if self.require_auth and not self.api_key:
            logger.warning("REQUIRE_AUTH is true but MCP_API_KEY not set. Generating random key.")
            self.api_key = self._generate_api_key()
            logger.info(f"Generated API key: {self.api_key[:8]}...")
    
    def _generate_api_key(self) -> str:
        """Generate a secure random API key."""
        return f"mcp_{secrets.token_urlsafe(32)}"
    
    def is_valid_api_key(self, provided_key: Optional[str]) -> bool:
        """Validate the provided API key."""
        if not self.require_auth:
            return True
        
        if not provided_key or not self.api_key:
            return False
        
        return secrets.compare_digest(self.api_key, provided_key)

class RateLimiter:
    """Simple rate limiting based on IP address or user identifier."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
    
    def is_allowed(self, identifier: str) -> Tuple[bool, int]:
        """Check if request is allowed and return remaining requests.
        
        Args:
            identifier: Can be an IP address or user identifier (e.g., slack:username)
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier] 
            if req_time > window_start
        ]
        
        current_requests = len(self.requests[identifier])
        
        if current_requests >= self.max_requests:
            return False, 0
        
        # Add current request
        self.requests[identifier].append(now)
        remaining = self.max_requests - (current_requests + 1)
        
        return True, remaining

class SecurityLogger:
    """Security event logging."""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_auth_success(self, client_ip: str, user_agent: str = None):
        """Log successful authentication."""
        self.logger.info(f"AUTH_SUCCESS - IP: {client_ip} - UA: {user_agent}")
    
    def log_auth_failure(self, client_ip: str, reason: str, user_agent: str = None):
        """Log authentication failure."""
        self.logger.warning(f"AUTH_FAILURE - IP: {client_ip} - Reason: {reason} - UA: {user_agent}")
    
    def log_rate_limit(self, identifier: str, user_agent: str = None):
        """Log rate limit violation."""
        self.logger.warning(f"RATE_LIMIT - ID: {identifier} - UA: {user_agent}")
    
    def log_opportunity_access(self, client_ip: str, count: int, user_agent: str = None):
        """Log opportunity data access."""
        self.logger.info(f"OPPORTUNITY_ACCESS - IP: {client_ip} - Count: {count} - UA: {user_agent}")

# Global instances
auth_config = AuthConfig()
rate_limiter = RateLimiter(
    max_requests=int(os.getenv('RATE_LIMIT_REQUESTS', '50')),
    window_seconds=int(os.getenv('RATE_LIMIT_WINDOW', '3600'))
)
security_logger = SecurityLogger()