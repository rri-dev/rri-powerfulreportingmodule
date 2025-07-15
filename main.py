#!/usr/bin/env python3

import asyncio
import logging
import os
from typing import Dict, Any
from fastmcp import FastMCP
from lib.salesforce_client import SalesforceClient
from lib.auth import auth_config, rate_limiter, security_logger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def auth_middleware(request):
    """Authentication middleware for MCP endpoints."""
    client_ip = request.client.host if hasattr(request, 'client') else 'unknown'
    user_agent = request.headers.get('user-agent', 'unknown')
    
    # Skip auth for health endpoint
    if request.url.path == '/health':
        return None
    
    # Check rate limiting first
    allowed, remaining = rate_limiter.is_allowed(client_ip)
    if not allowed:
        security_logger.log_rate_limit(client_ip, user_agent)
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Check API key authentication
    api_key = request.headers.get('x-api-key')
    if not auth_config.is_valid_api_key(api_key):
        security_logger.log_auth_failure(client_ip, "Invalid or missing API key", user_agent)
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    
    security_logger.log_auth_success(client_ip, user_agent)
    return None

mcp = FastMCP("Today's Opportunities MCP Server", middleware=[auth_middleware])
sf_client = SalesforceClient()

def add_security_headers(response):
    """Add security headers to response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@mcp.custom_route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        connection_status = sf_client.test_connection()
        response_data = {
            "status": "healthy",
            "salesforce_connected": connection_status.get("success", False),
            "timestamp": str(asyncio.get_event_loop().time() if asyncio.get_running_loop() else "N/A"),
            "auth_required": auth_config.require_auth,
            "rate_limit_enabled": True
        }
        return response_data
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "salesforce_connected": False,
            "auth_required": auth_config.require_auth
        }

@mcp.tool()
def get_todays_opportunities() -> Dict[str, Any]:
    """Get all opportunities created today with their name, stage, and owner information."""
    try:
        sf = sf_client.get_client()
        
        # SOQL query to get opportunities created today
        soql = """
        SELECT Id, Name, StageName, Owner.Name, CreatedDate, Amount, CloseDate
        FROM Opportunity 
        WHERE CreatedDate = TODAY
        ORDER BY CreatedDate DESC
        """
        
        result = sf.query(soql)
        
        # Format the results for better readability
        opportunities = []
        for record in result['records']:
            opportunities.append({
                "id": record['Id'],
                "name": record['Name'],
                "stage": record['StageName'],
                "owner": record['Owner']['Name'],
                "amount": record.get('Amount'),
                "close_date": record.get('CloseDate'),
                "created_date": record['CreatedDate']
            })
        
        # Log opportunity access for security monitoring
        security_logger.log_opportunity_access('authenticated_user', len(opportunities))
        
        return {
            "success": True,
            "total_count": result['totalSize'],
            "opportunities": opportunities,
            "summary": f"Found {len(opportunities)} opportunities created today"
        }
        
    except Exception as e:
        logger.error(f"Failed to get today's opportunities: {e}")
        return {
            "success": False,
            "error": str(e),
            "opportunities": []
        }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    # Log startup information
    logger.info(f"Starting MCP Server on {host}:{port}")
    logger.info(f"Authentication required: {auth_config.require_auth}")
    logger.info(f"Rate limiting: {rate_limiter.max_requests} requests per {rate_limiter.window_seconds} seconds")
    
    if auth_config.require_auth and auth_config.api_key:
        logger.info(f"API Key configured: {auth_config.api_key[:8]}...")
    
    mcp.run(
        transport="http",
        host=host,
        port=port,
        path="/mcp",
        log_level=os.getenv("LOG_LEVEL", "info")
    )