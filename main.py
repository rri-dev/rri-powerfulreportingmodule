#!/usr/bin/env python3

import asyncio
import logging
import os
import json
from typing import Dict, Any
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
import openai
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

# Initialize OpenAI client
openai.api_key = os.getenv('OPENAI_API_KEY')

def add_security_headers(response):
    """Add security headers to response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@mcp.custom_route("/health", methods=["GET"])
def health_check(request):
    """Health check endpoint for monitoring."""
    import json
    from starlette.responses import JSONResponse
    
    try:
        connection_status = sf_client.test_connection()
        response_data = {
            "status": "healthy",
            "salesforce_connected": connection_status.get("success", False),
            "timestamp": str(asyncio.get_event_loop().time() if asyncio.get_running_loop() else "N/A"),
            "auth_required": auth_config.require_auth,
            "rate_limit_enabled": True
        }
        return JSONResponse(response_data)
    except Exception as e:
        error_data = {
            "status": "unhealthy",
            "error": str(e),
            "salesforce_connected": False,
            "auth_required": auth_config.require_auth
        }
        return JSONResponse(error_data, status_code=500)

@mcp.custom_route("/slack/commands", methods=["POST"])
async def slack_command(request: Request):
    """Handle Slack slash commands"""
    import hmac
    import hashlib
    import time
    
    try:
        # Get raw body first for signature verification
        body = await request.body()
        
        # Verify Slack signature (optional but recommended)
        slack_signing_secret = os.getenv('SLACK_SIGNING_SECRET')
        if slack_signing_secret:
            timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
            slack_signature = request.headers.get('X-Slack-Signature', '')
            
            # Verify timestamp is recent (within 5 minutes)
            if abs(time.time() - int(timestamp)) > 300:
                return JSONResponse({"text": "Request too old"}, status_code=400)
            
            # Verify signature
            sig_basestring = f'v0:{timestamp}:{body.decode()}'
            computed_signature = 'v0=' + hmac.new(
                slack_signing_secret.encode(),
                sig_basestring.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(computed_signature, slack_signature):
                return JSONResponse({"text": "Invalid signature"}, status_code=401)
        
        # Parse form data from raw body
        from urllib.parse import parse_qs
        form_data = parse_qs(body.decode())
        
        # Parse Slack command (parse_qs returns lists)
        command = form_data.get('command', [''])[0]
        text = form_data.get('text', [''])[0]
        user_name = form_data.get('user_name', ['unknown'])[0]
        channel_name = form_data.get('channel_name', ['unknown'])[0]
        
        logger.info(f"Slack command: {command} {text} from {user_name} in #{channel_name}")
        
        # Handle /prm command
        if command == '/prm':
            response_text = await handle_prm_command(text, user_name)
            return JSONResponse({
                "response_type": "in_channel",
                "text": response_text
            })
        else:
            return JSONResponse({
                "text": f"Unknown command: {command}"
            })
            
    except Exception as e:
        logger.error(f"Slack command error: {e}")
        return JSONResponse({
            "text": "Sorry, there was an error processing your request."
        }, status_code=500)

async def handle_prm_command(text: str, user_name: str) -> str:
    """Handle PRM command with GPT integration"""
    try:
        # Get opportunities data
        if "today" in text.lower() and "opportunit" in text.lower():
            opportunities_data = get_todays_opportunities()
            
            if not opportunities_data.get('success'):
                return f"❌ Error fetching opportunities: {opportunities_data.get('error', 'Unknown error')}"
            
            opportunities = opportunities_data.get('opportunities', [])
            
            if not opportunities:
                return "📊 No opportunities were created today."
            
            # Use GPT to format the response
            gpt_prompt = f"""
            Format the following opportunities data for a Slack message. Be concise but informative.
            
            Data: {json.dumps(opportunities, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            Create a professional, easy-to-read summary. Use emojis and formatting appropriate for Slack.
            Include key metrics like total count, stages, and highlight any large deals.
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful sales assistant that formats Salesforce data for Slack messages."},
                        {"role": "user", "content": gpt_prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.3
                )
                
                formatted_response = response.choices[0].message.content
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, len(opportunities), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error: {gpt_error}")
                # Fallback to simple formatting
                return format_opportunities_simple(opportunities, user_name)
        
        else:
            # Handle other PRM commands
            return f"🤖 Hi {user_name}! Available commands:\n• `/prm today's opportunities` - Get opportunities created today"
            
    except Exception as e:
        logger.error(f"PRM command error: {e}")
        return f"❌ Error processing request: {str(e)}"

def format_opportunities_simple(opportunities: list, user_name: str) -> str:
    """Simple fallback formatting for opportunities"""
    if not opportunities:
        return "📊 No opportunities found."
    
    total_count = len(opportunities)
    total_amount = sum(opp.get('amount', 0) or 0 for opp in opportunities)
    
    # Group by stage
    stages = {}
    for opp in opportunities:
        stage = opp.get('stage', 'Unknown')
        stages[stage] = stages.get(stage, 0) + 1
    
    response = f"📊 **Today's Opportunities Report** (requested by {user_name})\n\n"
    response += f"**Total:** {total_count} opportunities"
    
    if total_amount > 0:
        response += f" | **Pipeline Value:** ${total_amount:,.0f}"
    
    response += "\n\n**By Stage:**\n"
    for stage, count in stages.items():
        response += f"• {stage}: {count}\n"
    
    if len(opportunities) <= 5:
        response += "\n**Details:**\n"
        for opp in opportunities:
            amount_str = f" (${opp.get('amount', 0):,.0f})" if opp.get('amount') else ""
            response += f"• {opp.get('name', 'Unknown')} - {opp.get('stage', 'Unknown')} - {opp.get('owner', 'Unknown')}{amount_str}\n"
    
    return response

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