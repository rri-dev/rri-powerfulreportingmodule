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
            # Respond immediately to avoid timeout
            response_url = form_data.get('response_url', [''])[0]
            
            # Start background processing
            asyncio.create_task(process_prm_command_async(text, user_name, response_url))
            
            return JSONResponse({
                "response_type": "in_channel",
                "text": "🔄 Fetching today's opportunities... please wait"
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

async def process_prm_command_async(text: str, user_name: str, response_url: str):
    """Process PRM command asynchronously and send result to Slack"""
    import httpx
    
    try:
        response_text = await handle_prm_command(text, user_name)
        
        # Send the result back to Slack
        async with httpx.AsyncClient() as client:
            await client.post(response_url, json={
                "response_type": "in_channel",
                "text": response_text,
                "replace_original": True
            })
            
    except Exception as e:
        logger.error(f"Async PRM command error: {e}")
        # Send error response
        async with httpx.AsyncClient() as client:
            await client.post(response_url, json={
                "response_type": "in_channel", 
                "text": f"❌ Error processing request: {str(e)}",
                "replace_original": True
            })

async def handle_prm_command(text: str, user_name: str) -> str:
    """Handle PRM command with GPT integration"""
    try:
        # Get opportunities data
        if "today" in text.lower() and "opportunit" in text.lower():
            opportunities_data = _fetch_todays_opportunities()
            
            if not opportunities_data.get('success'):
                return f"❌ Error fetching opportunities: {opportunities_data.get('error', 'Unknown error')}"
            
            all_opportunities = opportunities_data.get('all_opportunities', [])
            top_closed_won = opportunities_data.get('top_closed_won', [])
            summary_stats = opportunities_data.get('summary_stats', {})
            
            if not all_opportunities:
                return "📊 No opportunities were created today."
            
            # Summarize data for GPT to avoid token limits
            summary_data = {
                "summary_stats": summary_stats,
                "top_closed_won_details": []
            }
            
            # Only include detailed product info for top 3 closed won deals
            for opp in top_closed_won:
                # Summarize products to reduce token usage
                product_summary = ""
                if opp.get('products'):
                    product_names = [p['name'] for p in opp['products'][:3]]  # Limit to top 3
                    total_products = len(opp['products'])
                    if total_products > 3:
                        product_summary = f"{', '.join(product_names)} (+{total_products-3} more)"
                    else:
                        product_summary = ', '.join(product_names)
                
                summary_data["top_closed_won_details"].append({
                    "name": opp['name'],
                    "stage": opp['stage'],
                    "owner": opp['owner'],
                    "amount": opp.get('amount'),
                    "products": product_summary
                })
            
            # Use GPT to format the response
            gpt_prompt = f"""
            Format the following sales activity data for a Slack message. Be concise but informative.
            
            Data: {json.dumps(summary_data, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            Create a professional summary showing:
            1. Overall activity summary (total opportunities, stages breakdown, pipeline value)  
            2. Revenue won today from closed deals
            3. Detailed summaries of the top 3 closed won deals with products/services
            
            Use emojis and Slack formatting. Focus on celebrating wins while showing complete picture.
            
            IMPORTANT FORMATTING RULES FOR SLACK:
            - Use *text* for emphasis (single asterisks only)
            - NEVER use **double asterisks** - they don't work in Slack
            - Use simple bullet points with •
            - Keep it clean and readable
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful sales assistant that formats Salesforce data for Slack messages. Keep responses concise."},
                        {"role": "user", "content": gpt_prompt}
                    ],
                    max_tokens=500,
                    temperature=0.2
                )
                
                formatted_response = response.choices[0].message.content
                
                # Fix any remaining bold formatting for Slack
                formatted_response = formatted_response.replace('**', '*')
                formatted_response = formatted_response.replace('###', '')
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, len(all_opportunities), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error: {gpt_error}")
                # Fallback to simple formatting
                return format_opportunities_simple(all_opportunities, top_closed_won, summary_stats, user_name)
        
        else:
            # Handle other PRM commands
            return f"🤖 Hi {user_name}! Available commands:\n• `/prm today's opportunities` - Get opportunities created today"
            
    except Exception as e:
        logger.error(f"PRM command error: {e}")
        return f"❌ Error processing request: {str(e)}"

def format_opportunities_simple(all_opportunities: list, top_closed_won: list, summary_stats: dict, user_name: str) -> str:
    """Simple fallback formatting for opportunities"""
    if not all_opportunities:
        return "📊 No opportunities found."
    
    total_count = summary_stats.get('total_count', 0)
    total_pipeline_value = summary_stats.get('total_pipeline_value', 0)
    total_closed_won_revenue = summary_stats.get('total_closed_won_revenue', 0)
    stages_breakdown = summary_stats.get('stages_breakdown', {})
    
    response = f"📊 *Today's Sales Activity Summary* (requested by {user_name})\n\n"
    response += f"*Total Opportunities:* {total_count}"
    
    if total_pipeline_value > 0:
        response += f" | *Pipeline Value:* ${total_pipeline_value:,.0f}"
    
    if total_closed_won_revenue > 0:
        response += f" | *Revenue Won:* ${total_closed_won_revenue:,.0f}"
    
    response += "\n\n*By Stage:*\n"
    for stage, count in stages_breakdown.items():
        response += f"• {stage}: {count}\n"
    
    if top_closed_won:
        response += f"\n🎉 *Top {len(top_closed_won)} Deals Closed Today:*\n"
        for opp in top_closed_won:
            amount_str = f"${opp.get('amount', 0):,.0f}" if opp.get('amount') else "Amount TBD"
            response += f"🏆 *{opp.get('name', 'Unknown')}* - {amount_str} - {opp.get('owner', 'Unknown')}\n"
    
    return response

def _fetch_todays_opportunities() -> Dict[str, Any]:
    """Internal function to fetch opportunities data."""
    try:
        sf = sf_client.get_client()
        
        # Query 1: Get ALL opportunities created today for summary
        all_opportunities_soql = """
        SELECT Id, Name, StageName, Owner.Name, CreatedDate, Amount, CloseDate
        FROM Opportunity 
        WHERE CreatedDate = TODAY AND StageName = 'Closed Won'
        ORDER BY CreatedDate DESC
        """
        
        all_result = sf.query(all_opportunities_soql)
        
        # Query 2: Get top 3 closed won opportunities with products
        closed_won_soql = """
        SELECT Id, Name, StageName, Owner.Name, CreatedDate, Amount, CloseDate,
               (SELECT Id, Product2.Name, Product2.Description, Quantity, UnitPrice, TotalPrice 
                FROM OpportunityLineItems 
                ORDER BY TotalPrice DESC)
        FROM Opportunity 
        WHERE CreatedDate = TODAY AND StageName = 'Closed Won'
        ORDER BY Amount DESC NULLS LAST
        LIMIT 3
        """
        
        closed_won_result = sf.query(closed_won_soql)
        
        # Format ALL opportunities for summary stats
        all_opportunities = []
        for record in all_result['records']:
            all_opportunities.append({
                "id": record['Id'],
                "name": record['Name'],
                "stage": record['StageName'],
                "owner": record['Owner']['Name'],
                "amount": record.get('Amount'),
                "close_date": record.get('CloseDate'),
                "created_date": record['CreatedDate']
            })
        
        # Format top 3 closed won opportunities with product details
        top_closed_won = []
        for record in closed_won_result['records']:
            # Extract product information
            products = []
            if record.get('OpportunityLineItems') and record['OpportunityLineItems'].get('records'):
                for line_item in record['OpportunityLineItems']['records']:
                    products.append({
                        "name": line_item['Product2']['Name'],
                        "description": line_item['Product2'].get('Description', ''),
                        "quantity": line_item.get('Quantity', 0),
                        "unit_price": line_item.get('UnitPrice', 0),
                        "total_price": line_item.get('TotalPrice', 0)
                    })
            
            top_closed_won.append({
                "id": record['Id'],
                "name": record['Name'],
                "stage": record['StageName'],
                "owner": record['Owner']['Name'],
                "amount": record.get('Amount'),
                "close_date": record.get('CloseDate'),
                "created_date": record['CreatedDate'],
                "products": products
            })
        
        # Calculate summary statistics
        stages_breakdown = {}
        total_pipeline_value = 0
        total_closed_won_revenue = 0
        
        for opp in all_opportunities:
            stage = opp['stage']
            stages_breakdown[stage] = stages_breakdown.get(stage, 0) + 1
            if opp.get('amount'):
                total_pipeline_value += opp['amount']
                if stage == 'Closed Won':
                    total_closed_won_revenue += opp['amount']
        
        # Log opportunity access for security monitoring
        security_logger.log_opportunity_access('authenticated_user', len(all_opportunities))
        
        return {
            "success": True,
            "all_opportunities": all_opportunities,
            "top_closed_won": top_closed_won,
            "summary_stats": {
                "total_count": len(all_opportunities),
                "stages_breakdown": stages_breakdown,
                "total_pipeline_value": total_pipeline_value,
                "total_closed_won_revenue": total_closed_won_revenue,
                "closed_won_count": len(top_closed_won)
            },
            "summary": f"Found {len(all_opportunities)} opportunities created today, {len(top_closed_won)} closed won"
        }
        
    except Exception as e:
        logger.error(f"Failed to get today's opportunities: {e}")
        return {
            "success": False,
            "error": str(e),
            "all_opportunities": [],
            "top_closed_won": [],
            "summary_stats": {}
        }

@mcp.tool()
def get_todays_opportunities() -> Dict[str, Any]:
    """Get all opportunities created today with their name, stage, and owner information."""
    return _fetch_todays_opportunities()

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