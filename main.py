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
            
            # Dynamic loading message based on command type
            if "event" in text.lower():
                loading_message = "🔄 Fetching upcoming events... please wait"
            elif "today" in text.lower() and "opportunit" in text.lower():
                loading_message = "🔄 Fetching today's opportunities... please wait"
            else:
                loading_message = "🔄 Processing your request... please wait"
            
            # Start background processing
            asyncio.create_task(process_prm_command_async(text, user_name, response_url))
            
            return JSONResponse({
                "response_type": "in_channel",
                "text": loading_message
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
                return "📊 No Closed Won opportunities were created today."
            
            # Summarize data for GPT to avoid token limits - DO NOT send all 304+ records
            summary_data = {
                "daily_summary": {
                    "total_deals_closed_today": summary_stats.get('total_count', 0),
                    "total_revenue_won_today": summary_stats.get('total_closed_won_revenue', 0),
                    "showing_top_deals": min(len(top_closed_won), 3)
                },
                "top_deals_details": []
            }
            
            # Only include detailed product info for top 3 closed won deals
            for opp in top_closed_won[:3]:  # Ensure only top 3
                # Summarize products to reduce token usage
                product_summary = ""
                if opp.get('products'):
                    product_names = [p['name'] for p in opp['products'][:3]]  # Limit to top 3
                    total_products = len(opp['products'])
                    if total_products > 3:
                        product_summary = f"{', '.join(product_names)} (+{total_products-3} more)"
                    else:
                        product_summary = ', '.join(product_names)
                
                summary_data["top_deals_details"].append({
                    "name": opp['name'],
                    "owner": opp['owner'],
                    "amount": opp.get('amount'),
                    "products": product_summary
                })
            
            # Log the data being sent to GPT for debugging
            logger.info(f"GPT input summary_stats: {summary_stats}")
            logger.info(f"GPT input data size: all_opportunities={len(all_opportunities)}, top_closed_won={len(top_closed_won)}")
            
            # Use GPT to format the response
            gpt_prompt = f"""
            Format the following sales activity data for a Slack message. Be concise but informative.
            
            Data: {json.dumps(summary_data, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            IMPORTANT: You must show the EXACT total count from daily_summary.total_deals_closed_today
            
            Create a professional summary showing:
            1. TOTAL closed won deals for today (use exact number from daily_summary.total_deals_closed_today)
            2. TOTAL revenue won today (use exact number from daily_summary.total_revenue_won_today)  
            3. Detailed summaries of top 3 deals with products (from top_deals_details)
            4. If total > 3, say "(showing top 3 of [TOTAL] deals)"
            
            Use emojis and Slack formatting. The total count MUST be accurate.
            
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
                
                # Verify GPT didn't mess up the total count
                expected_total = summary_stats.get('total_count', 0)
                if expected_total > 10 and str(expected_total) not in formatted_response:
                    logger.warning(f"GPT response may have wrong total. Expected: {expected_total}, Response: {formatted_response[:200]}...")
                    # Could add fallback logic here if needed
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, len(all_opportunities), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error: {gpt_error}")
                # Fallback to simple formatting
                return format_opportunities_simple(all_opportunities, top_closed_won, summary_stats, user_name)
        
        # Get events data
        elif "event" in text.lower():
            events_data = _fetch_upcoming_events()
            
            if not events_data.get('success'):
                return f"❌ Error fetching events: {events_data.get('error', 'Unknown error')}"
            
            events = events_data.get('events', [])
            summary_stats = events_data.get('summary_stats', {})
            
            if not events:
                return "📅 No upcoming events found in the next 3 months."
            
            # Prepare data for GPT formatting
            events_summary = {
                "summary": {
                    "total_events": summary_stats.get('total_count', 0),
                    "date_range": summary_stats.get('date_range', 'next 3 months')
                },
                "events": events[:10]  # Limit to first 10 events for compact Slack display
            }
            
            # Use GPT to format the events as a table
            events_prompt = f"""
            Format the following events data for a Slack message as a clean table. Be concise but informative.
            
            Data: {json.dumps(events_summary, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            Create a professional table showing:
            1. Total number of events in the next 3 months
            2. A table with columns: Event Name, Start Date, End Date, Type, Location
            3. If there are more than 10 events, mention "(showing first 10 of [TOTAL])"
            
            Use emojis and Slack formatting for readability. KEEP IT COMPACT for mobile viewing.
            
            FORMATTING RULES FOR SLACK:
            - Use *text* for emphasis (single asterisks only)
            - NEVER use **double asterisks**
            - Use compact table format: Event | Date | Type | Location
            - Truncate long names to max 25 characters
            - Use short date format (MM/DD)
            - Keep each line under 80 characters
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant that formats event data for Slack messages. Keep responses concise and well-formatted."},
                        {"role": "user", "content": events_prompt}
                    ],
                    max_tokens=800,
                    temperature=0.2
                )
                
                formatted_response = response.choices[0].message.content
                
                # Fix any remaining bold formatting for Slack
                formatted_response = formatted_response.replace('**', '*')
                formatted_response = formatted_response.replace('###', '')
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, len(events), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error for events: {gpt_error}")
                # Fallback to simple formatting
                return format_events_simple(events, summary_stats, user_name)
        
        else:
            # Handle other PRM commands
            return f"🤖 Hi {user_name}! Available commands:\n• `/prm today's opportunities` - Get opportunities created today\n• `/prm events` - Get upcoming events (next 3 months)"
            
    except Exception as e:
        logger.error(f"PRM command error: {e}")
        return f"❌ Error processing request: {str(e)}"

def format_opportunities_simple(all_opportunities: list, top_closed_won: list, summary_stats: dict, user_name: str) -> str:
    """Simple fallback formatting for opportunities"""
    if not all_opportunities:
        return "📊 No Closed Won opportunities found today."
    
    total_count = summary_stats.get('total_count', 0)
    total_closed_won_revenue = summary_stats.get('total_closed_won_revenue', 0)
    
    response = f"🎉 *Today's Closed Won Deals* (requested by {user_name})\n\n"
    response += f"*Total Deals Won:* {total_count}"
    
    if total_closed_won_revenue > 0:
        response += f" | *Revenue Won:* ${total_closed_won_revenue:,.0f}"
    
    if top_closed_won:
        # Show "Top 3 by Value" when there are more deals than displayed
        if total_count > len(top_closed_won):
            response += f"\n\n*Top {len(top_closed_won)} Deals by Value:* (showing {len(top_closed_won)} of {total_count})\n"
        else:
            response += f"\n\n*Deal Details:*\n"
        for opp in top_closed_won:
            amount_str = f"${opp.get('amount', 0):,.0f}" if opp.get('amount') else "Amount TBD"
            response += f"🏆 *{opp.get('name', 'Unknown')}* - {amount_str} - {opp.get('owner', 'Unknown')}\n"
    
    return response

def format_events_simple(events: list, summary_stats: dict, user_name: str) -> str:
    """Simple fallback formatting for events"""
    if not events:
        return "📅 No upcoming events found in the next 3 months."
    
    total_count = summary_stats.get('total_count', 0)
    date_range = summary_stats.get('date_range', 'next 3 months')
    
    response = f"📅 *Upcoming Events* (requested by {user_name})\n\n"
    response += f"*Total Events:* {total_count} in the {date_range}\n\n"
    
    # Show events in a compact table format
    response += "*Event Schedule:*\n"
    for event in events[:10]:  # Limit to first 10 for compact display
        name = event.get('name', 'Unknown Event')
        start_date = event.get('start_date', 'TBD')
        event_type = event.get('type', 'Unknown')
        location = event.get('location', 'TBD')
        
        # Truncate long names and locations for compact display
        if len(name) > 25:
            name = name[:22] + "..."
        if len(location) > 20:
            location = location[:17] + "..."
        if len(event_type) > 15:
            event_type = event_type[:12] + "..."
        
        # Format date if it's provided (short format)
        if start_date and start_date != 'TBD':
            try:
                from datetime import datetime
                # Assume the date is in ISO format from Salesforce
                date_obj = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                start_date = date_obj.strftime('%m/%d')
            except:
                pass  # Keep original format if parsing fails
        
        response += f"📅 *{name}* | {start_date} | {event_type} | {location}\n"
    
    if total_count > 10:
        response += f"\n... and {total_count - 10} more events"
    
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
            "summary": f"Found {len(all_opportunities)} Closed Won deals today"
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

def _fetch_upcoming_events() -> Dict[str, Any]:
    """Internal function to fetch upcoming events from Event__c table."""
    try:
        sf = sf_client.get_client()
        
        # Query upcoming events in next 3 months
        events_soql = """
        SELECT Name, Start_Date__c, End_Date__c, Type__c, Location__c
        FROM Event__c 
        WHERE Start_Date__c >= TODAY AND Start_Date__c <= NEXT_N_MONTHS:3
        ORDER BY Start_Date__c ASC
        """
        
        result = sf.query(events_soql)
        
        # Format events data
        events = []
        for record in result['records']:
            events.append({
                "name": record.get('Name', ''),
                "start_date": record.get('Start_Date__c', ''),
                "end_date": record.get('End_Date__c', ''),
                "type": record.get('Type__c', ''),
                "location": record.get('Location__c', '')
            })
        
        # Calculate summary statistics
        summary_stats = {
            "total_count": len(events),
            "date_range": "next 3 months"
        }
        
        # Log event access for security monitoring
        security_logger.log_opportunity_access('authenticated_user', len(events), 'Events query')
        
        return {
            "success": True,
            "events": events,
            "summary_stats": summary_stats,
            "summary": f"Found {len(events)} upcoming events in the next 3 months"
        }
        
    except Exception as e:
        logger.error(f"Failed to get upcoming events: {e}")
        return {
            "success": False,
            "error": str(e),
            "events": [],
            "summary_stats": {}
        }

@mcp.tool()
def get_todays_opportunities() -> Dict[str, Any]:
    """Get all opportunities created today with their name, stage, and owner information."""
    return _fetch_todays_opportunities()

@mcp.tool()
def get_upcoming_events() -> Dict[str, Any]:
    """Get all upcoming events from Event__c table in the next 6 months with name, dates, type, and location."""
    return _fetch_upcoming_events()

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