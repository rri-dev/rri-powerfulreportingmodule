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

# GPT model configuration
GPT_MODEL = os.getenv('GPT_MODEL', 'gpt-4o-mini')
logger.info(f"Using GPT model: {GPT_MODEL}")

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
        
        # Check rate limiting for Slack user
        slack_user_id = f"slack:{user_name}"
        allowed, remaining = rate_limiter.is_allowed(slack_user_id)
        if not allowed:
            security_logger.log_rate_limit(slack_user_id, f"Slack command: {command}")
            return JSONResponse({
                "text": f"⚠️ Rate limit exceeded. You can only make {rate_limiter.max_requests} request(s) per {rate_limiter.window_seconds // 60} minutes. Please try again later."
            })
        
        # Handle /prm command
        if command == '/prm':
            # Respond immediately to avoid timeout
            response_url = form_data.get('response_url', [''])[0]
            
            # Dynamic loading message based on command type
            if "credit" in text.lower() or "ticket" in text.lower():
                loading_message = "🔄 Fetching event credits... please wait"
            elif "event" in text.lower():
                loading_message = "🔄 Fetching upcoming events... please wait"
            elif "today" in text.lower() and "opportunit" in text.lower():
                loading_message = "🔄 Fetching today's opportunities... please wait"
            elif "yesterday" in text.lower() and "opportunit" in text.lower():
                loading_message = "🔄 Fetching yesterday's opportunities... please wait"
            elif "report" in text.lower():
                loading_message = "🔄 Fetching Salesforce report... please wait"
            elif "compare disc" in text.lower():
                loading_message = "🔍 Analyzing DISC profiles for sales strategy... please wait"
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
        if ("today" in text.lower() and "opportunit" in text.lower()) or ("yesterday" in text.lower() and "opportunit" in text.lower()):
            # Determine which day to fetch
            if "yesterday" in text.lower():
                opportunities_data = _fetch_yesterdays_opportunities()
                date_label = "yesterday"
                no_data_message = "📊 No opportunities were closed yesterday."
            else:
                opportunities_data = _fetch_todays_opportunities()
                date_label = "today"
                no_data_message = "📊 No opportunities were closed today."
            
            if not opportunities_data.get('success'):
                return f"❌ Error fetching opportunities: {opportunities_data.get('error', 'Unknown error')}"
            
            all_opportunities = opportunities_data.get('all_opportunities', [])
            top_closed_won = opportunities_data.get('top_closed_won', [])
            summary_stats = opportunities_data.get('summary_stats', {})
            
            if not all_opportunities:
                return no_data_message
            
            # Summarize data for GPT to avoid token limits - DO NOT send all 304+ records
            summary_data = {
                "daily_summary": {
                    f"total_deals_closed_{date_label}": summary_stats.get('total_count', 0),
                    f"total_revenue_won_{date_label}": summary_stats.get('total_closed_won_revenue', 0),
                    "showing_top_deals": min(len(top_closed_won), 3),
                    "date_label": date_label
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
            
            IMPORTANT: You must show the EXACT total count from the daily_summary object
            
            Create a professional summary showing:
            1. TOTAL closed won deals for {date_label} (use exact number from daily_summary)
            2. TOTAL revenue won {date_label} (use exact number from daily_summary)  
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
                    model=GPT_MODEL,
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
            2. A table with columns: Event Name, Start Date, End Date, Location
            3. If there are more than 10 events, mention "(showing first 10 of [TOTAL])"
            
            Use emojis and Slack formatting for readability. KEEP IT COMPACT for mobile viewing.
            
            FORMATTING RULES FOR SLACK:
            - Use *text* for emphasis (single asterisks only)
            - NEVER use **double asterisks**
            - Use compact table format: Event | Date | Location
            - Show full event names (do not truncate)
            - Use short date format (MM/DD)
            - Keep each line readable for mobile viewing
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model=GPT_MODEL,
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
        
        # Get event credits data
        elif "credit" in text.lower() or "ticket" in text.lower():
            # Extract event name from command using word-based splitting
            import re
            
            # Use regex to find the keyword and extract everything after it
            credit_match = re.search(r'\b(credits?|tickets?)\b\s+(.*)', text, re.IGNORECASE)
            
            if credit_match:
                event_name = credit_match.group(2).strip()
            else:
                # Fallback: try simple word splitting
                words = text.split()
                event_name = ""
                for i, word in enumerate(words):
                    if word.lower() in ['credit', 'credits', 'ticket', 'tickets']:
                        event_name = ' '.join(words[i + 1:])
                        break
            
            # Debug logging to see what event name was extracted
            logger.info(f"Credits command - Original text: '{text}', Extracted event name: '{event_name}'")
            
            if not event_name:
                return "❓ Please provide an event name after the command. Example: `/prm credits Tony Robbins Summit`"
            
            credits_data = _fetch_event_credits_by_name(event_name)
            
            if not credits_data.get('success'):
                error_msg = credits_data.get('error', 'Unknown error')
                if 'No events found matching' in error_msg:
                    return f"❌ {error_msg}\n\n💡 Try using a partial name like:\n• `/prm credits UPW`\n• `/prm credits Tony Robbins`\n• `/prm credits Date with Destiny`"
                else:
                    return f"❌ Error fetching event credits: {error_msg}"
            
            event_info = credits_data.get('event', {})
            credits = credits_data.get('credits', [])
            summary_stats = credits_data.get('summary_stats', {})
            
            if not credits:
                event_name_found = event_info.get('name', event_name)
                return f"🎫 No credits found for event '{event_name_found}'."
            
            # Prepare summary data for GPT formatting (no individual credits)
            credits_summary = {
                "event": event_info,
                "summary": {
                    "total_credits": summary_stats.get('total_credits', 0),
                    "status_breakdown": summary_stats.get('status_breakdown', {}),
                    "duplicate_count": summary_stats.get('duplicate_count', 0),
                    "confirmed_count": summary_stats.get('confirmed_count', 0),
                    "other_matches": summary_stats.get('other_matching_events', [])
                }
            }
            
            # Use GPT to format the credits data
            credits_prompt = f"""
            Format the following event credits summary data for a Slack message. Be concise but informative.
            
            Data: {json.dumps(credits_summary, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            Create a professional summary showing ONLY:
            1. Event name and total credits count
            2. Status breakdown (how many in each status)
            3. Duplicate and confirmed counts
            4. If other_matches exist, mention "Similar events found: [list]"
            
            DO NOT include individual credit details or tables. Focus on summary statistics only.
            
            Use emojis and Slack formatting for readability. KEEP IT COMPACT for mobile viewing.
            
            FORMATTING RULES FOR SLACK:
            - Use *text* for emphasis (single asterisks only)
            - NEVER use **double asterisks**
            - Use clean summary format with bullet points or sections
            - Keep the response concise and focused on key metrics
            - Use 🎫 for event credits, 🔄 for duplicates, ✅ for confirmed
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model=GPT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant that formats event credits data for Slack messages. Keep responses concise and well-formatted."},
                        {"role": "user", "content": credits_prompt}
                    ],
                    max_tokens=800,
                    temperature=0.2
                )
                
                formatted_response = response.choices[0].message.content
                
                # Fix any remaining bold formatting for Slack
                formatted_response = formatted_response.replace('**', '*')
                formatted_response = formatted_response.replace('###', '')
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, len(credits), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error for event credits: {gpt_error}")
                # Fallback to simple formatting
                return format_event_credits_simple(credits, summary_stats, event_info, user_name)
        
        # Get Salesforce report data
        elif "report" in text.lower():
            # Extract report name from command
            import re
            
            # Use regex to find the keyword and extract everything after it
            report_match = re.search(r'\breports?\b\s+(.*)', text, re.IGNORECASE)
            
            if report_match:
                report_name = report_match.group(1).strip()
            else:
                # Fallback: try simple word splitting
                words = text.split()
                report_name = ""
                for i, word in enumerate(words):
                    if word.lower() in ['report', 'reports']:
                        report_name = ' '.join(words[i + 1:])
                        break
            
            # Debug logging
            logger.info(f"Report command - Original text: '{text}', Extracted report name: '{report_name}'")
            
            if not report_name:
                return "❓ Please provide a report name after the command. Example: `/prm report Sales Pipeline`"
            
            report_data = _fetch_salesforce_report_by_name(report_name)
            
            # Ensure report_data is a dictionary
            if not isinstance(report_data, dict):
                logger.error(f"Report data is not a dictionary: {type(report_data)}")
                return "❌ Error: Invalid response format from report fetch"
            
            if not report_data.get('success'):
                error_msg = report_data.get('error', 'Unknown error')
                if 'No reports found matching' in error_msg:
                    return f"❌ {error_msg}\n\n💡 Try using a partial name like:\n• `/prm report Pipeline`\n• `/prm report Sales`\n• `/prm report Monthly`"
                else:
                    return f"❌ Error fetching report: {error_msg}"
            
            report_info = report_data.get('report', {})
            data_format = report_data.get('data_format', 'unknown')
            summary_stats = report_data.get('summary_stats', {})
            actual_report_data = report_data.get('report_data', '')
            
            # Prepare the data for GPT formatting
            data_to_format = {
                "report_name": report_info.get('name', 'Unknown Report'),
                "total_rows": summary_stats.get('total_rows', 0)
            }
            
            # Handle JSON format data
            if isinstance(actual_report_data, dict):
                fact_map = actual_report_data.get('factMap', {})
                report_metadata = actual_report_data.get('reportMetadata', {})
                
                # Debug logging
                logger.info(f"Report data keys: {list(actual_report_data.keys())}")
                logger.info(f"FactMap keys: {list(fact_map.keys())}")
                logger.info(f"Report metadata keys: {list(report_metadata.keys())}")
                
                # Get report type
                report_type_info = report_metadata.get('reportType', {})
                report_type = report_type_info.get('type', 'Unknown') if isinstance(report_type_info, dict) else 'Unknown'
                
                # Get column information
                columns = report_metadata.get('detailColumns', [])
                column_names = []
                for col in columns:
                    if isinstance(col, dict):
                        column_names.append(col.get('label', col.get('name', '')))
                    elif isinstance(col, str):
                        column_names.append(col)
                    else:
                        column_names.append(str(col))
                
                # Extract data rows based on report type
                rows = []
                total_row_count = 0
                
                # Debug: Log contents of each factMap entry
                for fm_key, fm_data in fact_map.items():
                    if isinstance(fm_data, dict) and 'rows' in fm_data:
                        row_count = len(fm_data.get('rows', []))
                        logger.info(f"FactMap key '{fm_key}' has {row_count} rows")
                        if row_count > 0:
                            logger.info(f"First row sample from '{fm_key}': {fm_data['rows'][0] if fm_data['rows'] else 'No rows'}")
                
                # For tabular reports, data is in T!T
                if 'T!T' in fact_map and fact_map['T!T'].get('rows'):
                    detail_rows = fact_map['T!T'].get('rows', [])
                    total_row_count = len(detail_rows)
                    logger.info(f"Found {total_row_count} rows in T!T")
                    for row in detail_rows[:100]:  # Limit to 100 rows for analysis
                        row_data = []
                        for cell in row.get('dataCells', []):
                            value = cell.get('label', cell.get('value', ''))
                            row_data.append(value)
                        if row_data:
                            rows.append(row_data)
                
                # If no data found in T!T, check other factMap keys
                if not rows:
                    # For summary/matrix reports, data might be in different keys
                    logger.info(f"No data in T!T, checking other factMap keys")
                    # Collect all rows from all groupings
                    for key, group_data in fact_map.items():
                        if isinstance(group_data, dict) and 'rows' in group_data:
                            group_rows = group_data.get('rows', [])
                            if group_rows:
                                logger.info(f"Found {len(group_rows)} rows in factMap key '{key}'")
                                total_row_count += len(group_rows)
                                for row in group_rows[:20]:  # Limit per group
                                    row_data = []
                                    for cell in row.get('dataCells', []):
                                        value = cell.get('label', cell.get('value', ''))
                                        row_data.append(value)
                                    if row_data and len(rows) < 100:  # Overall limit
                                        rows.append(row_data)
                
                logger.info(f"Extracted {len(rows)} rows for GPT analysis")
                data_to_format["columns"] = column_names
                data_to_format["rows"] = rows
                data_to_format["total_rows_actual"] = total_row_count
                data_to_format["truncated"] = total_row_count > len(rows)
                data_to_format["format"] = "json"
                data_to_format["report_type"] = report_type
            else:
                # Fallback if data structure is unexpected
                data_to_format["data"] = str(actual_report_data)[:1000]
                data_to_format["format"] = "unknown"
            
            # Use GPT to analyze and summarize the report data
            report_prompt = f"""
            Analyze the following Salesforce report data and create an intelligent summary for a Slack message.
            
            Report Data: {json.dumps(data_to_format, indent=2)}
            
            User: {user_name}
            Request: {text}
            
            IMPORTANT: Analyze the data and create a meaningful SUMMARY, not a data table.
            
            Your summary should:
            1. Start with the report name
            2. Provide key insights and patterns from the data
            3. Include important statistics (totals, percentages, breakdowns)
            4. Highlight any notable trends or outliers
            5. Analyze the rows and extract meaningful patterns
            6. Keep it concise but informative (aim for 3-7 bullet points)
            7. If data is grouped (summary/matrix reports), identify key groupings
            
            Examples of good summaries:
            - "150 event credits total: 80% confirmed, 15% pending, 5% cancelled"
            - "Top 3 opportunities worth $2.5M, representing 65% of pipeline"
            - "25 new accounts created this month, 40% increase from last month"
            
            FORMATTING RULES FOR SLACK:
            - Use *text* for report name and emphasis (single asterisks only)
            - Use bullet points (•) for key insights
            - NEVER use **double asterisks**
            - Include relevant numbers and percentages
            - Keep it scannable and mobile-friendly
            - Use 📊 emoji for the report name
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model=GPT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a data analyst that creates intelligent summaries of Salesforce reports for Slack messages. Your job is to analyze the data and extract meaningful insights, patterns, and statistics. Create concise, actionable summaries that help users understand their data at a glance."},
                        {"role": "user", "content": report_prompt}
                    ],
                    max_tokens=2000,
                    temperature=0.1
                )
                
                formatted_response = response.choices[0].message.content
                
                # Fix any remaining bold formatting for Slack
                formatted_response = formatted_response.replace('**', '*')
                formatted_response = formatted_response.replace('###', '')
                
                # Add direct link to the report
                report_id = report_info.get('id')
                if report_id and hasattr(sf_client, 'sf') and sf_client.sf and sf_client.sf.base_url:
                    # Extract instance URL from base_url (e.g., https://rri.my.salesforce.com/services/data/v58.0/)
                    # We need just the domain part
                    base_url = sf_client.sf.base_url
                    if '/services/data/' in base_url:
                        instance_url = base_url.split('/services/data/')[0]
                    else:
                        instance_url = base_url.rstrip('/')
                    report_url = f"{instance_url}/lightning/r/Report/{report_id}/view"
                    formatted_response += f"\n\n📊 <{report_url}|View Full Report in Salesforce>"
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, summary_stats.get('total_rows', 0), f'Slack command: {text}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error for report: {gpt_error}", exc_info=True)
                # Fallback to simple formatting
                return format_report_simple(report_info, summary_stats, user_name, actual_report_data, data_format)
        
        # Get DISC profile comparison for sales strategy
        elif "compare disc" in text.lower():
            # Extract emails from command
            import re
            
            # Use regex to extract two email addresses
            email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            emails = re.findall(email_pattern, text)
            
            if len(emails) < 2:
                return "❓ Please provide two email addresses. Example: `/prm compare disc john.doe@company.com jane.smith@company.com`"
            
            seller_email = emails[0]
            prospect_email = emails[1]
            
            # Debug logging
            logger.info(f"DISC comparison - Seller: '{seller_email}', Prospect: '{prospect_email}'")
            
            disc_data = _fetch_disc_profiles_for_sales_strategy(seller_email, prospect_email)
            
            if not disc_data.get('success'):
                return f"❌ Error: {disc_data.get('error', 'Failed to fetch DISC profiles')}"
            
            seller_profile = disc_data.get('seller', {})
            prospect_profile = disc_data.get('prospect', {})
            
            # Check if DISC data is available
            if seller_profile.get('error') == "DISC profile data not available" or prospect_profile.get('error') == "DISC profile data not available":
                missing_person = []
                if seller_profile.get('error') == "DISC profile data not available":
                    missing_person.append(f"{seller_profile['name']} ({seller_email})")
                if prospect_profile.get('error') == "DISC profile data not available":
                    missing_person.append(f"{prospect_profile['name']} ({prospect_email})")
                
                return f"❌ DISC profile data not available for: {', '.join(missing_person)}\n\n💡 DISC assessments need to be completed first."
            
            # Prepare data for GPT formatting
            disc_summary = {
                "seller": {
                    "name": seller_profile.get('name', 'Unknown'),
                    "email": seller_profile.get('email', ''),
                    "natural_disc": seller_profile.get('natural_disc', ''),
                    "adaptive_disc": seller_profile.get('adaptive_disc', ''),
                    "natural_d_score": seller_profile.get('natural_d_score'),
                    "natural_i_score": seller_profile.get('natural_i_score'),
                    "natural_s_score": seller_profile.get('natural_s_score'),
                    "natural_c_score": seller_profile.get('natural_c_score'),
                    "adaptive_d_score": seller_profile.get('adaptive_d_score'),
                    "adaptive_i_score": seller_profile.get('adaptive_i_score'),
                    "adaptive_s_score": seller_profile.get('adaptive_s_score'),
                    "adaptive_c_score": seller_profile.get('adaptive_c_score')
                },
                "prospect": {
                    "name": prospect_profile.get('name', 'Unknown'),
                    "email": prospect_profile.get('email', ''),
                    "natural_disc": prospect_profile.get('natural_disc', ''),
                    "adaptive_disc": prospect_profile.get('adaptive_disc', ''),
                    "natural_d_score": prospect_profile.get('natural_d_score'),
                    "natural_i_score": prospect_profile.get('natural_i_score'),
                    "natural_s_score": prospect_profile.get('natural_s_score'),
                    "natural_c_score": prospect_profile.get('natural_c_score'),
                    "adaptive_d_score": prospect_profile.get('adaptive_d_score'),
                    "adaptive_i_score": prospect_profile.get('adaptive_i_score'),
                    "adaptive_s_score": prospect_profile.get('adaptive_s_score'),
                    "adaptive_c_score": prospect_profile.get('adaptive_c_score')
                }
            }
            
            # Use GPT to create sales strategy
            gpt_prompt = f"""
            Create a comprehensive DISC-based sales strategy for a seller approaching a prospect.
            
            Data: {json.dumps(disc_summary, indent=2)}
            
            User: {user_name}
            
            Note: Natural DISC represents their authentic personality style, while Adaptive DISC shows how they adjust their behavior in their current environment.
            
            Generate a professional sales strategy that includes:
            1. Brief profile summaries for both people
            2. Communication approach - How the seller should communicate
            3. Presentation style - What type of presentation will resonate
            4. Decision-making insights - How the prospect makes decisions
            5. Likely objections and how to handle them
            6. Closing techniques that work for the prospect's profile
            7. Key adjustments the seller needs to make based on their own profile
            
            Format using Slack markdown with emojis. Be specific and actionable.
            Focus on practical sales tactics, not generic advice.
            Limit to 1000 tokens for the response
            Tailor the responses to fit sales people from the Tony Robbins world
            Any examples should include events or coaching that might be relevant to the customer's DISC profile

            IMPORTANT FORMATTING RULES FOR SLACK:
            - Use *text* for emphasis (single asterisks only)
            - NEVER use **double asterisks** - they don't work in Slack
            - Use bullet points with •
            - Keep it professional but engaging
            """
            
            try:
                client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.chat.completions.create(
                    model=GPT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a professional sales strategist expert in DISC personality assessments. Provide actionable sales strategies based on DISC profiles. Tailor responses to fit sales people from the Tony Robbins world."},
                        {"role": "user", "content": gpt_prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.3
                )
                
                formatted_response = response.choices[0].message.content
                
                # Fix any remaining bold formatting for Slack
                formatted_response = formatted_response.replace('**', '*')
                formatted_response = formatted_response.replace('###', '')
                
                # Log the access for security
                security_logger.log_opportunity_access(user_name, 2, f'DISC comparison: {seller_email} to {prospect_email}')
                
                return formatted_response
                
            except Exception as gpt_error:
                logger.error(f"GPT error for DISC strategy: {gpt_error}")
                # Fallback to simple formatting
                return format_disc_sales_strategy_simple(seller_profile, prospect_profile, user_name)
        
        else:
            # Handle other PRM commands
            return f"🤖 Hi {user_name}! Available commands:\n• `/prm today's opportunities` - Get opportunities closed today\n• `/prm yesterday's opportunities` - Get opportunities closed yesterday\n• `/prm events` - Get upcoming events (next 3 months)\n• `/prm credits [event name]` - Get event tickets/credits\n• `/prm report [report name]` - Get Salesforce report data\n• `/prm compare disc [seller email] [prospect email]` - Get DISC-based sales strategy"
            
    except Exception as e:
        logger.error(f"PRM command error: {e}", exc_info=True)
        return f"❌ Error processing request: {str(e)}"

def format_opportunities_simple(all_opportunities: list, top_closed_won: list, summary_stats: dict, user_name: str) -> str:
    """Simple fallback formatting for opportunities"""
    if not all_opportunities:
        return "📊 No opportunities were closed today."
    
    total_count = summary_stats.get('total_count', 0)
    total_closed_won_revenue = summary_stats.get('total_closed_won_revenue', 0)
    
    response = f"🎉 *Today's Closed Deals* (requested by {user_name})\n\n"
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
        location = event.get('location', 'TBD')
        
        # Truncate long locations for compact display (keep full event names)
        # Event names are shown in full as requested
        if len(location) > 20:
            location = location[:17] + "..."
        
        # Format date if it's provided (short format)
        if start_date and start_date != 'TBD':
            try:
                from datetime import datetime
                # Assume the date is in ISO format from Salesforce
                date_obj = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                start_date = date_obj.strftime('%m/%d')
            except:
                pass  # Keep original format if parsing fails
        
        response += f"📅 *{name}* | {start_date} | {location}\n"
    
    if total_count > 10:
        response += f"\n... and {total_count - 10} more events"
    
    return response

def format_event_credits_simple(credits: list, summary_stats: dict, event_info: dict, user_name: str) -> str:
    """Simple fallback formatting for event credits"""
    if not credits:
        event_name = event_info.get('name', 'Unknown Event')
        return f"🎫 No credits found for event '{event_name}'."
    
    event_name = event_info.get('name', 'Unknown Event')
    total_credits = summary_stats.get('total_credits', 0)
    status_breakdown = summary_stats.get('status_breakdown', {})
    duplicate_count = summary_stats.get('duplicate_count', 0)
    confirmed_count = summary_stats.get('confirmed_count', 0)
    other_matches = summary_stats.get('other_matching_events', [])
    
    response = f"🎫 *Event Credits* (requested by {user_name})\n\n"
    response += f"*Event:* {event_name}\n"
    response += f"*Total Credits:* {total_credits}\n"
    
    # Status breakdown
    if status_breakdown:
        response += f"*Status Breakdown:* "
        status_parts = [f"{status}: {count}" for status, count in status_breakdown.items()]
        response += ", ".join(status_parts) + "\n"
    
    # Duplicate and confirmed counts
    if duplicate_count > 0:
        response += f"*Duplicates:* {duplicate_count}\n"
    if confirmed_count > 0:
        response += f"*Confirmed:* {confirmed_count}\n"
    
    # Show other matching events if any
    if other_matches:
        response += f"*Similar Events:* {', '.join(other_matches[:3])}\n"
    
    return response

def format_report_simple(report_info: dict, summary_stats: dict, user_name: str, report_data=None, data_format='unknown') -> str:
    """Simple fallback formatting for Salesforce reports - creates a basic summary"""
    report_name = report_info.get('name', 'Unknown Report')
    total_rows = summary_stats.get('total_rows', 0)
    report_type = summary_stats.get('report_type', 'Unknown')
    
    response = f"📊 *{report_name}*\n\n"
    response += f"*Summary:*\n"
    response += f"• Total Records: {total_rows:,}\n"
    response += f"• Report Type: {report_type}\n"
    
    # Try to extract some basic insights based on format
    if data_format == 'csv' and report_data:
        lines = report_data.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        # Basic analysis for CSV
        if len(non_empty_lines) > 1:
            header = non_empty_lines[0]
            columns = header.split(',')
            response += f"• Columns: {len(columns)}\n"
            
            # Sample first few column names
            if columns:
                col_names = [col.strip('"').strip() for col in columns[:3]]
                response += f"• Key Fields: {', '.join(col_names)}"
                if len(columns) > 3:
                    response += f" (+{len(columns)-3} more)\n"
                else:
                    response += "\n"
    
    elif data_format == 'json' and isinstance(report_data, dict):
        # Extract insights from JSON format
        fact_map = report_data.get('factMap', {})
        report_metadata = report_data.get('reportMetadata', {})
        
        # Get column info
        columns = report_metadata.get('detailColumns', [])
        if columns:
            response += f"• Columns: {len(columns)}\n"
            col_names = []
            for col in columns[:3]:
                if isinstance(col, dict):
                    col_names.append(col.get('label', col.get('name', '')))
                elif isinstance(col, str):
                    col_names.append(col)
                else:
                    col_names.append(str(col))
            if col_names:
                response += f"• Key Fields: {', '.join(col_names)}"
                if len(columns) > 3:
                    response += f" (+{len(columns)-3} more)\n"
                else:
                    response += "\n"
        
        # Try to get some data statistics
        if 'T!T' in fact_map:
            rows = fact_map['T!T'].get('rows', [])
            if rows and len(rows) > 0:
                # Count non-empty values in first column to estimate data completeness
                first_col_values = 0
                for row in rows[:100]:  # Sample first 100 rows
                    cells = row.get('dataCells', [])
                    if cells and cells[0].get('value'):
                        first_col_values += 1
                
                if first_col_values > 0:
                    completeness = (first_col_values / min(len(rows), 100)) * 100
                    response += f"• Data Completeness: ~{completeness:.0f}%\n"
    
    # Add note about limited analysis
    response += f"\n_Basic summary of {total_rows} records. Use GPT analysis for detailed insights._"
    
    # Add direct link to the report
    report_id = report_info.get('id')
    if report_id and hasattr(sf_client, 'sf') and sf_client.sf and sf_client.sf.base_url:
        # Extract instance URL from base_url (e.g., https://rri.my.salesforce.com/services/data/v58.0/)
        # We need just the domain part
        base_url = sf_client.sf.base_url
        if '/services/data/' in base_url:
            instance_url = base_url.split('/services/data/')[0]
        else:
            instance_url = base_url.rstrip('/')
        report_url = f"{instance_url}/lightning/r/Report/{report_id}/view"
        response += f"\n\n📊 <{report_url}|View Full Report in Salesforce>"
    
    return response

def format_disc_sales_strategy_simple(seller_profile: dict, prospect_profile: dict, user_name: str) -> str:
    """Simple fallback formatting for DISC sales strategy"""
    response = f"🎯 *DISC Sales Strategy* (requested by {user_name})\n\n"
    
    # Seller profile
    seller_name = seller_profile.get('name', 'Unknown')
    seller_email = seller_profile.get('email', '')
    response += f"*Seller:* {seller_name} ({seller_email})\n"
    
    if seller_profile.get('natural_disc'):
        response += f"• Natural DISC: {seller_profile.get('natural_disc', '')}\n"
        if seller_profile.get('adaptive_disc'):
            response += f"• Adaptive DISC: {seller_profile.get('adaptive_disc', '')}\n"
    else:
        response += "• DISC profile data not available\n"
    
    response += "\n"
    
    # Prospect profile
    prospect_name = prospect_profile.get('name', 'Unknown')
    prospect_email = prospect_profile.get('email', '')
    response += f"*Prospect:* {prospect_name} ({prospect_email})\n"
    
    if prospect_profile.get('natural_disc'):
        response += f"• Natural DISC: {prospect_profile.get('natural_disc', '')}\n"
        if prospect_profile.get('adaptive_disc'):
            response += f"• Adaptive DISC: {prospect_profile.get('adaptive_disc', '')}\n"
    else:
        response += "• DISC profile data not available\n"
    
    response += "\n*Basic Strategy:*\n"
    
    # Basic compatibility insights based on DISC profiles
    if seller_profile.get('natural_disc') and prospect_profile.get('natural_disc'):
        response += "• Use GPT-4 for detailed DISC-based sales strategy\n"
        response += "• Natural and Adaptive profiles provide insight into authentic vs situational behavior\n"
    else:
        response += "• Complete DISC assessments needed for detailed strategy\n"
    
    return response

def _fetch_opportunities_by_date(date_filter: str = "TODAY", date_label: str = "today") -> Dict[str, Any]:
    """Internal function to fetch opportunities closed on a specific date."""
    try:
        sf = sf_client.get_client()
        
        # Query 1: Get ALL opportunities closed on the specified date for summary
        all_opportunities_soql = f"""
        SELECT Id, Name, StageName, Owner.Name, CreatedDate, Amount, CloseDate
        FROM Opportunity 
        WHERE CloseDate = {date_filter} 
        AND StageName = 'Closed Won'
        AND (NOT Name LIKE '%test%')
        ORDER BY CloseDate DESC
        """
        
        all_result = sf.query(all_opportunities_soql)
        
        # Query 2: Get top 3 closed won opportunities with products
        closed_won_soql = f"""
        SELECT Id, Name, StageName, Owner.Name, CreatedDate, Amount, CloseDate,
               (SELECT Id, Product2.Name, Product2.Description, Quantity, UnitPrice, TotalPrice 
                FROM OpportunityLineItems 
                ORDER BY TotalPrice DESC)
        FROM Opportunity 
        WHERE CloseDate = {date_filter} 
        AND StageName = 'Closed Won'
        AND (NOT Name LIKE '%test%')
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
            "summary": f"Found {len(all_opportunities)} deals closed {date_label}"
        }
        
    except Exception as e:
        logger.error(f"Failed to get {date_label}'s opportunities: {e}")
        return {
            "success": False,
            "error": str(e),
            "all_opportunities": [],
            "top_closed_won": [],
            "summary_stats": {}
        }

def _fetch_todays_opportunities() -> Dict[str, Any]:
    """Internal function to fetch opportunities closed today."""
    return _fetch_opportunities_by_date("TODAY", "today")

def _fetch_yesterdays_opportunities() -> Dict[str, Any]:
    """Internal function to fetch opportunities closed yesterday."""
    return _fetch_opportunities_by_date("YESTERDAY", "yesterday")

def _fetch_upcoming_events() -> Dict[str, Any]:
    """Internal function to fetch upcoming events from Event__c table."""
    try:
        sf = sf_client.get_client()
        
        # Query upcoming events in next 3 months
        events_soql = """
        SELECT Name, Start_Date__c, End_Date__c, Location__c
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

def _fetch_event_credits_by_name(event_name: str) -> Dict[str, Any]:
    """Internal function to fetch event credits by event name."""
    try:
        from lib.soql_utils import build_safe_like_query, sanitize_salesforce_id, validate_event_name
        
        # Validate input first
        is_valid, error_msg = validate_event_name(event_name)
        if not is_valid:
            logger.warning(f"Invalid event name input: {error_msg}")
            return {
                "success": False,
                "error": f"Invalid event name: {error_msg}",
                "event": None,
                "credits": [],
                "summary_stats": {}
            }
        
        sf = sf_client.get_client()
        
        # Step 1: Find Event__c by name (partial match) - using safe query builder
        event_search_soql = build_safe_like_query(
            field_name="Name",
            search_term=event_name,
            object_name="Event__c",
            select_fields=["Id", "Name"],
            order_by="Name ASC",
            limit=5
        )
        
        logger.info(f"Executing safe SOQL query for event search: {event_search_soql}")
        event_result = sf.query(event_search_soql)
        
        if not event_result['records']:
            return {
                "success": False,
                "error": f"No events found matching '{event_name}'",
                "event": None,
                "credits": [],
                "summary_stats": {}
            }
        
        # If multiple events found, use the first one but note others
        target_event = event_result['records'][0]
        event_id = target_event['Id']
        event_full_name = target_event['Name']
        
        other_matches = [record['Name'] for record in event_result['records'][1:]]
        
        # Step 2: Query Event_Credit__c for this event - using sanitized ID
        try:
            sanitized_event_id = sanitize_salesforce_id(event_id)
        except ValueError as e:
            logger.error(f"Invalid Salesforce ID returned from event query: {e}")
            return {
                "success": False,
                "error": "Invalid event ID format",
                "event": None,
                "credits": [],
                "summary_stats": {}
            }
        
        credits_soql = f"""
        SELECT Name, Status__c, Am_Dupe__c, Confirmed_Date__c
        FROM Event_Credit__c 
        WHERE Related_Event__c = '{sanitized_event_id}'
        ORDER BY Name ASC
        """
        
        logger.info(f"Executing safe SOQL query for credits: Related_Event__c = '{sanitized_event_id}'")
        credits_result = sf.query_all(credits_soql)
        logger.info(f"Retrieved {len(credits_result['records'])} total credit records (using query_all for complete results)")
        
        # Format credits data
        credits = []
        for record in credits_result['records']:
            credits.append({
                "name": record.get('Name', ''),
                "status": record.get('Status__c', ''),
                "is_duplicate": record.get('Am_Dupe__c', False),
                "confirmed_date": record.get('Confirmed_Date__c', '')
            })
        
        # Calculate summary statistics
        total_credits = len(credits)
        status_breakdown = {}
        duplicate_count = 0
        confirmed_count = 0
        
        for credit in credits:
            # Status breakdown
            status = credit['status'] or 'Unknown'
            status_breakdown[status] = status_breakdown.get(status, 0) + 1
            
            # Count duplicates
            if credit['is_duplicate']:
                duplicate_count += 1
            
            # Count confirmed
            if credit['confirmed_date']:
                confirmed_count += 1
        
        summary_stats = {
            "total_credits": total_credits,
            "status_breakdown": status_breakdown,
            "duplicate_count": duplicate_count,
            "confirmed_count": confirmed_count,
            "other_matching_events": other_matches
        }
        
        # Log event credits access for security monitoring
        security_logger.log_opportunity_access('authenticated_user', total_credits, f'Event credits query: {event_full_name}')
        
        return {
            "success": True,
            "event": {
                "id": event_id,
                "name": event_full_name
            },
            "credits": credits,
            "summary_stats": summary_stats,
            "summary": f"Found {total_credits} credits for event '{event_full_name}'"
        }
        
    except Exception as e:
        logger.error(f"Failed to get event credits for '{event_name}': {e}")
        return {
            "success": False,
            "error": str(e),
            "event": None,
            "credits": [],
            "summary_stats": {}
        }

def _fetch_disc_profiles_for_sales_strategy(seller_email: str, prospect_email: str) -> Dict[str, Any]:
    """Internal function to fetch DISC profiles for sales strategy comparison."""
    try:
        from lib.soql_utils import escape_soql_string
        import re
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, seller_email):
            return {
                "success": False,
                "error": f"Invalid seller email format: {seller_email}",
                "seller": None,
                "prospect": None
            }
            
        if not re.match(email_pattern, prospect_email):
            return {
                "success": False,
                "error": f"Invalid prospect email format: {prospect_email}",
                "seller": None,
                "prospect": None
            }
        
        sf = sf_client.get_client()
        
        # Escape emails for safe SOQL queries
        seller_email_escaped = escape_soql_string(seller_email)
        prospect_email_escaped = escape_soql_string(prospect_email)
        
        # Query for DISC profiles - try Lead and Account
        # Note: DISC fields might be custom fields like Natural_DISC__c, Adaptive_DISC__c
        # We'll try common patterns and adjust if needed
        
        def fetch_profile(email_escaped: str, email_original: str):
            """Helper function to fetch a single profile from Lead or Account"""
            # Try Lead first
            lead_soql = f"""
            SELECT Id, Email, FirstName, LastName, Name,
                   Natural_DISC__c, Adaptive_DISC__c,
                   Natural_D_Score__c, Natural_I_Score__c, Natural_S_Score__c, Natural_C_Score__c,
                   Adaptive_D_Score__c, Adaptive_I_Score__c, Adaptive_S_Score__c, Adaptive_C_Score__c
            FROM Lead 
            WHERE Email = '{email_escaped}'
            LIMIT 1
            """
            
            try:
                lead_result = sf.query(lead_soql)
                if lead_result['totalSize'] > 0:
                    lead = lead_result['records'][0]
                    return {
                        "found": True,
                        "type": "Lead",
                        "id": lead.get('Id'),
                        "email": email_original,
                        "firstName": lead.get('FirstName', ''),
                        "lastName": lead.get('LastName', ''),
                        "name": lead.get('Name', ''),
                        "natural_disc": lead.get('Natural_DISC__c', ''),
                        "adaptive_disc": lead.get('Adaptive_DISC__c', ''),
                        "natural_d_score": lead.get('Natural_D_Score__c'),
                        "natural_i_score": lead.get('Natural_I_Score__c'),
                        "natural_s_score": lead.get('Natural_S_Score__c'),
                        "natural_c_score": lead.get('Natural_C_Score__c'),
                        "adaptive_d_score": lead.get('Adaptive_D_Score__c'),
                        "adaptive_i_score": lead.get('Adaptive_I_Score__c'),
                        "adaptive_s_score": lead.get('Adaptive_S_Score__c'),
                        "adaptive_c_score": lead.get('Adaptive_C_Score__c')
                    }
            except Exception as e:
                # Try without DISC fields
                logger.warning(f"Error querying Lead DISC fields: {e}")
                
                basic_lead_soql = f"""
                SELECT Id, Email, FirstName, LastName, Name
                FROM Lead 
                WHERE Email = '{email_escaped}'
                LIMIT 1
                """
                
                try:
                    basic_result = sf.query(basic_lead_soql)
                    if basic_result['totalSize'] > 0:
                        lead = basic_result['records'][0]
                        return {
                            "found": True,
                            "type": "Lead",
                            "id": lead.get('Id'),
                            "email": email_original,
                            "firstName": lead.get('FirstName', ''),
                            "lastName": lead.get('LastName', ''),
                            "name": lead.get('Name', ''),
                            "natural_disc": None,
                            "adaptive_disc": None,
                            "error": "DISC profile data not available"
                        }
                except Exception as e2:
                    logger.error(f"Error querying basic Lead: {e2}")
            
            # Try Account if Lead not found
            # Note: Person Accounts use PersonEmail
            account_soql = f"""
            SELECT Id, PersonEmail, Name, FirstName, LastName,
                   Natural_DISC__c, Adaptive_DISC__c,
                   Natural_D_Score__c, Natural_I_Score__c, Natural_S_Score__c, Natural_C_Score__c,
                   Adaptive_D_Score__c, Adaptive_I_Score__c, Adaptive_S_Score__c, Adaptive_C_Score__c
            FROM Account 
            WHERE PersonEmail = '{email_escaped}'
            LIMIT 1
            """
            
            try:
                account_result = sf.query(account_soql)
                if account_result['totalSize'] > 0:
                    account = account_result['records'][0]
                    return {
                        "found": True,
                        "type": "Account",
                        "id": account.get('Id'),
                        "email": email_original,
                        "firstName": account.get('FirstName', ''),
                        "lastName": account.get('LastName', ''),
                        "name": account.get('Name', ''),
                        "natural_disc": account.get('Natural_DISC__c', ''),
                        "adaptive_disc": account.get('Adaptive_DISC__c', ''),
                        "natural_d_score": account.get('Natural_D_Score__c'),
                        "natural_i_score": account.get('Natural_I_Score__c'),
                        "natural_s_score": account.get('Natural_S_Score__c'),
                        "natural_c_score": account.get('Natural_C_Score__c'),
                        "adaptive_d_score": account.get('Adaptive_D_Score__c'),
                        "adaptive_i_score": account.get('Adaptive_I_Score__c'),
                        "adaptive_s_score": account.get('Adaptive_S_Score__c'),
                        "adaptive_c_score": account.get('Adaptive_C_Score__c')
                    }
            except Exception as e:
                # Try without DISC fields
                logger.warning(f"Error querying Account DISC fields: {e}")
                
                # Try basic Account query without DISC fields
                basic_account_soql = f"""
                SELECT Id, PersonEmail, Name, FirstName, LastName
                FROM Account 
                WHERE PersonEmail = '{email_escaped}'
                LIMIT 1
                """
                
                try:
                    basic_result = sf.query(basic_account_soql)
                    if basic_result['totalSize'] > 0:
                        account = basic_result['records'][0]
                        return {
                            "found": True,
                            "type": "Account",
                            "id": account.get('Id'),
                            "email": email_original,
                            "firstName": account.get('FirstName', ''),
                            "lastName": account.get('LastName', ''),
                            "name": account.get('Name', ''),
                            "natural_disc": None,
                            "adaptive_disc": None,
                            "error": "DISC profile data not available"
                        }
                except Exception as e2:
                    logger.error(f"Error querying basic Account: {e2}")
            
            return {
                "found": False,
                "email": email_original,
                "error": f"No Lead or Account found with email: {email_original}"
            }
        
        # Fetch both profiles
        seller_profile = fetch_profile(seller_email_escaped, seller_email)
        prospect_profile = fetch_profile(prospect_email_escaped, prospect_email)
        
        # Check if both profiles were found
        if not seller_profile['found']:
            return {
                "success": False,
                "error": seller_profile['error'],
                "seller": seller_profile,
                "prospect": None
            }
            
        if not prospect_profile['found']:
            return {
                "success": False,
                "error": prospect_profile['error'],
                "seller": seller_profile,
                "prospect": prospect_profile
            }
        
        # No need to calculate types - we have Natural and Adaptive DISC profiles
        
        return {
            "success": True,
            "seller": seller_profile,
            "prospect": prospect_profile,
            "summary": f"DISC comparison for {seller_profile['name']} selling to {prospect_profile['name']}"
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch DISC profiles: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "seller": None,
            "prospect": None
        }

def _fetch_salesforce_report_by_name(report_name: str) -> Dict[str, Any]:
    """Internal function to fetch Salesforce report by name."""
    try:
        # Search for reports matching the name
        reports = sf_client.get_reports_by_name(report_name)
        
        if not reports:
            return {
                "success": False,
                "error": f"No reports found matching '{report_name}'",
                "reports": [],
                "report_data": None,
                "summary_stats": {}
            }
        
        # If multiple reports found, use the first one but note others
        target_report = reports[0]
        report_id = target_report['Id']
        report_full_name = target_report['Name']
        
        other_matches = [{"name": r['Name'], "folder": r.get('FolderName', 'N/A')} 
                        for r in reports[1:]]
        
        # Get report metadata
        try:
            report_metadata = sf_client.describe_report(report_id)
            report_type = report_metadata.get('reportMetadata', {}).get('reportType', {}).get('type', 'Unknown')
            
            # Get report data - API only supports JSON format
            report_data = sf_client.get_report_data(report_id, export_format='json', include_details=True)
            data_format = 'json'
            
            # Extract summary statistics from report data
            summary_stats = {}
            
            # Extract row count and metadata from JSON response
            fact_map = report_data.get('factMap', {})
            report_metadata_response = report_data.get('reportMetadata', {})
            
            # Count total rows across all groupings
            total_rows = 0
            if 'T!T' in fact_map:
                # Tabular report - all data in T!T
                total_rows = len(fact_map['T!T'].get('rows', []))
            else:
                # Summary/Matrix report - data in multiple groupings
                for _, group_data in fact_map.items():
                    if isinstance(group_data, dict) and 'rows' in group_data:
                        total_rows += len(group_data.get('rows', []))
            
            summary_stats = {
                "total_rows": total_rows,
                "report_type": report_type,
                "report_format": report_metadata_response.get('reportFormat', 'TABULAR'),
                "has_details": report_data.get('hasDetailRows', False),
                "columns": len(report_metadata_response.get('detailColumns', [])),
                "groupings": len(report_metadata_response.get('groupingsDown', [])),
                "other_matching_reports": other_matches
            }
            
            # Log report access for security monitoring
            security_logger.log_opportunity_access('authenticated_user', 
                                                 summary_stats.get('total_rows', 0), 
                                                 f'Report query: {report_full_name}')
            
            return {
                "success": True,
                "report": {
                    "id": report_id,
                    "name": report_full_name,
                    "folder": target_report.get('FolderName', 'N/A'),
                    "description": target_report.get('Description', '')
                },
                "report_data": report_data,
                "data_format": data_format,
                "summary_stats": summary_stats,
                "summary": f"Retrieved report '{report_full_name}' with {summary_stats.get('total_rows', 0)} rows"
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch report data: {e}")
            return {
                "success": False,
                "error": f"Found report but failed to fetch data: {str(e)}",
                "report": {
                    "id": report_id,
                    "name": report_full_name
                },
                "report_data": None,
                "summary_stats": {}
            }
        
    except Exception as e:
        logger.error(f"Failed to get report '{report_name}': {e}")
        return {
            "success": False,
            "error": str(e),
            "reports": [],
            "report_data": None,
            "summary_stats": {}
        }

@mcp.tool()
def get_todays_opportunities() -> Dict[str, Any]:
    """Get all opportunities closed today with their name, stage, and owner information."""
    return _fetch_todays_opportunities()

@mcp.tool()
def get_yesterdays_opportunities() -> Dict[str, Any]:
    """Get all opportunities closed yesterday with their name, stage, and owner information."""
    return _fetch_yesterdays_opportunities()

@mcp.tool()
def get_upcoming_events() -> Dict[str, Any]:
    """Get all upcoming events from Event__c table in the next 3 months with name, dates, type, and location."""
    return _fetch_upcoming_events()

@mcp.tool()
def get_event_credits(event_name: str) -> Dict[str, Any]:
    """Get event credits (tickets) summary for a specific event by name. Searches for events matching the name and returns summary statistics including total count, status breakdown, duplicate count, and confirmation count."""
    return _fetch_event_credits_by_name(event_name)

@mcp.tool()
def get_salesforce_report(report_name: str) -> Dict[str, Any]:
    """Get Salesforce report data by report name. Searches for reports matching the name and returns the report data along with summary statistics. Supports partial name matching and handles different report types (tabular, summary, matrix)."""
    return _fetch_salesforce_report_by_name(report_name)

@mcp.tool()
def get_disc_sales_strategy(seller_email: str, prospect_email: str) -> Dict[str, Any]:
    """Get DISC-based sales strategy recommendations for how a seller should approach a prospect. Fetches DISC personality profiles for both people and provides tailored sales guidance including communication style, presentation approach, objection handling, and closing techniques."""
    return _fetch_disc_profiles_for_sales_strategy(seller_email, prospect_email)

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