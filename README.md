# Today's Opportunities MCP Server

A focused Model Context Protocol (MCP) server that provides secure access to opportunities created today in your Salesforce instance. This server is designed to give users visibility into new sales opportunities without broader Salesforce access.

## Features

- **Today's Opportunities Only**: Restricted access to opportunities created today
- **Essential Information**: Returns opportunity name, stage, and owner details
- **API Key Authentication**: Secure access with configurable API key protection
- **Rate Limiting**: Prevents abuse with configurable request limits
- **Security Logging**: Comprehensive audit trail of all access attempts
- **Real-time Data**: Always shows current day's opportunities
- **Production Ready**: Configured for Heroku deployment with native MCP support

## Available MCP Tool

| Tool | Description | Returns |
|------|-------------|---------|
| `get_todays_opportunities()` | Get all opportunities created today | Opportunity name, stage, owner, amount, close date |

## Sample Response

```json
{
  "success": true,
  "total_count": 3,
  "opportunities": [
    {
      "id": "0061234567890AB",
      "name": "Acme Corp - Software License",
      "stage": "Prospecting",
      "owner": "John Smith",
      "amount": 50000,
      "close_date": "2025-01-31",
      "created_date": "2025-01-15T14:30:00.000+0000"
    }
  ],
  "summary": "Found 3 opportunities created today"
}
```

## Quick Deploy to Heroku

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

## Manual Deployment

### Prerequisites

- Heroku CLI installed
- Git repository
- Salesforce credentials (username, password, security token)

### Setup Steps

1. **Clone and prepare the repository:**
   ```bash
   git clone <your-repo-url>
   cd todays-opportunities-mcp
   ```

2. **Create Heroku app:**
   ```bash
   heroku create your-opportunities-app
   ```

3. **Add the Managed Inference and Agents add-on:**
   ```bash
   heroku addons:create heroku-managed-inference-and-agents:starter
   ```

4. **Configure environment variables:**
   ```bash
   heroku config:set SF_USERNAME=your_username@company.com
   heroku config:set SF_PASSWORD=your_password
   heroku config:set SF_SECURITY_TOKEN=your_security_token
   heroku config:set SF_INSTANCE_URL=https://your-company.salesforce.com
   heroku config:set SF_API_VERSION=58.0
   heroku config:set MCP_API_KEY=your_secure_random_api_key_here
   heroku config:set REQUIRE_AUTH=true
   ```

5. **Deploy:**
   ```bash
   git push heroku main
   ```

6. **Test the opportunities tool:**
   ```bash
   heroku open /health
   ```

### Getting Your MCP Toolkit Credentials

After deployment with the Managed Inference and Agents add-on:

1. Go to your Heroku app dashboard
2. Click on "Managed Inference and Agents" add-on
3. Copy your **MCP Toolkit URL** and **MCP Toolkit Token**

## Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Copy environment template:**
   ```bash
   cp .env.example .env
   ```

3. **Configure your Salesforce credentials in `.env`**

4. **Run locally:**
   ```bash
   python main.py
   ```

5. **Test health endpoint:**
   ```bash
   curl http://localhost:8000/health
   ```

## MCP Client Integration

### Claude Desktop

Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "opportunities": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "-H", "Authorization: Bearer YOUR_TOOLKIT_TOKEN",
        "-H", "X-API-Key: YOUR_MCP_API_KEY",
        "-H", "Content-Type: application/json",
        "YOUR_TOOLKIT_URL"
      ]
    }
  }
}
```

### Cursor IDE

Add to your Cursor MCP settings:
```json
{
  "opportunities": {
    "url": "YOUR_TOOLKIT_URL",
    "token": "YOUR_TOOLKIT_TOKEN",
    "headers": {
      "X-API-Key": "YOUR_MCP_API_KEY"
    }
  }
}
```

### Direct API Access

For testing or custom integrations:
```bash
curl -X POST https://your-app.herokuapp.com/mcp \
  -H "X-API-Key: YOUR_MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/call", "params": {"name": "get_todays_opportunities"}}'
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SF_USERNAME` | Salesforce username | Yes | - |
| `SF_PASSWORD` | Salesforce password | Yes | - |
| `SF_SECURITY_TOKEN` | Salesforce security token | Yes | - |
| `SF_INSTANCE_URL` | Salesforce instance URL | No | Auto-detected |
| `SF_API_VERSION` | API version to use | No | `58.0` |
| `MCP_API_KEY` | API key for authentication | Yes | Auto-generated |
| `REQUIRE_AUTH` | Enable authentication | No | `true` |
| `RATE_LIMIT_REQUESTS` | Max requests per hour | No | `50` |
| `RATE_LIMIT_WINDOW` | Rate limit window (seconds) | No | `3600` |
| `PORT` | Server port | No | `8000` |
| `HOST` | Server host | No | `0.0.0.0` |
| `LOG_LEVEL` | Logging level | No | `info` |

## Getting Salesforce Credentials

1. **Username**: Your Salesforce login email
2. **Password**: Your Salesforce login password  
3. **Security Token**: 
   - Log into Salesforce
   - Go to Settings → My Personal Information → Reset My Security Token
   - Check your email for the new token

**Required Permissions**: The Salesforce user must have read access to Opportunity objects.

## Generating API Keys

### For Production
Generate a secure random API key:
```bash
# Using Python
python -c "import secrets; print(f'mcp_{secrets.token_urlsafe(32)}')"

# Using OpenSSL
echo "mcp_$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-32)"

# Using online generator
# Visit: https://passwordsgenerator.net/ (use 40+ characters)
```

### For Development
The server will auto-generate a random key if `MCP_API_KEY` is not set and `REQUIRE_AUTH=true`.
Check the logs for the generated key: `Generated API key: mcp_abc123...`

## Security Features

### Authentication
- **API Key Required**: All MCP requests must include `X-API-Key` header
- **Health Check Exempt**: `/health` endpoint remains public for monitoring
- **Secure Comparison**: Uses constant-time comparison to prevent timing attacks

### Rate Limiting
- **Per-IP Limits**: 50 requests per hour per IP address (configurable)
- **Sliding Window**: 1-hour sliding window prevents burst attacks
- **Automatic Reset**: Counters reset automatically after time window

### Security Logging
All security events are logged with timestamps and IP addresses:
- Authentication successes and failures
- Rate limit violations
- Opportunity data access (with count)
- Invalid API key attempts

### Security Headers
- **HTTPS Enforcement**: Production deployment forces HTTPS
- **Security Logging**: Comprehensive audit trail
- **Error Handling**: No sensitive information in error responses

## Using the MCP Tool

Once deployed and configured, you can use the `get_todays_opportunities()` tool through any MCP client:

- **Claude Desktop**: "Show me today's opportunities"
- **Cursor IDE**: Access through MCP commands
- **Custom Clients**: Call the tool via the MCP protocol

The tool will return a formatted list of all opportunities created today, including:
- Opportunity name
- Current stage
- Owner name
- Deal amount
- Expected close date

## Security & Limitations

### Data Access Restrictions
- **Read-only access**: Cannot modify Salesforce data
- **Today only**: Restricted to opportunities created on the current date
- **Essential fields**: Only returns key opportunity information
- **No sensitive data**: Excludes internal notes, financials, or personal information

### Security Controls
- **API Key Authentication**: Prevents unauthorized access
- **Rate Limiting**: Protects against abuse and scraping
- **IP-based tracking**: Monitors access patterns by source
- **Comprehensive logging**: Full audit trail for compliance
- **Secure credentials**: Environment variables protect Salesforce access

## Monitoring

- **Health Check**: `GET /health` - Returns server and Salesforce connection status
- **Logging**: All queries and errors are logged for troubleshooting

## Monitoring & Support

### Monitoring
- **Health Check**: `GET /health` - Returns server and Salesforce connection status (no auth required)
- **Security Logs**: All authentication and access events are logged
- **Error Tracking**: Failed requests and errors captured with context

### Viewing Security Logs
```bash
# View all logs
heroku logs --tail

# Filter security events only
heroku logs --tail | grep "SECURITY"

# View authentication failures
heroku logs --tail | grep "AUTH_FAILURE"
```

### Support

For issues:
1. **Check health**: Visit `/health` endpoint for connection status
2. **Review security logs**: Look for authentication or rate limit issues  
3. **Verify credentials**: Ensure Salesforce credentials and API key are correct
4. **Check permissions**: Verify Salesforce user has Opportunity read access
5. **Test API key**: Use curl to test direct API access with your key