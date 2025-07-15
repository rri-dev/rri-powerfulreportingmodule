#!/usr/bin/env python3
"""
Simple MCP client for connecting to remote HTTP MCP server
"""
import sys
import json
import asyncio
import httpx

class MCPHTTPClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session_id = None
        
    async def send_request(self, method, params=None):
        """Send an MCP request to the HTTP server"""
        headers = {
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream'
        }
        
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method
        }
        
        if params:
            payload['params'] = params
            
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/",
                    headers=headers,
                    json=payload,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        'error': f'HTTP {response.status_code}: {response.text}'
                    }
            except Exception as e:
                return {'error': str(e)}

async def main():
    """Main MCP client loop"""
    # Configuration
    base_url = "https://rri-prm-39ad5d4cb165.herokuapp.com/mcp"
    api_key = "mcp_-vsIk4lFm_iOv7sNt47QvLb0qA8xA64xKFwBEqgE9jU"
    
    client = MCPHTTPClient(base_url, api_key)
    
    # Read from stdin for MCP protocol messages
    for line in sys.stdin:
        try:
            message = json.loads(line.strip())
            method = message.get('method')
            params = message.get('params')
            
            # Handle different MCP methods
            if method == 'initialize':
                # Initialize response
                response = {
                    'jsonrpc': '2.0',
                    'id': message.get('id'),
                    'result': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {
                            'tools': {}
                        },
                        'serverInfo': {
                            'name': 'Salesforce Opportunities MCP Client',
                            'version': '1.0.0'
                        }
                    }
                }
                print(json.dumps(response))
                
            elif method == 'tools/list':
                # Get tools from remote server
                result = await client.send_request('tools/list')
                response = {
                    'jsonrpc': '2.0',
                    'id': message.get('id'),
                    'result': result
                }
                print(json.dumps(response))
                
            elif method == 'tools/call':
                # Call tool on remote server
                result = await client.send_request('tools/call', params)
                response = {
                    'jsonrpc': '2.0',
                    'id': message.get('id'),
                    'result': result
                }
                print(json.dumps(response))
                
        except Exception as e:
            error_response = {
                'jsonrpc': '2.0',
                'id': message.get('id', 'unknown'),
                'error': {
                    'code': -32000,
                    'message': str(e)
                }
            }
            print(json.dumps(error_response))

if __name__ == '__main__':
    asyncio.run(main())