import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class SalesforceConfig:
    def __init__(self):
        self.username = os.getenv('SF_USERNAME')
        self.password = os.getenv('SF_PASSWORD')
        self.security_token = os.getenv('SF_SECURITY_TOKEN')
        self.instance_url = os.getenv('SF_INSTANCE_URL')
        self.api_version = os.getenv('SF_API_VERSION', '58.0')
    
    def is_valid(self) -> bool:
        return all([
            self.username,
            self.password,
            self.security_token
        ])
    
    def get_connection_params(self) -> dict:
        params = {
            'username': self.username,
            'password': self.password,
            'security_token': self.security_token,
            'version': self.api_version
        }
        
        if self.instance_url:
            params['instance_url'] = self.instance_url
            
        return params