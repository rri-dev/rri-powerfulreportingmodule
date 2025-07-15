import logging
import time
from typing import Optional, Dict, Any, List
from simple_salesforce import Salesforce, SalesforceLogin
from simple_salesforce.exceptions import SalesforceAuthenticationFailed, SalesforceError
from .salesforce_config import SalesforceConfig

logger = logging.getLogger(__name__)

class SalesforceClient:
    def __init__(self, config: Optional[SalesforceConfig] = None):
        self.config = config or SalesforceConfig()
        self.sf: Optional[Salesforce] = None
        self._connected = False
        self.max_retries = 3
        self.retry_delay = 1.0
    
    def connect(self) -> bool:
        if not self.config.is_valid():
            raise ValueError("Invalid Salesforce configuration. Please check your environment variables.")
        
        for attempt in range(self.max_retries):
            try:
                connection_params = self.config.get_connection_params()
                self.sf = Salesforce(**connection_params)
                self._connected = True
                logger.info("Successfully connected to Salesforce")
                return True
                
            except SalesforceAuthenticationFailed as e:
                logger.error(f"Authentication failed: {e}")
                raise
            except Exception as e:
                if attempt < self.max_retries - 1:
                    logger.warning(f"Connection attempt {attempt + 1} failed: {e}. Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                    self.retry_delay *= 2
                else:
                    logger.error(f"Connection failed after {self.max_retries} attempts: {e}")
                    raise
        
        return False
    
    def is_connected(self) -> bool:
        return self._connected and self.sf is not None
    
    def ensure_connected(self):
        if not self.is_connected():
            self.connect()
    
    def test_connection(self) -> Dict[str, Any]:
        self.ensure_connected()
        try:
            result = self.sf.query("SELECT Id, Name FROM Organization LIMIT 1")
            return {
                "success": True,
                "organization": result['records'][0] if result['records'] else None,
                "session_id": self.sf.session_id[:10] + "..." if self.sf.session_id else None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_client(self) -> Salesforce:
        self.ensure_connected()
        return self.sf
    
    def execute_with_retry(self, operation, *args, **kwargs):
        """Execute a Salesforce operation with retry logic for transient errors."""
        for attempt in range(self.max_retries):
            try:
                self.ensure_connected()
                return operation(*args, **kwargs)
            except SalesforceError as e:
                if "INVALID_SESSION_ID" in str(e) and attempt < self.max_retries - 1:
                    logger.warning(f"Session expired, reconnecting... (attempt {attempt + 1})")
                    self._connected = False
                    time.sleep(self.retry_delay)
                    continue
                elif "REQUEST_LIMIT_EXCEEDED" in str(e) and attempt < self.max_retries - 1:
                    logger.warning(f"API limit exceeded, waiting... (attempt {attempt + 1})")
                    time.sleep(self.retry_delay * 2)
                    continue
                else:
                    raise
            except Exception as e:
                if attempt < self.max_retries - 1:
                    logger.warning(f"Operation failed, retrying... (attempt {attempt + 1}): {e}")
                    time.sleep(self.retry_delay)
                    continue
                else:
                    raise
        
        raise Exception(f"Operation failed after {self.max_retries} attempts")