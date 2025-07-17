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
    
    def get_reports_by_name(self, report_name: str) -> List[Dict[str, Any]]:
        """Search for reports by name using SOQL.
        
        Args:
            report_name: The name or partial name of the report to search for
            
        Returns:
            List of report records with Id, Name, DeveloperName, Description, and FolderName
        """
        self.ensure_connected()
        
        # Escape single quotes in the report name for SOQL
        escaped_name = report_name.replace("'", "\\'")
        
        # Convert user-friendly wildcards (*) to SOQL wildcards (%)
        # This allows users to search with patterns like *BMH* or BMH*
        escaped_name = escaped_name.replace('*', '%')
        
        try:
            soql = f"""
            SELECT Id, Name, DeveloperName, Description, FolderName
            FROM Report
            WHERE Name LIKE '%{escaped_name}%'
            ORDER BY Name
            LIMIT 10
            """
            
            result = self.sf.query(soql)
            logger.info(f"Found {len(result['records'])} reports matching '{report_name}'")
            return result['records']
            
        except Exception as e:
            logger.error(f"Failed to search for reports: {e}")
            raise
    
    def get_report_data(self, report_id: str, export_format: str = 'json', include_details: bool = True) -> Any:
        """Fetch report data using Salesforce Reports API.
        
        Args:
            report_id: The Salesforce ID of the report
            export_format: Format for the report data (only 'json' is supported by API)
            include_details: Whether to include detailed report data
            
        Returns:
            Report data in JSON format
        """
        self.ensure_connected()
        
        try:
            # The Analytics API only supports JSON format
            # CSV export is only available through the UI, not the API
            url = f"{self.sf.base_url}analytics/reports/{report_id}"
            
            # Always include details to get the actual data
            url += "?includeDetails=true"
            
            response = self.sf._call_salesforce('GET', url)
            
            # Check if response is already parsed JSON (some versions of simple_salesforce do this)
            if isinstance(response, dict):
                return response
            
            if response.status_code != 200:
                raise Exception(f"Failed to fetch report data: {response.status_code} - {response.text}")
            
            return response.json()
                
        except Exception as e:
            logger.error(f"Failed to fetch report data for {report_id}: {e}")
            raise
    
    def describe_report(self, report_id: str) -> Dict[str, Any]:
        """Get report metadata and structure information.
        
        Args:
            report_id: The Salesforce ID of the report
            
        Returns:
            Report metadata including columns, filters, and report type
        """
        self.ensure_connected()
        
        try:
            url = f"{self.sf.base_url}analytics/reports/{report_id}/describe"
            response = self.sf._call_salesforce('GET', url)
            
            # Check if response is already parsed JSON
            if isinstance(response, dict):
                return response
            
            if response.status_code != 200:
                raise Exception(f"Failed to describe report: {response.status_code} - {response.text}")
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to describe report {report_id}: {e}")
            raise