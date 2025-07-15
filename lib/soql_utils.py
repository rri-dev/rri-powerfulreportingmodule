#!/usr/bin/env python3
"""
SOQL Sanitization Utilities
Provides functions to safely construct SOQL queries and prevent injection attacks.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def escape_soql_string(input_str: str) -> str:
    """
    Escape special characters in a string for safe use in SOQL queries.
    
    Args:
        input_str: The string to escape
        
    Returns:
        Escaped string safe for SOQL queries
    """
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    # Escape single quotes (most critical for SOQL injection)
    escaped = input_str.replace("'", "\\'")
    
    # Escape backslashes
    escaped = escaped.replace("\\", "\\\\")
    
    return escaped

def validate_event_name(event_name: str) -> tuple[bool, str]:
    """
    Validate event name input for safety and reasonable constraints.
    
    Args:
        event_name: The event name to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(event_name, str):
        return False, "Event name must be a string"
    
    # Check for null or empty
    if not event_name or not event_name.strip():
        return False, "Event name cannot be empty"
    
    # Check length constraints
    if len(event_name) > 255:
        return False, "Event name too long (max 255 characters)"
    
    if len(event_name) < 2:
        return False, "Event name too short (min 2 characters)"
    
    # Check for suspicious patterns that might indicate injection attempts
    suspicious_patterns = [
        r"'.*'",  # Single quotes with content
        r"--",    # SQL comments
        r"/\*.*\*/",  # Multi-line comments
        r"\bSELECT\b",  # SELECT keyword
        r"\bFROM\b",    # FROM keyword
        r"\bWHERE\b",   # WHERE keyword
        r"\bDROP\b",    # DROP keyword
        r"\bDELETE\b",  # DELETE keyword
        r"\bINSERT\b",  # INSERT keyword
        r"\bUPDATE\b",  # UPDATE keyword
        r"\bUNION\b",   # UNION keyword
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, event_name, re.IGNORECASE):
            logger.warning(f"Suspicious pattern detected in event name: {pattern}")
            return False, "Event name contains invalid characters"
    
    return True, ""

def sanitize_like_clause(search_term: str) -> str:
    """
    Sanitize a search term for safe use in SOQL LIKE clauses.
    
    Args:
        search_term: The search term to sanitize
        
    Returns:
        Sanitized search term safe for LIKE clauses
        
    Raises:
        ValueError: If the search term is invalid
    """
    # Validate input first
    is_valid, error_msg = validate_event_name(search_term)
    if not is_valid:
        raise ValueError(f"Invalid search term: {error_msg}")
    
    # Escape the string
    sanitized = escape_soql_string(search_term.strip())
    
    # Log the sanitization for security monitoring
    if sanitized != search_term.strip():
        logger.info(f"SOQL sanitization applied: original length={len(search_term)}, sanitized length={len(sanitized)}")
    
    return sanitized

def validate_salesforce_id(sf_id: str) -> tuple[bool, str]:
    """
    Validate a Salesforce ID for safety.
    
    Args:
        sf_id: The Salesforce ID to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(sf_id, str):
        return False, "Salesforce ID must be a string"
    
    # Salesforce IDs are 15 or 18 characters, alphanumeric
    if not re.match(r'^[a-zA-Z0-9]{15}$|^[a-zA-Z0-9]{18}$', sf_id):
        return False, "Invalid Salesforce ID format"
    
    return True, ""

def sanitize_salesforce_id(sf_id: str) -> str:
    """
    Sanitize a Salesforce ID for safe use in queries.
    
    Args:
        sf_id: The Salesforce ID to sanitize
        
    Returns:
        Sanitized Salesforce ID
        
    Raises:
        ValueError: If the ID is invalid
    """
    is_valid, error_msg = validate_salesforce_id(sf_id)
    if not is_valid:
        raise ValueError(f"Invalid Salesforce ID: {error_msg}")
    
    return sf_id  # If it passes validation, it's already safe

def build_safe_like_query(field_name: str, search_term: str, object_name: str, 
                         select_fields: list[str], order_by: Optional[str] = None, 
                         limit: Optional[int] = None) -> str:
    """
    Build a safe SOQL query with a LIKE clause.
    
    Args:
        field_name: The field to search in
        search_term: The term to search for
        object_name: The Salesforce object name
        select_fields: List of fields to select
        order_by: Optional ORDER BY clause
        limit: Optional LIMIT value
        
    Returns:
        Safe SOQL query string
        
    Raises:
        ValueError: If any parameter is invalid
    """
    # Validate inputs
    if not all([field_name, search_term, object_name, select_fields]):
        raise ValueError("All required parameters must be provided")
    
    if not isinstance(select_fields, list) or not select_fields:
        raise ValueError("select_fields must be a non-empty list")
    
    # Sanitize the search term
    sanitized_search = sanitize_like_clause(search_term)
    
    # Build the query safely
    fields_str = ", ".join(select_fields)
    query = f"SELECT {fields_str} FROM {object_name} WHERE {field_name} LIKE '%{sanitized_search}%'"
    
    if order_by:
        query += f" ORDER BY {order_by}"
    
    if limit and isinstance(limit, int) and limit > 0:
        query += f" LIMIT {limit}"
    
    return query