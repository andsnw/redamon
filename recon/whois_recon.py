"""
OSINT Module - WHOIS Information Gathering
This module provides comprehensive WHOIS lookup capabilities for domain reconnaissance.
Output is saved as structured JSON to the output folder.
"""

import json
import whois
from typing import Any
from datetime import datetime
from pathlib import Path


# Output directory for JSON results
OUTPUT_DIR = Path(__file__).parent / "output"


def get_whois_data(domain: str):
    """
    Get WHOIS information for a domain.
    
    Args:
        domain: The domain to lookup (e.g., "example.com")
        
    Returns:
        Tuple of (whois_result_dict_like_object, domain_string).
        
    Raises:
        Exception: If WHOIS lookup fails.
    """
    try:
        w = whois.whois(domain)
        return w, domain
    except Exception as e:
        raise Exception(f"WHOIS lookup failed for {domain}: {str(e)}")


def _serialize_for_json(value: Any) -> Any:
    """
    Serialize a value for JSON output, handling datetime objects.
    
    Args:
        value: The value to serialize.
        
    Returns:
        JSON-serializable value.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_for_json(item) for item in value]
    if isinstance(value, dict):
        return {k: _serialize_for_json(v) for k, v in value.items()}
    return value


def whois_to_dict(whois_result: Any, domain: str) -> dict:
    """
    Convert whois library result to a structured dictionary with all fields.
    Uses the library's dict-like interface to capture all available fields.
    
    Args:
        whois_result: The whois.whois() result (dict-like object).
        domain: The domain that was queried.
        
    Returns:
        Structured dictionary ready for JSON serialization with all fields.
    """
    # Convert whois result to dict (captures ALL fields automatically)
    whois_dict = dict(whois_result)
    
    # Serialize datetime objects and structure the output
    serialized_data = _serialize_for_json(whois_dict)
    
    # Structure the output nicely, while preserving all fields
    result = {
        "metadata": {
            "scan_type": "whois",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain
        },
        "whois_data": serialized_data
    }
    
    return result


def save_json_report(data: dict, domain: str, output_dir: Path = OUTPUT_DIR) -> str:
    """
    Save WHOIS information as a structured JSON file.
    
    Args:
        data: Dictionary containing WHOIS data.
        domain: Domain name for filename.
        output_dir: Directory to save the JSON file.
        
    Returns:
        Path to the saved JSON file.
    """
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    filename = f"whois_{domain}.json"
    filepath = output_dir / filename
    
    # Save the structured data
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return str(filepath)


def whois_lookup(domain: str, save_output: bool = True) -> dict:
    """
    Main function to perform a WHOIS lookup and save results as JSON.
    
    Args:
        domain: The domain to lookup (e.g., "example.com")
        save_output: Whether to save the JSON report to file.
        
    Returns:
        Dictionary containing all WHOIS data with metadata.
    """
    whois_result, domain = get_whois_data(domain)
    result = whois_to_dict(whois_result, domain)
    
    if save_output:
        filepath = save_json_report(result, domain)
        print(f"✓ WHOIS report saved to: {filepath}")
    
    return result

