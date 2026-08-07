import time
import requests
import re
from modules.models import ToolResult

def run_lookup_id(facebook_url: str, timeout: int = 30) -> ToolResult:
    """
    Converts a Facebook profile/group/page URL to its unique numeric Facebook ID
    by querying the free lookup-id.com service.
    """
    start = time.time()
    url = "https://lookup-id.com/"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://lookup-id.com/"
    }
    
    payload = {
        "fburl": facebook_url,
        "check": "Lookup"
    }
    
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as e:
        return ToolResult(
            tool="lookup_id",
            identifier=facebook_url,
            success=False,
            error=f"HTTP request failed: {e}",
            duration_seconds=time.time() - start,
        )
        
    match = re.search(r'<span[^>]*id=["\']code["\'][^>]*>(.*?)</span>', resp.text, re.IGNORECASE | re.DOTALL)
    if not match:
        err_match = re.search(r'<div[^>]*class=["\']error["\'][^>]*>(.*?)</div>', resp.text, re.IGNORECASE)
        error_msg = err_match.group(1).strip() if err_match else "Could not extract Facebook ID from response. Check if URL is correct/public."
        return ToolResult(
            tool="lookup_id",
            identifier=facebook_url,
            success=False,
            error=error_msg,
            duration_seconds=time.time() - start,
        )
        
    fb_id = match.group(1).strip()
    return ToolResult(
        tool="lookup_id",
        identifier=facebook_url,
        success=True,
        data={
            "facebook_url": facebook_url,
            "facebook_id": fb_id
        },
        error=None,
        duration_seconds=time.time() - start,
    )
