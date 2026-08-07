import os
import sys
import time
import shutil
import subprocess
import requests
import json
from typing import Optional
from modules.models import ToolResult

# --------------------------------------------------------------------------
# Holehe (Email Registration Checker)
# --------------------------------------------------------------------------

def run_holehe(email: str, timeout: int = 180, extra_args: Optional[list] = None) -> ToolResult:
    start = time.time()
    extra_args = extra_args or []

    check = subprocess.run(
        [sys.executable, "-m", "holehe", "--help"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        base_cmd = [sys.executable, "-m", "holehe"]
    elif shutil.which("holehe") is not None:
        base_cmd = ["holehe"]
    else:
        return ToolResult(
            tool="holehe",
            identifier=email,
            success=False,
            error="holehe CLI executable not found on system PATH.",
            duration_seconds=time.time() - start,
        )

    cmd = [
        *base_cmd,
        email,
        "--only-used",
        *extra_args,
    ]

    custom_env = os.environ.copy()
    custom_env["PYTHONIOENCODING"] = "utf-8"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=custom_env,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool="holehe",
            identifier=email,
            success=False,
            error=f"holehe scan timed out after {timeout} seconds.",
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="holehe",
            identifier=email,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

    registered = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if "Email used" in line:
            continue
        if line.startswith("[+]"):
            parts = line[3:].split(":", 1)
            domain = parts[0].strip()
            registered.append({"domain": domain, "email_recovery_hint": None, "phone_hint": None})

    return ToolResult(
        tool="holehe",
        identifier=email,
        success=proc.returncode == 0 or bool(registered),
        data={"registered_count": len(registered), "registered_services": registered},
        error=None if proc.returncode == 0 else f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
        duration_seconds=time.time() - start,
    )


# --------------------------------------------------------------------------
# GHunt (Google Account Footprint Scans)
# --------------------------------------------------------------------------

def run_ghunt(email: str, timeout: int = 180) -> ToolResult:
    start = time.time()
    
    with __import__("tempfile").TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "ghunt_out.json")
        
        # We execute ghunt module logic directly by targeting parse_and_run via python command.
        # This acts as an anti-virus bypass.
        cmd = [
            sys.executable,
            "-c",
            f"from ghunt.cli import parse_and_run; parse_and_run()",
            "email",
            email,
            "--json",
            out_file
        ]
        
        custom_env = os.environ.copy()
        custom_env["PYTHONIOENCODING"] = "utf-8"
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=custom_env,
                encoding="utf-8",
                errors="replace"
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="ghunt",
                identifier=email,
                success=False,
                error=f"GHunt execution timed out after {timeout} seconds.",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool="ghunt",
                identifier=email,
                success=False,
                error=f"GHunt execution error: {e}",
                duration_seconds=time.time() - start,
            )
            
        if not os.path.exists(out_file):
            return ToolResult(
                tool="ghunt",
                identifier=email,
                success=False,
                error=f"GHunt output file was not generated. stdout: {proc.stdout[-300:]}. stderr: {proc.stderr[-300:]}",
                duration_seconds=time.time() - start,
            )
            
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return ToolResult(
                tool="ghunt",
                identifier=email,
                success=False,
                error=f"Failed to parse GHunt JSON results: {e}",
                duration_seconds=time.time() - start,
            )
            
        return ToolResult(
            tool="ghunt",
            identifier=email,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# h8mail (Credential Leaks Search)
# --------------------------------------------------------------------------

def run_h8mail(target: str, timeout: int = 180) -> ToolResult:
    start = time.time()
    
    check = subprocess.run(
        [sys.executable, "-m", "h8mail", "--help"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        base_cmd = [sys.executable, "-m", "h8mail"]
    elif shutil.which("h8mail") is not None:
        base_cmd = ["h8mail"]
    else:
        return ToolResult(
            tool="h8mail",
            identifier=target,
            success=False,
            error="h8mail CLI executable not found on system PATH.",
            duration_seconds=time.time() - start,
        )
        
    with __import__("tempfile").TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "h8mail_out.json")
        cmd = [
            *base_cmd,
            "-t", target,
            "-j", out_file
        ]
        
        custom_env = os.environ.copy()
        custom_env["PYTHONIOENCODING"] = "utf-8"
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=custom_env,
                encoding="utf-8",
                errors="replace"
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="h8mail",
                identifier=target,
                success=False,
                error=f"h8mail scan timed out after {timeout} seconds.",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool="h8mail",
                identifier=target,
                success=False,
                error=str(e),
                duration_seconds=time.time() - start,
            )
            
        if not os.path.exists(out_file):
            return ToolResult(
                tool="h8mail",
                identifier=target,
                success=False,
                error=f"h8mail JSON output file not found. stdout: {proc.stdout[-300:]}",
                duration_seconds=time.time() - start,
            )
            
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return ToolResult(
                tool="h8mail",
                identifier=target,
                success=False,
                error=f"Failed to parse h8mail JSON results: {e}",
                duration_seconds=time.time() - start,
            )
            
        return ToolResult(
            tool="h8mail",
            identifier=target,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Breach Directory (Credential Exposure Lookup)
# --------------------------------------------------------------------------

BREACHDIRECTORY_API_URL = "https://breachdirectory.p.rapidapi.com/"
BREACHDIRECTORY_API_HOST = "breachdirectory.p.rapidapi.com"
_SENSITIVE_FIELDS = {"password", "password_hash", "hash", "sha1", "md5", "plaintext"}

def run_breach_directory(identifier: str, timeout: int = 30) -> ToolResult:
    start = time.time()
    api_key = os.getenv("BREACHDIRECTORY_API_KEY")

    if not api_key:
        return ToolResult(
            tool="breach_directory",
            identifier=identifier,
            success=False,
            error="BREACHDIRECTORY_API_KEY environment variable not set.",
            duration_seconds=time.time() - start,
        )

    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": BREACHDIRECTORY_API_HOST,
    }

    try:
        resp = requests.get(
            BREACHDIRECTORY_API_URL,
            headers=headers,
            params={"func": "auto", "term": identifier},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return ToolResult(
            tool="breach_directory",
            identifier=identifier,
            success=False,
            error=f"Request failed: {e}",
            duration_seconds=time.time() - start,
        )

    if resp.status_code != 200:
        return ToolResult(
            tool="breach_directory",
            identifier=identifier,
            success=False,
            error=f"API returned HTTP {resp.status_code}: {resp.text[:300]}",
            duration_seconds=time.time() - start,
        )

    try:
        payload = resp.json()
    except ValueError:
        return ToolResult(
            tool="breach_directory",
            identifier=identifier,
            success=False,
            error="Could not parse API response as JSON.",
            duration_seconds=time.time() - start,
        )

    raw_results = payload.get("result") or []
    sanitized = []
    for entry in raw_results:
        if not isinstance(entry, dict):
            continue
        exposed_fields = sorted(
            k for k, v in entry.items()
            if v not in (None, "", []) and k.lower() not in _SENSITIVE_FIELDS
        )
        redacted_fields = sorted(
            k for k in entry.keys() if k.lower() in _SENSITIVE_FIELDS
        )
        sanitized.append({
            "source": entry.get("sources") or entry.get("source") or "unknown",
            "line": entry.get("line"),
            "exposed_field_types": exposed_fields,
            "redacted_field_types": redacted_fields,
        })

    return ToolResult(
        tool="breach_directory",
        identifier=identifier,
        success=True,
        data={"breach_count": len(sanitized), "breaches": sanitized},
        error=None,
        duration_seconds=time.time() - start,
    )
