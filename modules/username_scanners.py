import os
import sys
import time
import shutil
import subprocess
import requests
import concurrent.futures
from typing import Optional
from modules.models import ToolResult

# --------------------------------------------------------------------------
# Sherlock (Username OSINT)
# --------------------------------------------------------------------------

def run_sherlock(username: str, timeout: int = 300, extra_args: Optional[list] = None) -> ToolResult:
    start = time.time()
    extra_args = extra_args or []

    check = subprocess.run(
        [sys.executable, "-m", "sherlock_project", "--help"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        base_cmd = [sys.executable, "-m", "sherlock_project"]
    elif shutil.which("sherlock") is not None:
        base_cmd = ["sherlock"]
    else:
        return ToolResult(
            tool="sherlock",
            identifier=username,
            success=False,
            error="Sherlock CLI executable not found on system PATH.",
            duration_seconds=time.time() - start,
        )

    with __import__("tempfile").TemporaryDirectory() as tmpdir:
        from pathlib import Path
        out_file = Path(tmpdir) / f"{username}.json"
        
        cmd = [
            *base_cmd,
            username,
            "--output", str(out_file.with_suffix("")),
            "--timeout", "5",
            "--print-found",
            "--no-color",
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
                cwd=tmpdir,
                env=custom_env,
                encoding="utf-8",
                errors="replace"
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="sherlock",
                identifier=username,
                success=False,
                error=f"Sherlock scan timed out after {timeout} seconds.",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool="sherlock",
                identifier=username,
                success=False,
                error=str(e),
                duration_seconds=time.time() - start,
            )

        found_sites = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                try:
                    rest = line[3:].strip()
                    site, url = rest.split(":", 1)
                    found_sites[site.strip()] = url.strip()
                except ValueError:
                    continue

        return ToolResult(
            tool="sherlock",
            identifier=username,
            success=proc.returncode == 0 or bool(found_sites),
            data={"found_count": len(found_sites), "profiles": found_sites},
            error=None if proc.returncode == 0 else f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Maigret (Extended Username OSINT, 3000+ sites)
# --------------------------------------------------------------------------

def run_maigret(username: str, timeout: int = 300, extra_args: Optional[list] = None) -> ToolResult:
    start = time.time()
    extra_args = extra_args or []

    check = subprocess.run(
        [sys.executable, "-m", "maigret", "--help"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        base_cmd = [sys.executable, "-m", "maigret"]
    elif shutil.which("maigret") is not None:
        base_cmd = ["maigret"]
    else:
        return ToolResult(
            tool="maigret",
            identifier=username,
            success=False,
            error="Maigret CLI executable not found on system PATH.",
            duration_seconds=time.time() - start,
        )

    with __import__("tempfile").TemporaryDirectory() as tmpdir:
        cmd = [
            *base_cmd,
            username,
            "--timeout", "10",
            "--no-color",
            "--folderoutput", tmpdir,
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
                cwd=tmpdir,
                env=custom_env,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool="maigret",
                identifier=username,
                success=False,
                error=f"Maigret scan timed out after {timeout} seconds.",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool="maigret",
                identifier=username,
                success=False,
                error=str(e),
                duration_seconds=time.time() - start,
            )

        found_sites = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                try:
                    rest = line[3:].strip()
                    site, url = rest.split(":", 1)
                    found_sites[site.strip()] = url.strip()
                except ValueError:
                    continue

        return ToolResult(
            tool="maigret",
            identifier=username,
            success=proc.returncode == 0 or bool(found_sites),
            data={"found_count": len(found_sites), "profiles": found_sites},
            error=None if proc.returncode == 0 else f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# WhatsMyName (Site-by-site Username Existence Check)
# --------------------------------------------------------------------------

WHATSMYNAME_DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

def _check_wmn_site(site: dict, username: str, session: requests.Session, timeout: int) -> Optional[dict]:
    uri_check = site.get("uri_check", "")
    if not uri_check or "{account}" not in uri_check:
        return None
    url = uri_check.replace("{account}", username)

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None

    expected_code = site.get("e_code")
    expected_string = site.get("e_string")
    missing_code = site.get("m_code")
    missing_string = site.get("m_string")

    code_ok = expected_code is None or resp.status_code == expected_code
    string_ok = not expected_string or expected_string in resp.text
    not_missing_code = missing_code is None or resp.status_code != missing_code
    not_missing_string = not missing_string or missing_string not in resp.text

    if code_ok and string_ok and not_missing_code and not_missing_string:
        return {"name": site.get("name", "unknown"), "url": url, "category": site.get("cat")}
    return None


def run_whatsmyname(username: str, timeout: int = 300, per_request_timeout: int = 6,
                    max_workers: int = 20, max_sites: Optional[int] = None) -> ToolResult:
    start = time.time()

    try:
        data_resp = requests.get(WHATSMYNAME_DATA_URL, timeout=15)
        data_resp.raise_for_status()
        wmn_data = data_resp.json()
    except (requests.RequestException, ValueError) as e:
        return ToolResult(
            tool="whatsmyname",
            identifier=username,
            success=False,
            error=f"Could not fetch WhatsMyName data file: {e}",
            duration_seconds=time.time() - start,
        )

    sites = wmn_data.get("sites", [])
    if max_sites:
        sites = sites[:max_sites]

    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (OSINT-Aggregator)"})

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_check_wmn_site, site, username, session, per_request_timeout): site
                for site in sites
            }
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                result = future.result()
                if result:
                    found.append(result)
    except concurrent.futures.TimeoutError:
        pass

    return ToolResult(
        tool="whatsmyname",
        identifier=username,
        success=True,
        data={"found_count": len(found), "sites_checked": len(sites), "profiles": found},
        error=None,
        duration_seconds=time.time() - start,
    )
