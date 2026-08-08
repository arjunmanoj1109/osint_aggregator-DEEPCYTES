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


# --------------------------------------------------------------------------
# Picuki (Login-free Instagram Profile Scraper)
# --------------------------------------------------------------------------

def run_picuki(username: str) -> ToolResult:
    """
    Scrapes Instagram profile metadata from the public Instagram viewer Picuki.
    Requires no login, API keys, or cookies.
    """
    start = time.time()
    url = f"https://www.picuki.com/profile/{username}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 403:
            return ToolResult(
                tool="picuki",
                identifier=username,
                success=False,
                error="Picuki is protected by Cloudflare anti-bot verification (WAF). Request blocked.",
                duration_seconds=time.time() - start,
            )
        if resp.status_code == 404:
            return ToolResult(
                tool="picuki",
                identifier=username,
                success=False,
                error="Instagram profile not found on Picuki.",
                duration_seconds=time.time() - start,
            )
        resp.raise_for_status()
        html = resp.text

        import re
        name_match = re.search(r'<h1 class="profile-name-second"[^>]*>(.*?)</h1>', html)
        real_name = name_match.group(1).strip() if name_match else None

        bio_match = re.search(r'<div class="profile-description"[^>]*>(.*?)</div>', html, re.DOTALL)
        bio = bio_match.group(1).strip() if bio_match else None

        follows_block_match = re.search(r'<div class="profile-follows"[^>]*>(.*?)</div>', html, re.DOTALL)
        followers = None
        following = None
        posts = None
        if follows_block_match:
            block = follows_block_match.group(1)
            followers_match = re.search(r'<b>([\d\.,KMkm]+)</b>\s*followers', block, re.IGNORECASE)
            following_match = re.search(r'<b>([\d\.,KMkm]+)</b>\s*following', block, re.IGNORECASE)
            posts_match = re.search(r'<b>([\d\.,KMkm]+)</b>\s*posts', block, re.IGNORECASE)
            if followers_match: followers = followers_match.group(1)
            if following_match: following = following_match.group(1)
            if posts_match: posts = posts_match.group(1)

        photo_match = re.search(r'<div class="profile-avatar"[^>]*>\s*<span[^>]*style="background-image:\s*url\(\'(.*?)\'\)', html)
        photo_url = photo_match.group(1) if photo_match else None

        data = {
            "username": username,
            "real_name": real_name or username,
            "biography": bio or "No biography provided.",
            "followers": followers or "0",
            "following": following or "0",
            "posts_count": posts or "0",
            "profile_picture": photo_url,
        }

        return ToolResult(
            tool="picuki",
            identifier=username,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="picuki",
            identifier=username,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Bluesky Profile Resolver (AT Protocol)
# --------------------------------------------------------------------------

def run_bluesky(handle: str) -> ToolResult:
    """
    Queries Bluesky public AT Protocol APIs to resolve handle to DID and get full profile.
    """
    start = time.time()
    clean_handle = handle.lstrip("@").strip()
    if "." not in clean_handle:
        clean_handle = f"{clean_handle}.bsky.social"
    try:
        resolve_url = f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={clean_handle}"
        resp_resolve = requests.get(resolve_url, timeout=10)
        if resp_resolve.status_code != 200:
            return ToolResult(
                tool="bluesky",
                identifier=handle,
                success=False,
                error=f"Could not resolve Bluesky handle. Status code: {resp_resolve.status_code}",
                duration_seconds=time.time() - start,
            )
        did = resp_resolve.json().get("did")
        if not did:
            return ToolResult(
                tool="bluesky",
                identifier=handle,
                success=False,
                error="Bluesky handle did not resolve to a DID.",
                duration_seconds=time.time() - start,
            )

        profile_url = f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={did}"
        resp_profile = requests.get(profile_url, timeout=10)
        if resp_profile.status_code != 200:
            err_msg = f"HTTP {resp_profile.status_code}"
            try:
                err_data = resp_profile.json()
                if "message" in err_data:
                    err_msg = f"{err_data.get('error')}: {err_data.get('message')}"
            except Exception:
                pass
            return ToolResult(
                tool="bluesky",
                identifier=handle,
                success=False,
                error=f"Could not retrieve profile. {err_msg}",
                duration_seconds=time.time() - start,
            )
        profile_data = resp_profile.json()

        data = {
            "did": did,
            "handle": profile_data.get("handle"),
            "display_name": profile_data.get("displayName") or clean_handle,
            "description": profile_data.get("description") or "No description provided.",
            "avatar": profile_data.get("avatar"),
            "banner": profile_data.get("banner"),
            "followers_count": profile_data.get("followersCount", 0),
            "follows_count": profile_data.get("followsCount", 0),
            "posts_count": profile_data.get("postsCount", 0),
            "created_at": profile_data.get("createdAt"),
        }

        return ToolResult(
            tool="bluesky",
            identifier=handle,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="bluesky",
            identifier=handle,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Discord Snowflake Decoder (Offline Math)
# --------------------------------------------------------------------------

def run_discord_snowflake(snowflake_id: str) -> ToolResult:
    """
    Performs bitwise arithmetic on a 64-bit Discord Snowflake ID
    to extract the exact account creation timestamp completely offline.
    """
    start = time.time()
    try:
        clean_id = snowflake_id.strip()
        if not clean_id.isdigit():
            raise ValueError("Discord Snowflake ID must consist only of numeric digits.")
        
        snowflake_int = int(clean_id)
        timestamp_ms = (snowflake_int >> 22) + 1420070400000
        
        from datetime import datetime, timezone
        creation_dt = datetime.fromtimestamp(timestamp_ms / 1000.0, timezone.utc)
        creation_str = creation_dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        
        data = {
            "snowflake_id": clean_id,
            "epoch_timestamp_ms": timestamp_ms,
            "creation_date_utc": creation_str,
            "creation_iso": creation_dt.isoformat(),
        }
        return ToolResult(
            tool="discord_snowflake",
            identifier=snowflake_id,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="discord_snowflake",
            identifier=snowflake_id,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Reddit Profile Auditor (SnooSnoop counterpart)
# --------------------------------------------------------------------------

def run_reddit(username: str) -> ToolResult:
    """
    Queries Reddit's public API to retrieve user account age, karma, and profile bio.
    Requires a realistic User-Agent to bypass rate limits.
    """
    start = time.time()
    clean_user = username.strip()
    url = f"https://www.reddit.com/user/{clean_user}/about.json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code == 403:
            return ToolResult(
                tool="reddit",
                identifier=username,
                success=False,
                error="Reddit is protected by anti-bot verification (JavaScript challenge). Request blocked.",
                duration_seconds=time.time() - start,
            )
        if resp.status_code == 404:
            return ToolResult(
                tool="reddit",
                identifier=username,
                success=False,
                error="Reddit user not found or deleted.",
                duration_seconds=time.time() - start,
            )
        resp.raise_for_status()
        raw_data = resp.json()
        user_data = raw_data.get("data", {})
        if not user_data:
            return ToolResult(
                tool="reddit",
                identifier=username,
                success=False,
                error="Invalid response structure from Reddit API.",
                duration_seconds=time.time() - start,
            )

        from datetime import datetime, timezone
        created_utc = user_data.get("created_utc")
        created_str = None
        if created_utc:
            created_str = datetime.fromtimestamp(created_utc, timezone.utc).isoformat()

        subreddit = user_data.get("subreddit") or {}
        bio = subreddit.get("public_description") or "No description provided."

        data = {
            "username": clean_user,
            "id": user_data.get("id"),
            "display_name": subreddit.get("title") or clean_user,
            "biography": bio,
            "created_at": created_str,
            "link_karma": user_data.get("link_karma", 0),
            "comment_karma": user_data.get("comment_karma", 0),
            "total_karma": user_data.get("total_karma", 0),
            "is_employee": user_data.get("is_employee"),
            "is_gold": user_data.get("is_gold"),
            "verified_email": user_data.get("has_verified_email"),
        }

        return ToolResult(
            tool="reddit",
            identifier=username,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="reddit",
            identifier=username,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# GitHub Profile Search
# --------------------------------------------------------------------------

def run_github(username: str) -> ToolResult:
    """
    Queries GitHub REST API to get username profile details.
    """
    start = time.time()
    clean_user = username.strip()
    url = f"https://api.github.com/users/{clean_user}"
    headers = {
        "User-Agent": "Mozilla/5.0 (OSINT-Aggregator)",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return ToolResult(
                tool="github",
                identifier=username,
                success=False,
                error="GitHub user profile not found.",
                duration_seconds=time.time() - start,
            )
        resp.raise_for_status()
        raw_data = resp.json()

        data = {
            "username": clean_user,
            "id": raw_data.get("id"),
            "real_name": raw_data.get("name"),
            "avatar_url": raw_data.get("avatar_url"),
            "company": raw_data.get("company"),
            "blog": raw_data.get("blog"),
            "location": raw_data.get("location"),
            "email": raw_data.get("email"),
            "biography": raw_data.get("bio") or "No biography provided.",
            "twitter_username": raw_data.get("twitter_username"),
            "public_repositories": raw_data.get("public_repos", 0),
            "followers": raw_data.get("followers", 0),
            "following": raw_data.get("following", 0),
            "created_at": raw_data.get("created_at"),
            "updated_at": raw_data.get("updated_at"),
        }

        return ToolResult(
            tool="github",
            identifier=username,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="github",
            identifier=username,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# GitHub Dorking URL Generator
# --------------------------------------------------------------------------

def run_github_dorking(username: str) -> ToolResult:
    """
    Generates targeted GitHub Search queries (dorks) to find code leaks
    (credentials, passwords, config files) matching a target handle.
    """
    start = time.time()
    clean_user = username.strip()
    
    dorks_list = [
        {"label": "Exposed JSON config credentials", "query": f'extension:json "{clean_user}"'},
        {"label": "Config files containing username", "query": f'filename:config "{clean_user}"'},
        {"label": "YAML details containing username", "query": f'extension:yml "{clean_user}"'},
        {"label": "Leaked passwords containing username", "query": f'"{clean_user}" password'},
        {"label": "Leaked access tokens containing username", "query": f'"{clean_user}" token'},
        {"label": "Leaked API keys containing username", "query": f'"{clean_user}" key'},
        {"label": "Linked Gmail address leaks", "query": f'"{clean_user}" @gmail.com'},
    ]

    import urllib.parse
    queries = []
    for d in dorks_list:
        encoded_q = urllib.parse.quote_plus(d["query"])
        search_url = f"https://github.com/search?q={encoded_q}&type=code"
        queries.append({
            "label": d["label"],
            "query": d["query"],
            "url": search_url
        })

    data = {
        "username": clean_user,
        "query_count": len(queries),
        "queries": queries
    }

    return ToolResult(
        tool="github_dorking",
        identifier=username,
        success=True,
        data=data,
        duration_seconds=time.time() - start,
    )
