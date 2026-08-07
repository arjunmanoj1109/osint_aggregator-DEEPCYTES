import os
import sys
import time
import shutil
import subprocess
import requests
import json
from pathlib import Path
from typing import Optional
import urllib.parse
from modules.models import ToolResult

# --------------------------------------------------------------------------
# ExifTool (File Metadata Extraction)
# --------------------------------------------------------------------------

def run_exiftool(file_path: str, timeout: int = 30) -> ToolResult:
    """
    Runs ExifTool as a subprocess against a local file the user supplies,
    extracting embedded metadata (EXIF/GPS/camera/author fields, etc).
    Operates only on files the user provides -- no network lookups.
    """
    start = time.time()

    if not Path(file_path).is_file():
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error=f"File not found: {file_path}",
            duration_seconds=time.time() - start,
        )

    if shutil.which("exiftool") is None:
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error="exiftool executable not found on system PATH. Install via "
                  "your package manager (e.g. `apt install libimage-exiftool-perl` "
                  "or `brew install exiftool`).",
            duration_seconds=time.time() - start,
        )

    cmd = ["exiftool", "-json", "-G", file_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error=f"exiftool timed out after {timeout} seconds.",
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

    if proc.returncode != 0:
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error=f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
            duration_seconds=time.time() - start,
        )

    try:
        parsed = json.loads(proc.stdout)
        metadata = parsed[0] if parsed else {}
    except (ValueError, IndexError):
        return ToolResult(
            tool="exiftool",
            identifier=file_path,
            success=False,
            error="Could not parse exiftool JSON output.",
            duration_seconds=time.time() - start,
        )

    gps_fields = {k: v for k, v in metadata.items() if "gps" in k.lower()}

    return ToolResult(
        tool="exiftool",
        identifier=file_path,
        success=True,
        data={"metadata": metadata, "gps_fields": gps_fields, "field_count": len(metadata)},
        error=None,
        duration_seconds=time.time() - start,
    )


# --------------------------------------------------------------------------
# Wayback Machine (Historical Snapshot Lookup)
# --------------------------------------------------------------------------

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

def run_wayback(target_url: str, timeout: int = 30, limit: int = 50) -> ToolResult:
    """
    Queries the Internet Archive's free, public CDX API for historical
    snapshots of a given URL/domain. No API key required.
    """
    start = time.time()

    params = {
        "url": target_url,
        "output": "json",
        "limit": str(limit),
        "collapse": "timestamp:8",  # one snapshot per day
    }

    try:
        resp = requests.get(WAYBACK_CDX_URL, params=params, timeout=timeout)
    except requests.RequestException as e:
        return ToolResult(
            tool="wayback_machine",
            identifier=target_url,
            success=False,
            error=f"Request failed: {e}",
            duration_seconds=time.time() - start,
        )

    if resp.status_code != 200:
        return ToolResult(
            tool="wayback_machine",
            identifier=target_url,
            success=False,
            error=f"API returned HTTP {resp.status_code}: {resp.text[:300]}",
            duration_seconds=time.time() - start,
        )

    try:
        rows = resp.json()
    except ValueError:
        return ToolResult(
            tool="wayback_machine",
            identifier=target_url,
            success=False,
            error="Could not parse CDX API response as JSON.",
            duration_seconds=time.time() - start,
        )

    if not rows:
        return ToolResult(
            tool="wayback_machine",
            identifier=target_url,
            success=True,
            data={"snapshot_count": 0, "snapshots": []},
            error=None,
            duration_seconds=time.time() - start,
        )

    header, *data_rows = rows
    snapshots = []
    for row in data_rows:
        entry = dict(zip(header, row))
        timestamp = entry.get("timestamp", "")
        original = entry.get("original", target_url)
        snapshots.append({
            "timestamp": timestamp,
            "status_code": entry.get("statuscode"),
            "mime_type": entry.get("mimetype"),
            "archive_url": f"https://web.archive.org/web/{timestamp}/{original}" if timestamp else None,
        })

    return ToolResult(
        tool="wayback_machine",
        identifier=target_url,
        success=True,
        data={"snapshot_count": len(snapshots), "snapshots": snapshots},
        error=None,
        duration_seconds=time.time() - start,
    )


# --------------------------------------------------------------------------
# theHarvester (Corporate/Domain OSINT)
# --------------------------------------------------------------------------

def run_theharvester(domain: str, timeout: int = 300, sources: str = "bing,duckduckgo,crtsh",
                      extra_args: Optional[list] = None) -> ToolResult:
    """
    Runs theHarvester as a subprocess to passively gather emails,
    subdomains, and hosts tied to a target domain using public sources
    (search engines, certificate transparency logs, etc). No API key
    required for the default source set.
    """
    start = time.time()
    extra_args = extra_args or []

    check = subprocess.run(
        [sys.executable, "-m", "theHarvester", "--help"],
        capture_output=True, text=True,
    )
    if check.returncode == 0:
        base_cmd = [sys.executable, "-m", "theHarvester"]
    elif shutil.which("theHarvester") is not None:
        base_cmd = ["theHarvester"]
    else:
        return ToolResult(
            tool="theharvester",
            identifier=domain,
            success=False,
            error="theHarvester CLI executable not found on system PATH.",
            duration_seconds=time.time() - start,
        )

    with __import__("tempfile").TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "harvester_out.json"
        cmd = [
            *base_cmd,
            "-d", domain,
            "-b", sources,
            "-f", str(out_file),
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
                tool="theharvester",
                identifier=domain,
                success=False,
                error=f"theHarvester scan timed out after {timeout} seconds.",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ToolResult(
                tool="theharvester",
                identifier=domain,
                success=False,
                error=str(e),
                duration_seconds=time.time() - start,
            )

        candidates = [out_file, out_file.with_suffix(""), Path(str(out_file) + ".json")]
        parsed = None
        for candidate in candidates:
            if candidate.exists():
                try:
                    parsed = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                    break
                except ValueError:
                    continue

        if parsed is None:
            return ToolResult(
                tool="theharvester",
                identifier=domain,
                success=proc.returncode == 0,
                data={"raw_output": proc.stdout.strip()},
                error=None if proc.returncode == 0 else f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
                duration_seconds=time.time() - start,
            )

        emails = parsed.get("emails", []) or []
        hosts = parsed.get("hosts", []) or []
        ips = parsed.get("ips", []) or []

        return ToolResult(
            tool="theharvester",
            identifier=domain,
            success=True,
            data={
                "email_count": len(emails),
                "emails": emails,
                "host_count": len(hosts),
                "hosts": hosts,
                "ips": ips,
            },
            error=None,
            duration_seconds=time.time() - start,
        )


# --------------------------------------------------------------------------
# Google Dorking (Search Query Builder)
# --------------------------------------------------------------------------

def run_google_dorking(target: str) -> ToolResult:
    """
    Builds a set of ready-to-use Google Dork search URLs for a target
    identifier (name, username, domain, or email).
    """
    start = time.time()

    dorks = {
        "site_search": f'site:linkedin.com "{target}"',
        "filetype_pdf": f'"{target}" filetype:pdf',
        "filetype_docx": f'"{target}" filetype:docx OR filetype:xlsx',
        "intitle_profile": f'intitle:"{target}" (profile OR bio OR about)',
        "exposed_config": f'"{target}" (intitle:"index of" OR filetype:env OR filetype:log)',
        "pastebin_mentions": f'"{target}" site:pastebin.com',
        "social_mentions": f'"{target}" (site:twitter.com OR site:x.com OR site:facebook.com OR site:instagram.com)',
    }

    queries = []
    for label, query in dorks.items():
        queries.append({
            "label": label,
            "query": query,
            "url": "https://www.google.com/search?q=" + urllib.parse.quote(query),
        })

    return ToolResult(
        tool="google_dorking",
        identifier=target,
        success=True,
        data={"query_count": len(queries), "queries": queries},
        error=None,
        duration_seconds=time.time() - start,
    )


# --------------------------------------------------------------------------
# Hudson Rock (Infostealer Log OSINT)
# --------------------------------------------------------------------------

def run_hudsonrock(identifier: str, search_type: str = "username", timeout: int = 30) -> ToolResult:
    """
    Queries Hudson Rock's free OSINT API endpoints for target infostealer logs.
    """
    start = time.time()
    
    if search_type == "username":
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={identifier}"
    elif search_type == "email":
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={identifier}"
    else:
        return ToolResult(
            tool=f"hudsonrock_{search_type}",
            identifier=identifier,
            success=False,
            error=f"Invalid search type: {search_type}",
            duration_seconds=time.time() - start,
        )
        
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        
        return ToolResult(
            tool=f"hudsonrock_{search_type}",
            identifier=identifier,
            success=True,
            data=data,
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool=f"hudsonrock_{search_type}",
            identifier=identifier,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

def run_hudsonrock_username(username: str, timeout: int = 30) -> ToolResult:
    return run_hudsonrock(username, search_type="username", timeout=timeout)

def run_hudsonrock_email(email: str, timeout: int = 30) -> ToolResult:
    return run_hudsonrock(email, search_type="email", timeout=timeout)


# --------------------------------------------------------------------------
# Socialscan (Fast Account Checker)
# --------------------------------------------------------------------------

def run_socialscan(identifier: str) -> ToolResult:
    """
    Checks if a username or email is registered on major platforms using socialscan.
    """
    start = time.time()
    try:
        from socialscan.util import sync_execute_queries
    except ImportError:
        return ToolResult(
            tool="socialscan",
            identifier=identifier,
            success=False,
            error="socialscan package is not installed. Install via 'pip install socialscan'.",
            duration_seconds=time.time() - start,
        )

    try:
        responses = sync_execute_queries([identifier])
        taken_platforms = []
        for r in responses:
            if r.success and r.valid and not r.available:
                taken_platforms.append(str(r.platform).split(".")[-1].lower())
                
        return ToolResult(
            tool="socialscan",
            identifier=identifier,
            success=True,
            data={"registered_count": len(taken_platforms), "registered_platforms": taken_platforms},
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="socialscan",
            identifier=identifier,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

# --------------------------------------------------------------------------
# ExifRead (Pure Python EXIF parser)
# --------------------------------------------------------------------------

def _get_exifread_gps_info(tags):
    def _to_decimal(value):
        try:
            d = float(value.values[0].num) / float(value.values[0].den)
            m = float(value.values[1].num) / float(value.values[1].den)
            s = float(value.values[2].num) / float(value.values[2].den)
            return d + (m / 60.0) + (s / 3600.0)
        except Exception:
            return None

    lat_val = tags.get('GPS GPSLatitude')
    lat_ref = tags.get('GPS GPSLatitudeRef')
    lon_val = tags.get('GPS GPSLongitude')
    lon_ref = tags.get('GPS GPSLongitudeRef')

    if lat_val and lat_ref and lon_val and lon_ref:
        lat = _to_decimal(lat_val)
        lon = _to_decimal(lon_val)
        if lat is not None and lon is not None:
            if str(lat_ref.values) != 'N':
                lat = -lat
            if str(lon_ref.values) != 'E':
                lon = -lon
            return lat, lon
    return None

def run_exifread(file_path: str) -> ToolResult:
    start = time.time()
    if not Path(file_path).is_file():
        return ToolResult(
            tool="exifread",
            identifier=file_path,
            success=False,
            error=f"File not found: {file_path}",
            duration_seconds=time.time() - start,
        )

    try:
        import exifread
    except ImportError:
        return ToolResult(
            tool="exifread",
            identifier=file_path,
            success=False,
            error="exifread package is not installed. Install via 'pip install exifread'.",
            duration_seconds=time.time() - start,
        )

    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        
        metadata = {}
        for tag, val in tags.items():
            # Exclude thumbnail tag data to keep output clean and lightweight
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail'):
                metadata[tag] = str(val)

        gps_info = _get_exifread_gps_info(tags)
        gps_data = {}
        if gps_info:
            gps_data["latitude"] = gps_info[0]
            gps_data["longitude"] = gps_info[1]

        return ToolResult(
            tool="exifread",
            identifier=file_path,
            success=True,
            data={"metadata": metadata, "gps": gps_data, "field_count": len(metadata)},
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="exifread",
            identifier=file_path,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

# --------------------------------------------------------------------------
# Pillow (PIL EXIF Metadata Extraction)
# --------------------------------------------------------------------------

def _get_pillow_gps_info(exif_data):
    from PIL.ExifTags import TAGS, GPSTAGS
    gps_info = {}
    if not exif_data:
        return None
    for key, val in exif_data.items():
        tag = TAGS.get(key)
        if tag == "GPSInfo":
            for gps_key in val:
                gps_tag = GPSTAGS.get(gps_key, gps_key)
                gps_info[gps_tag] = val[gps_key]
    
    if not gps_info:
        return None
        
    def _to_decimal(rational_tuple):
        try:
            d = rational_tuple[0]
            m = rational_tuple[1]
            s = rational_tuple[2]
            d = float(d)
            m = float(m)
            s = float(s)
            return d + (m / 60.0) + (s / 3600.0)
        except Exception:
            return None

    lat_ref = gps_info.get("GPSLatitudeRef")
    lat_val = gps_info.get("GPSLatitude")
    lon_ref = gps_info.get("GPSLongitudeRef")
    lon_val = gps_info.get("GPSLongitude")

    if lat_ref and lat_val and lon_ref and lon_val:
        lat = _to_decimal(lat_val)
        lon = _to_decimal(lon_val)
        if lat is not None and lon is not None:
            if lat_ref != 'N':
                lat = -lat
            if lon_ref != 'E':
                lon = -lon
            return lat, lon
    return None

def run_pillow_exif(file_path: str) -> ToolResult:
    start = time.time()
    if not Path(file_path).is_file():
        return ToolResult(
            tool="pillow",
            identifier=file_path,
            success=False,
            error=f"File not found: {file_path}",
            duration_seconds=time.time() - start,
        )

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return ToolResult(
            tool="pillow",
            identifier=file_path,
            success=False,
            error="Pillow package is not installed. Install via 'pip install Pillow'.",
            duration_seconds=time.time() - start,
        )

    try:
        with Image.open(file_path) as img:
            exif_data = img.getexif()
            
        metadata = {}
        if exif_data:
            for key, val in exif_data.items():
                tag = TAGS.get(key, key)
                metadata[str(tag)] = str(val)

        gps_info = _get_pillow_gps_info(exif_data)
        gps_data = {}
        if gps_info:
            gps_data["latitude"] = gps_info[0]
            gps_data["longitude"] = gps_info[1]

        return ToolResult(
            tool="pillow",
            identifier=file_path,
            success=True,
            data={"metadata": metadata, "gps": gps_data, "field_count": len(metadata)},
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="pillow",
            identifier=file_path,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

# --------------------------------------------------------------------------
# Geopy Nominatim Reverse Geocoding
# --------------------------------------------------------------------------

def run_geopy_reverse(latitude: float, longitude: float) -> ToolResult:
    start = time.time()
    identifier = f"{latitude},{longitude}"
    try:
        from geopy.geocoders import Nominatim
    except ImportError:
        return ToolResult(
            tool="geopy_reverse",
            identifier=identifier,
            success=False,
            error="geopy package is not installed. Install via 'pip install geopy'.",
            duration_seconds=time.time() - start,
        )

    try:
        geolocator = Nominatim(user_agent="osint-footprint-aggregator")
        location = geolocator.reverse((latitude, longitude), timeout=10)
        if location:
            return ToolResult(
                tool="geopy_reverse",
                identifier=identifier,
                success=True,
                data={
                    "address": location.address,
                    "raw": location.raw,
                    "latitude": latitude,
                    "longitude": longitude,
                },
                duration_seconds=time.time() - start,
            )
        else:
            return ToolResult(
                tool="geopy_reverse",
                identifier=identifier,
                success=False,
                error="Nominatim returned no address results for these coordinates.",
                duration_seconds=time.time() - start,
            )
    except Exception as e:
        return ToolResult(
            tool="geopy_reverse",
            identifier=identifier,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

# --------------------------------------------------------------------------
# IP-API Geolocation (Free Online Lookup)
# --------------------------------------------------------------------------

def run_ip_api(ip_or_domain: str) -> ToolResult:
    start = time.time()
    url = f"http://ip-api.com/json/{ip_or_domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        success = data.get("status") == "success"
        return ToolResult(
            tool="ip_api",
            identifier=ip_or_domain,
            success=success,
            data=data,
            error=None if success else data.get("message", "API query failed"),
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="ip_api",
            identifier=ip_or_domain,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

# --------------------------------------------------------------------------
# MaxMind GeoLite2 Geolocation (Offline DB Lookup)
# --------------------------------------------------------------------------

def run_maxmind_geolite(ip_address: str, db_path: Optional[str] = None) -> ToolResult:
    start = time.time()
    if not db_path:
        db_path = os.path.join("databases", "GeoLite2-City.mmdb")
        
    if not os.path.isfile(db_path):
        return ToolResult(
            tool="maxmind_geolite",
            identifier=ip_address,
            success=False,
            error=f"GeoLite2-City database file not found at '{db_path}'. Place the .mmdb file there or specify via --geolite-db.",
            duration_seconds=time.time() - start,
        )

    try:
        import geoip2.database
    except ImportError:
        return ToolResult(
            tool="maxmind_geolite",
            identifier=ip_address,
            success=False,
            error="geoip2 package is not installed. Install via 'pip install geoip2'.",
            duration_seconds=time.time() - start,
        )

    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip_address)
            data = {
                "ip": ip_address,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "city": response.city.name,
                "postal_code": response.postal.code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
            }
            return ToolResult(
                tool="maxmind_geolite",
                identifier=ip_address,
                success=True,
                data=data,
                duration_seconds=time.time() - start,
            )
    except Exception as e:
        return ToolResult(
            tool="maxmind_geolite",
            identifier=ip_address,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )
