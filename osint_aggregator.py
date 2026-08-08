#!/usr/bin/env python3
"""
OSINT Digital Footprint Aggregator (Sherlock Specialized Engine)
-------------------------------------------------------------------
A modular framework for running OSINT reconnaissance tools against target
identifiers (usernames) and aggregating findings into a clean JSON report.

REQUIREMENTS
    pip install sherlock-project maigret requests holehe ignorant ghunt socialscan h8mail

    Breach Directory lookups require an API key from RapidAPI's
    "Breach Directory" API, set as an environment variable or via fallback.

    WhatsMyName queries the live community-maintained site-definition file.

    holehe checks whether an email is registered on ~120 online services.

    ExifTool requires the exiftool binary on PATH (e.g. `apt install
    libimage-exiftool-perl` or `brew install exiftool`). Operates only on
    local files you provide -- no network lookups.

    Wayback Machine and Google Dorking need no extra installs or API
    keys; they call the Internet Archive's public CDX API and build
    search-query URLs, respectively.

    theHarvester requires `pip install theHarvester` (or the CLI on
    PATH) and only uses free, keyless sources (Bing, DuckDuckGo, crt.sh)
    by default.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Import modular package elements
from modules.models import Report
from modules.utils import print_result_to_terminal
from modules.username_scanners import (
    run_sherlock,
    run_maigret,
    run_whatsmyname,
    run_picuki,
    run_bluesky,
    run_discord_snowflake,
    run_reddit,
    run_github,
    run_github_dorking
)
from modules.email_scanners import run_holehe, run_ghunt, run_h8mail, run_breach_directory
from modules.phone_scanners import run_ignorant, run_phonenumbers
from modules.facebook_scanners import run_lookup_id
from modules.passive_scanners import (
    run_wayback,
    run_theharvester,
    run_exiftool,
    run_google_dorking,
    run_hudsonrock_username,
    run_hudsonrock_email,
    run_socialscan,
    run_exifread,
    run_pillow_exif,
    run_geopy_reverse,
    run_ip_api,
    run_maxmind_geolite
)

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Username Digital Footprint Aggregator."
    )
    parser.add_argument("--username", help="Target username handle to search")
    parser.add_argument("--discord-id", default=None, help="Target Discord Snowflake ID to decode")
    parser.add_argument("--email", default=None, help="Target email address")
    parser.add_argument("--phone", default=None, help="Target phone number (e.g. '+33 644637111' or '33 644637111')")
    parser.add_argument("--facebook-url", default=None, help="Target Facebook Profile/Group URL for Lookup-ID")
    parser.add_argument("--domain", default=None, help="Target domain for theHarvester (optional)")
    parser.add_argument("--file", default=None, help="Local file path for ExifTool metadata extraction (optional)")
    parser.add_argument("--skip-breach-check", action="store_true", help="Skip Breach Directory lookup")
    parser.add_argument("--skip-maigret", action="store_true", help="Skip Maigret scan")
    parser.add_argument("--skip-whatsmyname", action="store_true", help="Skip WhatsMyName scan")
    parser.add_argument("--skip-holehe", action="store_true", help="Skip holehe email scan")
    parser.add_argument("--skip-exiftool", action="store_true", help="Skip ExifTool metadata extraction")
    parser.add_argument("--skip-wayback", action="store_true", help="Skip Wayback Machine snapshot lookup")
    parser.add_argument("--skip-theharvester", action="store_true", help="Skip theHarvester domain scan")
    parser.add_argument("--skip-dorking", action="store_true", help="Skip Google Dork query generation")
    parser.add_argument("--skip-ignorant", action="store_true", help="Skip Ignorant phone scan")
    parser.add_argument("--skip-lookup-id", action="store_true", help="Skip Lookup-ID Facebook URL scan")
    parser.add_argument("--skip-ghunt", action="store_true", help="Skip GHunt Google account scan")
    parser.add_argument("--skip-hudsonrock", action="store_true", help="Skip Hudson Rock infostealer scan")
    parser.add_argument("--skip-socialscan", action="store_true", help="Skip Socialscan fast account scan")
    parser.add_argument("--skip-h8mail", action="store_true", help="Skip h8mail breach search")
    parser.add_argument("--skip-exifread", action="store_true", help="Skip Exifread image metadata scan")
    parser.add_argument("--skip-pillow", action="store_true", help="Skip Pillow image metadata scan")
    parser.add_argument("--skip-ipapi", action="store_true", help="Skip IP-API Geolocation lookup")
    parser.add_argument("--skip-geolite", action="store_true", help="Skip MaxMind GeoLite2 Geolocation lookup")
    parser.add_argument("--skip-geopy", action="store_true", help="Skip geopy reverse geocoding lookup")
    parser.add_argument("--skip-phonenumbers", action="store_true", help="Skip phonenumbers telecom info lookup")
    parser.add_argument("--skip-picuki", action="store_true", help="Skip Picuki Instagram lookup")
    parser.add_argument("--skip-bluesky", action="store_true", help="Skip Bluesky lookup")
    parser.add_argument("--skip-discord-snowflake", action="store_true", help="Skip Discord Snowflake decoding")
    parser.add_argument("--skip-reddit", action="store_true", help="Skip Reddit lookup")
    parser.add_argument("--skip-github", action="store_true", help="Skip GitHub lookup")
    parser.add_argument("--skip-github-dorks", action="store_true", help="Skip GitHub search dorks")
    parser.add_argument("--geolite-db", default=None, help="Path to local GeoLite2-City.mmdb database file")
    parser.add_argument("--wmn-max-sites", type=int, default=None, help="Limit WhatsMyName sites")
    parser.add_argument("--timeout", type=int, default=300, help="Execution timeout in seconds")
    parser.add_argument("-o", "--output", default=None, help="Path to write JSON report")
    args = parser.parse_args()

    print("\n" + "="*55)
    print("      OSINT DIGITAL FOOTPRINT AGGREGATOR ENGINE      ")
    print("="*55 + "\n")

    is_interactive = sys.stdin.isatty()

    # Prompt user for Username if not provided via CLI and in interactive terminal
    username = args.username
    if not username and is_interactive:
        if not (args.email or args.phone or args.domain or args.facebook_url or args.file):
            username = input("[?] Enter Target Username (or press Enter to skip): ").strip()
            if not username:
                username = None

    # Prompt user for Email if not provided via CLI and in interactive terminal
    email = args.email
    if not email and is_interactive:
        email_input = input("[?] Enter Target Email (Optional, press Enter to skip): ").strip()
        email = email_input if email_input else None

    # Prompt user for Phone if not provided via CLI and in interactive terminal
    phone = args.phone
    if not phone and is_interactive and not args.skip_ignorant:
        phone_input = input("[?] Enter Target Phone Number (Optional, e.g. +33 644637111 or press Enter to skip): ").strip()
        phone = phone_input if phone_input else None

    # Prompt user for Facebook URL if not provided via CLI and in interactive terminal
    facebook_url = args.facebook_url
    if not facebook_url and is_interactive and not args.skip_lookup_id:
        fb_input = input("[?] Enter Target Facebook URL (Optional, press Enter to skip): ").strip()
        facebook_url = fb_input if fb_input else None

    report = Report(
        identifiers={
            "username": username,
            "email": email,
            "phone": phone,
            "facebook_url": facebook_url,
            "domain": args.domain,
            "file": args.file,
        },
        generated_at=datetime.now(timezone.utc).isoformat()
    )

    target_desc = username or email or phone or facebook_url or args.domain or args.file or "all-targets"
    print(f"\n[*] Starting Execution Pipeline for target: '{target_desc}'")

    # 1. Sherlock (requires username)
    if username:
        print(f"\n[*] [1/4] Executing Sherlock ...")
        res_sherlock = run_sherlock(username, timeout=args.timeout)
        report.results.append(res_sherlock)
        print_result_to_terminal(res_sherlock)
    else:
        print("\n[!] No username provided. Skipping Sherlock.")

    # 2. Breach Directory
    if not args.skip_breach_check:
        breach_target = email or username or phone
        if breach_target:
            print(f"\n[*] [2/4] Executing Breach Directory ('{breach_target}') ...")
            res_breach = run_breach_directory(breach_target)
            report.results.append(res_breach)
            print_result_to_terminal(res_breach)
        else:
            print("\n[!] No email, username or phone provided. Skipping Breach Directory.")

    # 3. Maigret (requires username)
    if not args.skip_maigret:
        if username:
            print(f"\n[*] [3/4] Executing Maigret ...")
            res_maigret = run_maigret(username, timeout=args.timeout)
            report.results.append(res_maigret)
            print_result_to_terminal(res_maigret)
        else:
            print("\n[!] No username provided. Skipping Maigret.")

    # 4. WhatsMyName (requires username)
    if not args.skip_whatsmyname:
        if username:
            print(f"\n[*] [4/4] Executing WhatsMyName ...")
            res_wmn = run_whatsmyname(username, timeout=args.timeout, max_sites=args.wmn_max_sites)
            report.results.append(res_wmn)
            print_result_to_terminal(res_wmn)
            
            if not args.skip_hudsonrock:
                print(f"\n[*] Executing Hudson Rock Stealer Logs Search ('{username}') ...")
                res_hr_user = run_hudsonrock_username(username, timeout=args.timeout)
                report.results.append(res_hr_user)
                print_result_to_terminal(res_hr_user)
        else:
            print("\n[!] No username provided. Skipping WhatsMyName.")
            if not args.skip_hudsonrock:
                print("\n[!] No username provided. Skipping Hudson Rock Username search.")

    # Username Extra Scans (Picuki, Bluesky, Reddit, GitHub, GitHub Dorks)
    if username:
        if not args.skip_picuki:
            print(f"\n[*] Executing Picuki Instagram lookup ('{username}') ...")
            res_picuki = run_picuki(username)
            report.results.append(res_picuki)
            print_result_to_terminal(res_picuki)
            
        if not args.skip_bluesky:
            print(f"\n[*] Executing Bluesky Profile Resolver ('{username}') ...")
            res_bsky = run_bluesky(username)
            report.results.append(res_bsky)
            print_result_to_terminal(res_bsky)
            
        if not args.skip_reddit:
            print(f"\n[*] Executing Reddit Profile Auditor ('{username}') ...")
            res_reddit = run_reddit(username)
            report.results.append(res_reddit)
            print_result_to_terminal(res_reddit)
            
        if not args.skip_github:
            print(f"\n[*] Executing GitHub Profile Search ('{username}') ...")
            res_github = run_github(username)
            report.results.append(res_github)
            print_result_to_terminal(res_github)
            
        if not args.skip_github_dorks:
            print(f"\n[*] Executing GitHub Code Leak Dorking ('{username}') ...")
            res_gh_dorks = run_github_dorking(username)
            report.results.append(res_gh_dorks)
            print_result_to_terminal(res_gh_dorks)

    # Discord Snowflake Decoding
    discord_snowflake_target = args.discord_id
    if not discord_snowflake_target and username and username.isdigit() and len(username) >= 17 and len(username) <= 20:
        discord_snowflake_target = username
        print(f"[*] Auto-detected username '{username}' as a Discord Snowflake ID.")

    if discord_snowflake_target:
        if not args.skip_discord_snowflake:
            print(f"\n[*] Decoding Discord Snowflake ID ('{discord_snowflake_target}') ...")
            res_discord = run_discord_snowflake(discord_snowflake_target)
            report.results.append(res_discord)
            print_result_to_terminal(res_discord)

    # Email Specific Scans (Holehe, GHunt, Hudson Rock Email, h8mail)
    if email:
        if not args.skip_holehe:
            print(f"\n[*] Executing Holehe ('{email}') ...")
            res_holehe = run_holehe(email, timeout=args.timeout)
            report.results.append(res_holehe)
            print_result_to_terminal(res_holehe)
        if not args.skip_ghunt:
            print(f"\n[*] Executing GHunt ('{email}') ...")
            res_ghunt = run_ghunt(email, timeout=args.timeout)
            report.results.append(res_ghunt)
            print_result_to_terminal(res_ghunt)
        if not args.skip_hudsonrock:
            print(f"\n[*] Executing Hudson Rock Stealer Logs Search ('{email}') ...")
            res_hr_email = run_hudsonrock_email(email, timeout=args.timeout)
            report.results.append(res_hr_email)
            print_result_to_terminal(res_hr_email)
        if not args.skip_h8mail:
            print(f"\n[*] Executing h8mail ('{email}') ...")
            res_h8mail = run_h8mail(email, timeout=args.timeout)
            report.results.append(res_h8mail)
            print_result_to_terminal(res_h8mail)
    else:
        if not args.skip_holehe:
            print("\n[!] No email provided. Skipping Holehe.")
        if not args.skip_ghunt:
            print("\n[!] No email provided. Skipping GHunt.")
        if not args.skip_hudsonrock:
            print("\n[!] No email provided. Skipping Hudson Rock Email search.")
        if not args.skip_h8mail:
            print("\n[!] No email provided. Skipping h8mail.")

    # Socialscan (Username and/or Email lookup)
    if not args.skip_socialscan:
        if email or username:
            if email:
                print(f"\n[*] Executing Socialscan Email Lookup ('{email}') ...")
                res_social_email = run_socialscan(email)
                report.results.append(res_social_email)
                print_result_to_terminal(res_social_email)
            if username:
                print(f"\n[*] Executing Socialscan Username Lookup ('{username}') ...")
                res_social_user = run_socialscan(username)
                report.results.append(res_social_user)
                print_result_to_terminal(res_social_user)
        else:
            print("\n[!] No email or username provided. Skipping Socialscan.")

    # Phone Specific Scans (Ignorant, phonenumbers)
    if phone:
        if not args.skip_ignorant:
            print(f"\n[*] Executing Ignorant ('{phone}') ...")
            res_ignorant = run_ignorant(phone, timeout=args.timeout)
            report.results.append(res_ignorant)
            print_result_to_terminal(res_ignorant)
        if not args.skip_phonenumbers:
            print(f"\n[*] Executing phonenumbers telecom parsing ('{phone}') ...")
            res_phone_info = run_phonenumbers(phone)
            report.results.append(res_phone_info)
            print_result_to_terminal(res_phone_info)
    else:
        if not args.skip_ignorant:
            print("\n[!] No phone number provided. Skipping Ignorant.")
        if not args.skip_phonenumbers:
            print("\n[!] No phone number provided. Skipping phonenumbers telecom check.")

    # Facebook Lookup ID Scans
    if facebook_url:
        if not args.skip_lookup_id:
            print(f"\n[*] Executing Lookup-ID ('{facebook_url}') ...")
            res_lookup = run_lookup_id(facebook_url, timeout=args.timeout)
            report.results.append(res_lookup)
            print_result_to_terminal(res_lookup)
    else:
        if not args.skip_lookup_id:
            print("\n[!] No Facebook URL provided. Skipping Lookup-ID.")

    # Google Dorking
    if not args.skip_dorking:
        dork_target = email or username or phone
        if dork_target:
            print(f"\n[*] Executing Google Dorking ('{dork_target}') ...")
            res_dork = run_google_dorking(dork_target)
            report.results.append(res_dork)
            print_result_to_terminal(res_dork)
        else:
            print("\n[!] No target identifier available for Google Dorking.")

    # Wayback Machine
    if not args.skip_wayback:
        wayback_target = args.domain or username or facebook_url
        if wayback_target:
            print(f"\n[*] Executing Wayback Machine ('{wayback_target}') ...")
            res_wayback = run_wayback(wayback_target, timeout=args.timeout)
            report.results.append(res_wayback)
            print_result_to_terminal(res_wayback)
        else:
            print("\n[!] No domain or username available for Wayback Machine.")

    # Domain / IP specific scans (theHarvester, ip-api, maxmind_geolite)
    target_domain = args.domain
    if not target_domain and is_interactive and not (args.skip_theharvester and args.skip_ipapi):
        domain_input = input("[?] Enter Target Domain or IP Address (Optional, press Enter to skip): ").strip()
        target_domain = domain_input if domain_input else None

    if target_domain:
        # theHarvester
        if not args.skip_theharvester:
            print(f"\n[*] Executing theHarvester ('{target_domain}') ...")
            res_harvester = run_theharvester(target_domain, timeout=args.timeout)
            report.results.append(res_harvester)
            print_result_to_terminal(res_harvester)
            
        # ip-api
        if not args.skip_ipapi:
            print(f"\n[*] Executing IP-API Geolocation ('{target_domain}') ...")
            res_ip_api = run_ip_api(target_domain)
            report.results.append(res_ip_api)
            print_result_to_terminal(res_ip_api)
            
        # maxmind_geolite (requires resolving the domain to IP first, or if target is already an IP)
        if not args.skip_geolite:
            import socket
            ip_to_check = None
            # check if it is already an IP format
            is_ip = True
            for part in target_domain.split('.'):
                if not part.isdigit():
                    is_ip = False
                    break
            if is_ip and len(target_domain.split('.')) == 4:
                ip_to_check = target_domain
            else:
                try:
                    ip_to_check = socket.gethostbyname(target_domain)
                    print(f"[*] Resolved '{target_domain}' to IP '{ip_to_check}' for offline database lookup.")
                except Exception:
                    pass
            
            if ip_to_check:
                print(f"\n[*] Executing MaxMind GeoLite2 Geolocation ('{ip_to_check}') ...")
                res_geolite = run_maxmind_geolite(ip_to_check, db_path=args.geolite_db)
                report.results.append(res_geolite)
                print_result_to_terminal(res_geolite)
            else:
                print("\n[!] Could not resolve target to an IP address. Skipping MaxMind GeoLite2.")
    else:
        if not args.skip_theharvester:
            print("\n[!] No domain provided. Skipping theHarvester.")
        if not args.skip_ipapi:
            print("\n[!] No domain or IP provided. Skipping IP-API Geolocation.")
        if not args.skip_geolite:
            print("\n[!] No domain or IP provided. Skipping MaxMind GeoLite2.")

    # File Specific Scans (ExifTool, Exifread, Pillow)
    file_path = args.file
    if not file_path and is_interactive:
        if not (args.skip_exiftool and args.skip_exifread and args.skip_pillow):
            file_input = input("[?] Enter local file path for image metadata extraction (Optional, press Enter to skip): ").strip()
            file_path = file_input if file_input else None

    extracted_latitude = None
    extracted_longitude = None

    if file_path:
        # ExifTool
        if not args.skip_exiftool:
            print(f"\n[*] Executing ExifTool ('{file_path}') ...")
            res_exif = run_exiftool(file_path, timeout=args.timeout)
            report.results.append(res_exif)
            print_result_to_terminal(res_exif)

        # Exifread
        if not args.skip_exifread:
            print(f"\n[*] Executing Exifread ('{file_path}') ...")
            res_exifread = run_exifread(file_path)
            report.results.append(res_exifread)
            print_result_to_terminal(res_exifread)
            if res_exifread.success:
                gps = res_exifread.data.get("gps", {})
                if gps.get("latitude") is not None:
                    extracted_latitude = gps.get("latitude")
                    extracted_longitude = gps.get("longitude")

        # Pillow
        if not args.skip_pillow:
            print(f"\n[*] Executing Pillow Metadata Reader ('{file_path}') ...")
            res_pillow = run_pillow_exif(file_path)
            report.results.append(res_pillow)
            print_result_to_terminal(res_pillow)
            if res_pillow.success:
                gps = res_pillow.data.get("gps", {})
                if gps.get("latitude") is not None:
                    extracted_latitude = gps.get("latitude")
                    extracted_longitude = gps.get("longitude")
    else:
        if not args.skip_exiftool:
            print("\n[!] No file path provided. Skipping ExifTool.")
        if not args.skip_exifread:
            print("\n[!] No file path provided. Skipping Exifread.")
        if not args.skip_pillow:
            print("\n[!] No file path provided. Skipping Pillow.")

    # Geopy Reverse Geocoding (if coordinates extracted)
    if extracted_latitude is not None and extracted_longitude is not None:
        if not args.skip_geopy:
            print(f"\n[*] Coordinates extracted: {extracted_latitude}, {extracted_longitude}")
            print(f"[*] Executing Geopy Reverse Geocoding (OSM Nominatim) ...")
            res_geopy = run_geopy_reverse(extracted_latitude, extracted_longitude)
            report.results.append(res_geopy)
            print_result_to_terminal(res_geopy)

    # Post-Scan IP Discovery & Geolocation Correlation Engine
    discovered_ips = set()
    import re
    import ipaddress
    queried_ips = set()
    if target_domain:
        is_ip = True
        for part in target_domain.split('.'):
            if not part.isdigit():
                is_ip = False
                break
        if is_ip and len(target_domain.split('.')) == 4:
            queried_ips.add(target_domain)
        else:
            import socket
            try:
                resolved_ip = socket.gethostbyname(target_domain)
                queried_ips.add(resolved_ip)
            except Exception:
                pass

    for res in report.results:
        if not res.success or not res.data:
            continue
        if res.tool == "theharvester":
            for ip in res.data.get("ips", []):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_loopback and not ip_obj.is_unspecified:
                        discovered_ips.add(str(ip_obj))
                except ValueError:
                    pass

        def extract_ips(obj):
            if isinstance(obj, str):
                # Split standard tokens to test for IPs
                tokens = re.split(r'[\s,;"\'\[\]\(\)\{\}]+', obj)
                for token in tokens:
                    token = token.strip().strip(':')
                    if not token:
                        continue
                    try:
                        ip_obj = ipaddress.ip_address(token)
                        if not ip_obj.is_loopback and not ip_obj.is_unspecified:
                            discovered_ips.add(str(ip_obj))
                    except ValueError:
                        pass
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    extract_ips(k)
                    extract_ips(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract_ips(item)

        extract_ips(res.data)

    ips_to_geocode = discovered_ips - queried_ips

    if ips_to_geocode:
        print("\n" + "="*55)
        print(f"[*] AUTO-CORRELATION: Discovered {len(ips_to_geocode)} new IP(s) in scan details:")
        print("="*55)
        for ip in sorted(ips_to_geocode):
            print(f"[*] Discovered IP: {ip}")
            if not args.skip_ipapi:
                print(f"[*] Geolocating discovered IP via IP-API ({ip}) ...")
                res_ip_api = run_ip_api(ip)
                report.results.append(res_ip_api)
                print_result_to_terminal(res_ip_api)
            if not args.skip_geolite:
                print(f"[*] Geolocating discovered IP via MaxMind ({ip}) ...")
                res_geolite = run_maxmind_geolite(ip, db_path=args.geolite_db)
                report.results.append(res_geolite)
                print_result_to_terminal(res_geolite)

    output_json = json.dumps(report.to_dict(), indent=2)

    # Output Options
    print("\n" + "="*55)
    print("                 SCAN COMPLETE                    ")
    print("="*55)

    # Print raw JSON directly to Terminal
    if is_interactive:
        try:
            show_json = input("\n[?] Print full Raw JSON report to terminal? (y/n) [default: y]: ").strip().lower()
            if show_json in ['', 'y', 'yes']:
                print("\n--- RAW JSON REPORT START ---")
                print(output_json)
                print("--- RAW JSON REPORT END ---\n")
        except KeyboardInterrupt:
            pass

    # Save to JSON File
    output_path = args.output
    if not output_path and is_interactive:
        try:
            save_prompt = input("[?] Save this report to a JSON file? (y/n) [default: y]: ").strip().lower()
            if save_prompt in ['', 'y', 'yes']:
                file_name = input("[?] Enter output filename (Press Enter for default): ").strip()
                if not file_name:
                    target_slug = str(username or email or phone or "osint")
                    target_slug = "".join(c for c in target_slug if c.isalnum() or c in ('@', '.', '_', '-'))
                    file_name = f"osint_report_{target_slug}_{int(time.time())}.json"
                output_path = file_name
        except KeyboardInterrupt:
            print("\n[!] Exiting without saving file.")

    if output_path:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        target_path = Path(output_path)
        if not target_path.is_absolute():
            target_path = reports_dir / target_path.name
            
        target_path.write_text(output_json, encoding="utf-8")
        print(f"\n[+] File saved successfully: {target_path}")


if __name__ == "__main__":
    main()