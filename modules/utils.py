from modules.models import ToolResult

def print_result_to_terminal(result: ToolResult):
    """Helper to cleanly display live tool findings on stdout."""
    status_str = "+ SUCCESS" if result.success else "- FAILED"
    print(f"\n[{status_str}] Tool: {result.tool.upper()} ({result.duration_seconds:.1f}s)")
    if not result.success:
        print(f"   Error: {result.error}")
        return

    data = result.data
    if result.tool in ("sherlock", "maigret"):
        profiles = data.get("profiles", {})
        print(f"   Profiles Found ({data.get('found_count', 0)}):")
        for site, url in profiles.items():
            print(f"     - {site}: {url}")

    elif result.tool == "whatsmyname":
        profiles = data.get("profiles", [])
        print(f"   Matches Found ({data.get('found_count', 0)} / {data.get('sites_checked', 0)} checked):")
        for item in profiles:
            print(f"     - {item.get('name')}: {item.get('url')}")

    elif result.tool == "holehe":
        services = data.get("registered_services", [])
        print(f"   Registered Accounts ({data.get('registered_count', 0)}):")
        for item in services:
            print(f"     - Domain: {item.get('domain')}")

    elif result.tool == "breach_directory":
        breaches = data.get("breaches", [])
        print(f"   Breaches Detected ({data.get('breach_count', 0)}):")
        for b in breaches:
            print(f"     - Source: {b.get('source')} | Fields: {', '.join(b.get('exposed_field_types', []))}")

    elif result.tool == "exiftool":
        print(f"   Metadata Fields Extracted ({data.get('field_count', 0)}):")
        gps = data.get("gps_fields", {})
        if gps:
            print(f"     GPS Fields: {gps}")
        else:
            print("     No GPS fields found.")

    elif result.tool == "wayback_machine":
        snaps = data.get("snapshots", [])
        print(f"   Snapshots Found ({data.get('snapshot_count', 0)}):")
        for s in snaps[:10]:
            print(f"     - {s.get('timestamp')}: {s.get('archive_url')}")

    elif result.tool == "theharvester":
        print(f"   Emails Found ({data.get('email_count', 0)}), Hosts Found ({data.get('host_count', 0)}):")
        for e in data.get("emails", [])[:10]:
            print(f"     - Email: {e}")
        for h in data.get("hosts", [])[:10]:
            print(f"     - Host: {h}")

    elif result.tool == "google_dorking":
        print(f"   Generated Dork Queries ({data.get('query_count', 0)}):")
        for q in data.get("queries", []):
            print(f"     - {q.get('label')}: {q.get('url')}")

    elif result.tool == "ignorant":
        registered = data.get("registered_services", [])
        print(f"   Registered Accounts ({data.get('registered_count', 0)}):")
        for item in registered:
            print(f"     - Platform: {item}")
        errors = data.get("failed_or_rate_limited", [])
        if errors:
            print(f"     - Rate limits / Errors on: {', '.join(errors)}")

    elif result.tool == "lookup_id":
        print(f"   Facebook Numeric ID: {data.get('facebook_id')}")

    elif result.tool == "ghunt":
        print(f"   Google Profile Details:")
        # Render clean key fields matching the structure returned in the parsed JSON
        # Let's check: in GHunt output, there's profile details.
        profile_container = data.get("PROFILE_CONTAINER", {})
        profile = profile_container.get("profile", {})
        names = profile.get("names", {}).get("PROFILE", {})
        name_val = f"{names.get('firstName', '')} {names.get('lastName', '')}".strip() or names.get('fullname', '')
        gaia_id = profile.get("personId", "")
        photo_url = profile.get("profilePhotos", {}).get("PROFILE", {}).get("url", "")
        
        print(f"     - Name: {name_val or 'None'}")
        print(f"     - GAIA ID: {gaia_id or 'None'}")
        if photo_url:
            print(f"     - Profile Photo: {photo_url}")
            
        in_app = profile.get("inAppReachability", {}).get("PROFILE", {}).get("apps", [])
        if in_app:
            print(f"     - Active Services: {', '.join(in_app)}")

    elif result.tool in ("hudsonrock_username", "hudsonrock_email"):
        stealers = data.get("stealers", [])
        if stealers:
            print(f"   Compromised Stealer Logs Found ({len(stealers)}):")
            for idx, s in enumerate(stealers[:5], 1):
                print(f"     [{idx}] Stealer Family: {s.get('stealer_family')}")
                print(f"         Date Compromised: {s.get('date_compromised')}")
                print(f"         Operating System: {s.get('operating_system')}")
                print(f"         Antiviruses: {', '.join(s.get('antiviruses', [])) or 'None'}")
                if s.get('top_passwords'):
                    print(f"         Masked Passwords: {', '.join(s.get('top_passwords'))}")
            if len(stealers) > 5:
                print(f"     ... and {len(stealers) - 5} more stealer logs.")
        else:
            print("   No infostealer compromise records found.")

    elif result.tool == "socialscan":
        registered = data.get("registered_platforms", [])
        if registered:
            print(f"   Registered Accounts ({len(registered)}):")
            for platform in registered:
                print(f"     - {platform}")
        else:
            print("   No registered accounts detected.")

    elif result.tool == "h8mail":
        print("   Breach check completed.")
        if isinstance(data, list):
            for target_data in data:
                print(f"     - Target: {target_data.get('target')}")
                breaches = target_data.get("breach_details", [])
                if breaches:
                    for b in breaches:
                        print(f"       Source: {b.get('source')} (Found in {len(b.get('found', []))} leaks)")
        elif isinstance(data, dict):
            targets = data.get("targets", [])
            for target_data in targets:
                print(f"     - Target: {target_data.get('target')}")
                breaches = target_data.get("breach_details", [])
                if breaches:
                    for b in breaches:
                        print(f"       Source: {b.get('source')} (Found in {len(b.get('found', []))} leaks)")

    elif result.tool in ("exifread", "pillow"):
        print(f"   Metadata Fields Extracted ({data.get('field_count', 0)}):")
        gps = data.get("gps", {})
        if gps:
            print(f"     Resolved GPS: Latitude {gps.get('latitude')}, Longitude {gps.get('longitude')}")
        else:
            print("     No GPS coordinates found in image metadata.")

    elif result.tool == "geopy_reverse":
        print(f"   Nominatim Reverse Geocoding Result:")
        print(f"     - Address: {data.get('address')}")

    elif result.tool == "ip_api":
        print(f"   IP-API Geolocation Details:")
        print(f"     - Country: {data.get('country')} ({data.get('countryCode')})")
        print(f"     - Region/City: {data.get('regionName')} / {data.get('city')}")
        print(f"     - ISP/Org: {data.get('isp')} / {data.get('org')}")
        print(f"     - Location: Latitude {data.get('lat')}, Longitude {data.get('lon')}")
        print(f"     - Timezone: {data.get('timezone')}")

    elif result.tool == "maxmind_geolite":
        print(f"   MaxMind GeoLite2 Geolocation Details:")
        print(f"     - Country: {data.get('country')} ({data.get('country_code')})")
        print(f"     - Region/City: {data.get('region')} / {data.get('city')}")
        print(f"     - Postal Code: {data.get('postal_code')}")
        print(f"     - Location: Latitude {data.get('latitude')}, Longitude {data.get('longitude')}")
        print(f"     - Timezone: {data.get('timezone')}")

    elif result.tool == "phonenumbers":
        print(f"   phonenumbers Telecom Details:")
        print(f"     - International Format: {data.get('format_international')}")
        print(f"     - National Format: {data.get('format_national')}")
        print(f"     - Carrier Network: {data.get('carrier')}")
        print(f"     - Registered Location: {data.get('location')}")
        print(f"     - Number Type: {data.get('number_type')}")
        print(f"     - Timezones: {', '.join(data.get('timezones', []))}")

    elif result.tool == "picuki":
        print(f"   Instagram (via Picuki) Profile Details:")
        print(f"     - Real Name: {data.get('real_name')}")
        print(f"     - Followers: {data.get('followers')}")
        print(f"     - Following: {data.get('following')}")
        print(f"     - Posts Count: {data.get('posts_count')}")
        print(f"     - Biography: {data.get('biography')}")
        if data.get('profile_picture'):
            print(f"     - Avatar URL: {data.get('profile_picture')}")

    elif result.tool == "bluesky":
        print(f"   Bluesky Actor Profile Details:")
        print(f"     - Display Name: {data.get('display_name')}")
        print(f"     - Handle Name: {data.get('handle')}")
        print(f"     - DID Identifier: {data.get('did')}")
        print(f"     - Account Created: {data.get('created_at')}")
        print(f"     - Followers / Follows: {data.get('followers_count')} / {data.get('follows_count')}")
        print(f"     - Posts Count: {data.get('posts_count')}")
        print(f"     - Biography: {data.get('description')}")

    elif result.tool == "discord_snowflake":
        print(f"   Discord Snowflake ID Decoded:")
        print(f"     - Discord ID: {data.get('snowflake_id')}")
        print(f"     - Calculated Created UTC: {data.get('creation_date_utc')}")

    elif result.tool == "reddit":
        print(f"   Reddit Profile Details:")
        print(f"     - Display Name: {data.get('display_name')}")
        print(f"     - Created UTC: {data.get('created_at')}")
        print(f"     - Total Karma (Link / Comment): {data.get('total_karma')} ({data.get('link_karma')} / {data.get('comment_karma')})")
        print(f"     - Email Verified: {data.get('verified_email')}")
        print(f"     - Biography: {data.get('biography')}")

    elif result.tool == "github":
        print(f"   GitHub User Profile Details:")
        print(f"     - Real Name: {data.get('real_name') or data.get('username')}")
        print(f"     - Created UTC: {data.get('created_at')}")
        print(f"     - Public Repositories: {data.get('public_repositories')}")
        print(f"     - Followers / Following: {data.get('followers')} / {data.get('following')}")
        if data.get('email'):
            print(f"     - Public Email: {data.get('email')}")
        if data.get('location'):
            print(f"     - Location: {data.get('location')}")
        if data.get('company'):
            print(f"     - Company: {data.get('company')}")
        print(f"     - Biography: {data.get('biography')}")

    elif result.tool == "github_dorking":
        print(f"   Targeted GitHub Code Leak Dorks ({data.get('query_count', 0)}):")
        for q in data.get("queries", []):
            print(f"     - {q.get('label')}: {q.get('url')}")
