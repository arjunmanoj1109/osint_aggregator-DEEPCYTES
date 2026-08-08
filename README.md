# OSINT Digital Footprint Aggregator Engine

An advanced, modular, and keyless OSINT (Open Source Intelligence) data aggregator designed to query, correlate, and document the digital footprint of target Usernames, Emails, Phone Numbers, Facebook profiles, Domains, and Image files.

It compiles results into structured JSON reports and includes a post-scan **Auto-Correlation Engine** to extract and geolocate discovered network entities.

---

## 📁 Project Architecture

The codebase utilizes a modular package layout, separating scanners by category:

```text
osint_aggregator/
  ├── osint_aggregator.py        # Main entrypoint CLI orchestrator
  ├── databases/                 # Folder for local binary databases (e.g. MaxMind GeoLite2-City.mmdb)
  ├── reports/                   # Saved JSON target scan profiles (auto-created)
  └── modules/
        ├── __init__.py          # Scanner registry exports
        ├── models.py            # Standardized schemas (ToolResult, Report) and serialization
        ├── utils.py             # Rich console formatting and ASCII printing blocks
        ├── username_scanners.py # Sherlock, Maigret, WhatsMyName, Picuki, Bluesky, Reddit, GitHub, GitHub Dorks
        ├── email_scanners.py    # Holehe, GHunt, h8mail, Breach Directory
        ├── phone_scanners.py    # Ignorant, phonenumbers
        ├── facebook_scanners.py # Lookup-ID
        └── passive_scanners.py  # Wayback, theHarvester, ExifTool, Dorking, Hudson Rock, Socialscan, Exifread, Pillow, ip-api, MaxMind GeoLite2, Geopy
```

---

## 🛠️ Installation & Setup

1. **Clone the Repository**:
   ```bash
   cd osint_aggregator
   ```

2. **Install Required Packages**:
   Make sure you have Python 3.8+ installed, then run:
   ```bash
   pip install -r requirements.txt
   ```
   *(Ensure dependencies like `requests`, `exifread`, `Pillow`, `geopy`, `geoip2`, and `phonenumbers` are installed).*

3. **Configure Database (Optional)**:
   Place your offline `GeoLite2-City.mmdb` database inside the `databases/` folder for local network geolocation lookups.

---

## 🚀 Usage Guide

### Complete Scan (All Target Fields)
Provide the identifiers you want to audit. The script executes fully non-interactively and saves the output directly.

```powershell
python osint_aggregator.py `
  --username "target_user" `
  --email "target_email@example.com" `
  --phone "+1 555-0199" `
  --facebook-url "https://www.facebook.com/zuck" `
  --domain "example.com" `
  --file "C:\path\to\photo.jpg" `
  -o reports/full_audit_profile.json
```

### Targeted Command-Line Option Flags

| CLI Flag | Input Category | Active Scanners |
| :--- | :--- | :--- |
| `--username` | Target Handle | Sherlock, Maigret, WhatsMyName, Picuki, Bluesky, Reddit, GitHub, GitHub Dorks |
| `--discord-id` | Discord Snowflake | Offline Discord creation timestamp decoder |
| `--email` | Target Email | Holehe, GHunt, h8mail, Breach Directory, Hudson Rock Email, Socialscan |
| `--phone` | Target Phone Number | Ignorant, phonenumbers telecom data |
| `--facebook-url` | Facebook profile URL | Lookup-ID converter |
| `--domain` | Domain or IP | theHarvester, Wayback Machine, ip-api, MaxMind GeoLite2 |
| `--file` | Photographic File | ExifTool, exifread, Pillow, Geopy reverse geocoding |
| `-o` | Output File Path | *(Optional)* Custom report destination. If omitted, the script automatically saves a timestamped file: `reports/osint_report_<target>_<timestamp>.json` |

### Skip Scan Flags
If you want to skip slow scanners or target API queries, you can supply individual bypass flags:
*   `--skip-sherlock`, `--skip-maigret`, `--skip-whatsmyname`
*   `--skip-holehe`, `--skip-ghunt`, `--skip-h8mail`, `--skip-breach-check`
*   `--skip-ignorant`, `--skip-phonenumbers`
*   `--skip-picuki`, `--skip-bluesky`, `--skip-reddit`, `--skip-github`, `--skip-github-dorks`
*   `--skip-discord-snowflake`
*   `--skip-lookup-id`
*   `--skip-theharvester`, `--skip-wayback`, `--skip-dorking`
*   `--skip-exiftool`, `--skip-exifread`, `--skip-pillow`, `--skip-geopy`
*   `--skip-ipapi`, `--skip-geolite`

---

## 🔍 Core Features

### 1. Auto-Correlation Engine
At the end of the scan pipeline, the script parses the collected data results for discovered IPv4 and IPv6 addresses. If found, it automatically geolocates them online (via `ip-api`) and offline (via `MaxMind GeoLite2`) to pinpoint physical location, ISP, and country info.

### 2. EXIF Coordinate Reverse Geocoding
When an image path is supplied via `--file`, the script extracts EXIF GPS coordinates (latitude/longitude decimal tags). If coordinates exist, they are passed directly into the **Geopy OpenStreetMap Nominatim** engine to output the **exact physical street address** where the photo was taken.

### 3. Anti-Bot Block Bypasses
For platforms with aggressive browser-verification checks (Instagram and Reddit public profile views):
*   The script handles WAF/403 blocks gracefully without raising tracebacks.
*   The orchestrator runs **Socialscan** queries independently on both email and username targets to verify profile existence directly via backend registration endpoints, bypassing the browser blocks.

### 4. Non-Interactive Reporting
The aggregator pipeline executes completely non-interactively without prompting for permissions, files, or raw outputs:
*   Reports are automatically converted into structured JSON profiles.
*   Outputs are saved inside the local `reports/` folder. If a custom name isn't specified, a timestamped name (e.g. `osint_report_<target>_<timestamp>.json`) is generated automatically.

### 5. OSINT Pivoting Engine (Stage 2 Recursion)
The script performs automatic multi-stage pivoting:
*   If a **GitHub Profile Search** reveals a public email address registered to a user account, the Pivoting Engine dynamically extracts it.
*   The email address is automatically queued for Stage 2 checks (**Holehe**, **GHunt**, **h8mail**, **Breach Directory**, and **Socialscan**), avoiding duplicates if that email was already scanned.

### 6. Smart Discord Snowflake Auto-Trigger
*   If a username consisting only of digits (17–20 characters) is entered, the script automatically identifies it as a Discord Snowflake ID and triggers the offline binary bit-shift decoder to output the exact millisecond of account registration.

### 7. Front-Loaded Interactive Prompts
*   When executing without CLI flags in interactive mode, the terminal will ask for all **7 target inputs** (Username, Email, Phone, Facebook URL, Discord ID, Domain, and Image path) upfront. This ensures that the script runs continuously without interrupting you for prompts midway through.

---

## ⏱️ Performance & Run Times

*   **Full Power Scan**: Takes **3 to 4 minutes** (approx. 180 to 240 seconds) on average. 
*   **Primary Bottlenecks**: `Sherlock` and `Maigret` query thousands of websites sequentially/in batches, representing ~80% of total run time.
*   **Speed Up Tip**: To run a rapid scan in **under 30 seconds**, skip the slow scanners:
    ```powershell
    python osint_aggregator.py --username "target_user" --skip-maigret
    ```