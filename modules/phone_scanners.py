import os
import sys
import time
import shutil
import subprocess
from modules.models import ToolResult

def run_ignorant(phone_number: str, timeout: int = 30) -> ToolResult:
    """
    Checks if a target mobile phone number is registered on social media platforms
    using the Ignorant tool. Splits input into country code and number.
    """
    start = time.time()
    
    # Simple, robust parsing of country code and number
    phone_clean = phone_number.replace("+", "").strip()
    parts = phone_clean.split()
    if len(parts) >= 2:
        country_code = parts[0]
        number = "".join(parts[1:])
    else:
        # Heuristic fallbacks for common formats
        val = phone_clean
        if val.startswith("91") and len(val) == 12:
            country_code = "91"
            number = val[2:]
        elif val.startswith("44") and len(val) in (12, 13):
            country_code = "44"
            number = val[2:]
        elif val.startswith("33") and len(val) == 11:
            country_code = "33"
            number = val[2:]
        elif val.startswith("1") and len(val) == 11:
            country_code = "1"
            number = val[1:]
        elif val.startswith("49") and len(val) in (11, 12, 13):
            country_code = "49"
            number = val[2:]
        else:
            if len(val) <= 10:
                country_code = "1"
                number = val
            else:
                country_code = val[:2]
                number = val[2:]

    try:
        import ignorant.core
        base_cmd = [sys.executable, "-c", "from ignorant.core import main; main()"]
    except ImportError:
        if shutil.which("ignorant") is not None:
            base_cmd = ["ignorant"]
        else:
            return ToolResult(
                tool="ignorant",
                identifier=phone_number,
                success=False,
                error="Ignorant is not installed. Run 'pip install ignorant'.",
                duration_seconds=time.time() - start,
            )

    cmd = [
        *base_cmd,
        country_code,
        number
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
            tool="ignorant",
            identifier=phone_number,
            success=False,
            error=f"Ignorant scan timed out after {timeout} seconds.",
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="ignorant",
            identifier=phone_number,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )

    registered = []
    errors = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if "Phone number used" in line:
            continue
        if line.startswith("[+]"):
            parts = line[3:].split(":", 1)
            platform = parts[0].strip()
            registered.append(platform)
        elif line.startswith("[x]"):
            parts = line[3:].split(":", 1)
            platform = parts[0].strip()
            errors.append(platform)

    return ToolResult(
        tool="ignorant",
        identifier=phone_number,
        success=proc.returncode == 0 or bool(registered),
        data={
            "country_code": country_code,
            "number": number,
            "registered_count": len(registered),
            "registered_services": registered,
            "failed_or_rate_limited": errors
        },
        error=None if proc.returncode == 0 else f"Exit code {proc.returncode}: {proc.stderr[-300:]}",
        duration_seconds=time.time() - start,
    )

def run_phonenumbers(phone_number: str) -> ToolResult:
    start = time.time()
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
    except ImportError:
        return ToolResult(
            tool="phonenumbers",
            identifier=phone_number,
            success=False,
            error="phonenumbers package is not installed. Install via 'pip install phonenumbers'.",
            duration_seconds=time.time() - start,
        )

    try:
        # Parse the phone number
        # If it doesn't start with +, let's assume it has no leading + but might be formatted.
        parsed_num = phonenumbers.parse(phone_number, None)
        if not phonenumbers.is_valid_number(parsed_num):
            if not phone_number.startswith("+"):
                parsed_num = phonenumbers.parse("+" + phone_number, None)
        
        is_valid = phonenumbers.is_valid_number(parsed_num)
        
        number_type = phonenumbers.number_type(parsed_num)
        type_str = "UNKNOWN"
        if number_type == phonenumbers.PhoneNumberType.MOBILE:
            type_str = "MOBILE"
        elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
            type_str = "FIXED_LINE"
        elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:
            type_str = "FIXED_LINE_OR_MOBILE"
        elif number_type == phonenumbers.PhoneNumberType.TOLL_FREE:
            type_str = "TOLL_FREE"
        elif number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE:
            type_str = "PREMIUM_RATE"

        region = geocoder.description_for_number(parsed_num, "en")
        carrier_name = carrier.name_for_number(parsed_num, "en")
        timezones = list(timezone.time_zones_for_number(parsed_num))

        data = {
            "valid": is_valid,
            "format_international": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "format_national": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.NATIONAL),
            "format_e164": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164),
            "country_code": parsed_num.country_code,
            "national_number": parsed_num.national_number,
            "number_type": type_str,
            "location": region or "Unknown Location",
            "carrier": carrier_name or "Unknown Carrier",
            "timezones": timezones,
        }

        return ToolResult(
            tool="phonenumbers",
            identifier=phone_number,
            success=is_valid,
            data=data,
            error=None if is_valid else "Phone number is parsed but is not a valid international phone number.",
            duration_seconds=time.time() - start,
        )
    except Exception as e:
        return ToolResult(
            tool="phonenumbers",
            identifier=phone_number,
            success=False,
            error=str(e),
            duration_seconds=time.time() - start,
        )
