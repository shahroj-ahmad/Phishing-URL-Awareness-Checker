#!/usr/bin/env python3
"""
=============================================================================
Project Name : EWB Phishing URL Awareness Checker
Module       : phishing_checker.py
Description  : Beginner-friendly cybersecurity awareness tool that inspects
               URL text for common phishing and spoofing indicators.
               Runs entirely locally using the Python standard library.
Security Note: This tool NEVER performs network requests, DNS lookups, or
               visits any destination. It operates purely via static string
               and lexical pattern analysis for defensive education.
=============================================================================
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

# Maximum typical URL length before flagging as suspicious (Requirement 2)
MAX_URL_LENGTH_THRESHOLD = 100

# Minimum number of dot-separated hostname segments to flag (Requirement 4)
SUBDOMAIN_SEGMENT_THRESHOLD = 5

# Punycode prefix indicating an Internationalized Domain Name (Requirement 5)
PUNYCODE_PREFIX = "xn--"

# Regular expression pattern to recognize an IPv4 address hostname (Requirement 3)
# Validates 4 octets where each octet is a number between 0 and 255.
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
)

# ANSI Color formatting codes for terminal presentation (with reset)
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_BLUE = "\033[94m"
ANSI_GRAY = "\033[90m"
ANSI_RESET = "\033[0m"


# =============================================================================
# INDIVIDUAL WARNING CHECKS
# =============================================================================

def check_at_symbol(url: str, parsed: urllib.parse.ParseResult) -> Optional[Dict[str, str]]:
    """
    Check 1: Detect the presence of an '@' symbol in the URL.

    Educational Context:
    RFC 3986 allows an '@' symbol to separate user authentication info from the
    host (e.g., http://username:password@actual-destination.com).
    Phishing threat actors exploit this by crafting deceptive links like:
    https://mybank.com@malicious-domain.example/login
    Many users only read the beginning of the URL ('mybank.com') and mistakenly
    believe they are on a legitimate website, whereas modern browsers route the
    traffic entirely to the domain specified after the '@' character.

    Args:
        url: The raw sanitized URL string.
        parsed: The urllib.parse ParseResult object.

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    if "@" in url or parsed.username is not None:
        return {
            "check_id": "CHECK_1_AT_SYMBOL",
            "name": "Presence of '@' Credential/Redirection Symbol",
            "severity": "HIGH",
            "finding": "The '@' character was found in the URL.",
            "explanation": (
                "Attackers use the '@' symbol in phishing attacks to trick victims into "
                "believing they are visiting the brand name before the '@', while the "
                "browser actually directs traffic to the host located after the '@'."
            ),
        }
    return None


def check_url_length(url: str, max_length: int = MAX_URL_LENGTH_THRESHOLD) -> Optional[Dict[str, str]]:
    """
    Check 2: Flag URLs longer than 100 characters.

    Educational Context:
    Excessively long URLs are commonly utilized in phishing and social engineering
    campaigns. Long query parameters or padded subdirectories push the actual
    destination domain out of view, especially on mobile browsers or email clients
    with narrow address bars.

    Args:
        url: The raw sanitized URL string.
        max_length: Character limit threshold (default: 100).

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    if len(url) > max_length:
        return {
            "check_id": "CHECK_2_LONG_URL",
            "name": "Excessive URL Length (> 100 characters)",
            "severity": "MEDIUM",
            "finding": f"URL length is {len(url)} characters (threshold: {max_length}).",
            "explanation": (
                "Phishing links often use exceptionally long strings to obscure the "
                "true destination host, hiding deceptive subdomains or malicious tokens "
                "beyond the visible boundary of mobile or desktop browser address bars."
            ),
        }
    return None


def check_ipv4_hostname(hostname: str) -> Optional[Dict[str, str]]:
    """
    Check 3: Detect an IPv4-address-style hostname.

    Educational Context:
    Standard websites almost exclusively use domain names (e.g., example.com)
    backed by public DNS. Threat actors frequently host phishing kits on direct
    IP addresses to avoid domain registration verification, conceal their identity,
    or bypass reputation databases that monitor domain name registrations.

    Args:
        hostname: The hostname component extracted from the URL.

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    if not hostname:
        return None

    # Strip port if present in hostname (e.g., '192.0.2.10:8080')
    host_clean = hostname.split(":")[0].strip()

    if IPV4_REGEX.match(host_clean):
        return {
            "check_id": "CHECK_3_IPV4_HOST",
            "name": "Raw IPv4 Address Hostname",
            "severity": "HIGH",
            "finding": f"Hostname '{host_clean}' is a direct numeric IPv4 address.",
            "explanation": (
                "Legitimate institutions and organizations use registered domain names "
                "(e.g., 'bank.com') rather than direct numeric IP addresses. Direct IPs "
                "are frequently associated with rogue servers or evasion techniques."
            ),
        }
    return None


def check_subdomain_segments(
    hostname: str, threshold: int = SUBDOMAIN_SEGMENT_THRESHOLD
) -> Optional[Dict[str, str]]:
    """
    Check 4: Flag hostnames containing five or more dot-separated segments.

    Educational Context:
    A domain normally consists of two to three segments (e.g., 'sub.example.com' or
    'example.co.uk'). Phishers frequently create deeply nested subdomains (e.g.,
    'login.verify.account.paypal.com.attacker-controlled.net') to trick the victim
    into seeing trusted brand names within the URL.

    Args:
        hostname: The hostname component extracted from the URL.
        threshold: Minimum segment count to trigger warning (default: 5).

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    if not hostname:
        return None

    # Strip port if present
    host_clean = hostname.split(":")[0].strip()

    # If the hostname is a pure IP address, segment count check is not applicable
    # because IPv4 naturally has 4 octets.
    if IPV4_REGEX.match(host_clean):
        return None

    segments = [seg for seg in host_clean.split(".") if seg]
    if len(segments) >= threshold:
        return {
            "check_id": "CHECK_4_EXCESSIVE_SEGMENTS",
            "name": f"Deeply Nested Hostname ({len(segments)} dot segments)",
            "severity": "MEDIUM",
            "finding": (
                f"Hostname contains {len(segments)} segments: "
                f"{'.'.join(segments)} (threshold: {threshold}+)."
            ),
            "explanation": (
                "Multiple levels of subdomains are frequently engineered to visually "
                "mimic legitimate service URLs (e.g., 'login.security.brand.verify.com.evil.xyz') "
                "to deceive victims into trusting an unauthorized domain."
            ),
        }
    return None


def check_punycode_hostname(hostname: str) -> Optional[Dict[str, str]]:
    """
    Check 5: Detect punycode-style hostnames containing 'xn--'.

    Educational Context:
    Punycode is an encoding scheme used to represent Internationalized Domain Names
    (IDNs) using ASCII characters (prefix 'xn--'). Attackers use Punycode to carry
    out 'IDN Homograph Attacks', substituting Latin characters with visually identical
    Cyrillic, Greek, or Unicode glyphs (e.g., replacing Latin 'a' with Cyrillic 'а')
    to create deceptive replicas of popular domains.

    Args:
        hostname: The hostname component extracted from the URL.

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    if not hostname:
        return None

    host_lower = hostname.lower()
    if PUNYCODE_PREFIX in host_lower:
        return {
            "check_id": "CHECK_5_PUNYCODE",
            "name": "Punycode / IDN Homograph Indicator ('xn--')",
            "severity": "HIGH",
            "finding": f"Hostname '{hostname}' contains Punycode prefix '{PUNYCODE_PREFIX}'.",
            "explanation": (
                "Punycode ('xn--') allows domain names to encode international characters. "
                "Threat actors use this mechanism to create visually identical lookalike "
                "domains (homograph attacks) that deceive users into entering credentials."
            ),
        }
    return None


def check_http_scheme(scheme: str, raw_url: str) -> Optional[Dict[str, str]]:
    """
    Check 6: Flag URLs using HTTP instead of HTTPS (or missing scheme).

    Educational Context:
    Plain HTTP ('http://') sends data in unencrypted cleartext across the network,
    exposing passwords, session cookies, and sensitive details to interception or
    manipulation via Man-in-the-Middle (MitM) attacks. Modern legitimate portals
    exclusively enforce HTTPS with valid SSL/TLS certificates.

    Args:
        scheme: The scheme extracted from the URL (e.g., 'http', 'https').
        raw_url: The raw URL string for fallback verification.

    Returns:
        A dictionary with warning details if triggered, or None if safe.
    """
    scheme_clean = (scheme or "").lower().strip()

    # Triggered if explicitly 'http'
    if scheme_clean == "http":
        return {
            "check_id": "CHECK_6_INSECURE_HTTP",
            "name": "Insecure Protocol (HTTP instead of HTTPS)",
            "severity": "HIGH",
            "finding": "The URL uses unencrypted 'http://' rather than encrypted 'https://'.",
            "explanation": (
                "HTTP does not provide encryption or server identity verification. "
                "Any sensitive data entered on HTTP websites can be monitored, captured, "
                "or modified by attackers on the same network."
            ),
        }

    # If no protocol scheme was provided at all
    if not scheme_clean and not raw_url.lower().startswith("https://"):
        return {
            "check_id": "CHECK_6_MISSING_SCHEME",
            "name": "Missing Secure Protocol (Scheme Not Specified)",
            "severity": "MEDIUM",
            "finding": "No 'https://' protocol was specified in the URL.",
            "explanation": (
                "The URL lacks an explicit secure protocol ('https://'). When accessed, "
                "browsers or applications may default to unencrypted communication."
            ),
        }

    return None


# =============================================================================
# CORE ANALYSIS ENGINE
# =============================================================================

def parse_url_safely(raw_url: str) -> Tuple[Optional[urllib.parse.ParseResult], Optional[str]]:
    """
    Safely parses a URL string into components using urllib.parse.urlparse.
    Handles missing schemes gracefully to ensure hostname extraction succeeds.

    Args:
        raw_url: The user-supplied URL string.

    Returns:
        A tuple of (ParseResult object, error_message or None).
    """
    try:
        # Standard urllib.parse.urlparse requires '//' or a scheme to correctly
        # populate the 'netloc' and 'hostname' fields.
        url_to_parse = raw_url
        if "://" not in raw_url and not raw_url.startswith("//"):
            # Provide double slashes for component extraction without modifying original text
            url_to_parse = f"//{raw_url}"

        parsed = urllib.parse.urlparse(url_to_parse)
        return parsed, None
    except Exception as exc:
        return None, f"Malformed URL parsing error: {exc}"


def analyze_url(raw_input: Optional[str]) -> Dict[str, Any]:
    """
    Examines a URL string against all six cybersecurity phishing awareness checks.

    This function never visits the destination, never resolves DNS, and never
    sends network traffic. It conducts pure local lexical analysis.

    Args:
        raw_input: The input string entered by the user.

    Returns:
        A dictionary containing:
            - 'url': The sanitized input string.
            - 'is_empty': True if input was empty or whitespace.
            - 'is_malformed': True if parsing failed critically.
            - 'error_message': Description of any parsing or input fault.
            - 'warnings': List of detected warning dictionaries.
            - 'warning_count': Total number of warnings detected.
            - 'status': 'EMPTY', 'MALFORMED', 'REVIEW_CAREFULLY', or 'NO_WARNINGS'.
            - 'hostname': Extracted hostname string.
            - 'scheme': Extracted scheme string.
    """
    # 1. Handle empty or None input gracefully
    if raw_input is None:
        return {
            "url": "",
            "is_empty": True,
            "is_malformed": False,
            "error_message": "Input was None. Please provide a valid URL string.",
            "warnings": [],
            "warning_count": 0,
            "status": "EMPTY",
            "hostname": "",
            "scheme": "",
        }

    sanitized_url = raw_input.strip()

    if not sanitized_url:
        return {
            "url": "",
            "is_empty": True,
            "is_malformed": False,
            "error_message": "No input provided. Please enter a URL to analyze.",
            "warnings": [],
            "warning_count": 0,
            "status": "EMPTY",
            "hostname": "",
            "scheme": "",
        }

    # 2. Parse URL safely
    parsed, parse_error = parse_url_safely(sanitized_url)
    if parse_error or parsed is None:
        return {
            "url": sanitized_url,
            "is_empty": False,
            "is_malformed": True,
            "error_message": parse_error or "Unable to parse URL structure.",
            "warnings": [],
            "warning_count": 0,
            "status": "MALFORMED",
            "hostname": "",
            "scheme": "",
        }

    # Extract hostname safely
    hostname = parsed.hostname or ""
    # In some edge cases (e.g. malformed ports or odd inputs), hostname might be None
    if not hostname and parsed.netloc:
        hostname = parsed.netloc.split(":")[0].split("@")[-1].strip()

    # Extract scheme
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    # 3. Execute all 6 warning checks
    warnings: List[Dict[str, str]] = []

    # Check 1: '@' symbol in URL
    warning_1 = check_at_symbol(sanitized_url, parsed)
    if warning_1:
        warnings.append(warning_1)

    # Check 2: URL length > 100 characters
    warning_2 = check_url_length(sanitized_url, MAX_URL_LENGTH_THRESHOLD)
    if warning_2:
        warnings.append(warning_2)

    # Check 3: IPv4 address hostname
    warning_3 = check_ipv4_hostname(hostname)
    if warning_3:
        warnings.append(warning_3)

    # Check 4: 5 or more dot-separated hostname segments
    warning_4 = check_subdomain_segments(hostname, SUBDOMAIN_SEGMENT_THRESHOLD)
    if warning_4:
        warnings.append(warning_4)

    # Check 5: Punycode hostname ('xn--')
    warning_5 = check_punycode_hostname(hostname)
    if warning_5:
        warnings.append(warning_5)

    # Check 6: Insecure HTTP instead of HTTPS
    warning_6 = check_http_scheme(scheme, sanitized_url)
    if warning_6:
        warnings.append(warning_6)

    # Determine final analysis status
    warning_count = len(warnings)
    status = "REVIEW_CAREFULLY" if warning_count > 0 else "NO_WARNINGS"

    return {
        "url": sanitized_url,
        "is_empty": False,
        "is_malformed": False,
        "error_message": None,
        "warnings": warnings,
        "warning_count": warning_count,
        "status": status,
        "hostname": hostname,
        "scheme": scheme,
    }


# =============================================================================
# PRESENTATION & REPORTING FORMATTER
# =============================================================================

def format_report(result: Dict[str, Any], use_colors: bool = True) -> str:
    """
    Renders a human-readable, educational report for terminal display.

    Args:
        result: The dictionary output generated by analyze_url().
        use_colors: Boolean flag to enable ANSI terminal styling.

    Returns:
        Formatted multi-line report string.
    """
    # Color helper lambdas
    bold = (lambda text: f"{ANSI_BOLD}{text}{ANSI_RESET}") if use_colors else (lambda text: text)
    red = (lambda text: f"{ANSI_RED}{text}{ANSI_RESET}") if use_colors else (lambda text: text)
    yellow = (lambda text: f"{ANSI_YELLOW}{text}{ANSI_RESET}") if use_colors else (lambda text: text)
    green = (lambda text: f"{ANSI_GREEN}{text}{ANSI_RESET}") if use_colors else (lambda text: text)
    cyan = (lambda text: f"{ANSI_CYAN}{text}{ANSI_RESET}") if use_colors else (lambda text: text)

    lines = []
    lines.append("-" * 72)
    lines.append(bold(cyan("  EWB Phishing URL Awareness Checker - Analysis Report")))
    lines.append("-" * 72)

    status = result.get("status")

    if status == "EMPTY":
        lines.append(yellow(" [!] Notice: Empty Input"))
        lines.append(f"     {result.get('error_message')}")
        lines.append("-" * 72)
        return "\n".join(lines)

    if status == "MALFORMED":
        lines.append(red(" [X] Error: Malformed URL Input"))
        lines.append(f"     URL     : {result.get('url')}")
        lines.append(f"     Details : {result.get('error_message')}")
        lines.append("-" * 72)
        return "\n".join(lines)

    # Display URL details
    lines.append(f" Analyzed URL : {result.get('url')}")
    lines.append(f" Extracted Host: {result.get('hostname') or '(None / Unspecified)'}")
    lines.append(f" URL Length    : {len(result.get('url', ''))} characters")
    lines.append("-" * 72)

    warnings = result.get("warnings", [])
    count = result.get("warning_count", 0)

    if status == "REVIEW_CAREFULLY":
        header_text = f" [!] REVIEW CAREFULLY: {count} Potential Phishing Indicator(s) Detected!"
        lines.append(bold(red(header_text)))
        lines.append("")

        for idx, item in enumerate(warnings, start=1):
            sev = item.get("severity", "MEDIUM")
            sev_tag = red(f"[{sev}]") if sev == "HIGH" else yellow(f"[{sev}]")
            item_name = item.get("name", "Warning")
            lines.append(f"  {bold(f'{idx}. {item_name}')} {sev_tag}")
            lines.append(f"     • Observation : {item.get('finding')}")
            lines.append(f"     • Risk Reason : {item.get('explanation')}")
            lines.append("")

        lines.append(bold(yellow(" Educational Guidance:")))
        lines.append("  • Do NOT enter passwords, credit cards, or personal data.")
        lines.append("  • Compare the actual hostname with the organization's verified domain.")
        lines.append("  • Navigate to trusted websites via bookmarks or official search engines.")
    else:
        # NO_WARNINGS status
        lines.append(bold(green(" [*] NO COMMON WARNINGS DETECTED")))
        lines.append("")
        lines.append(
            "  The tested URL did not exhibit any of the six surface-level patterns"
        )
        lines.append("  checked by this educational awareness tool.")
        lines.append("")
        lines.append(bold(yellow(" [!] IMPORTANT DEFENSIVE NOTICE:")))
        lines.append("  This check DOES NOT prove that the URL or website is safe!")
        lines.append("  Modern cybercriminals routinely utilize valid HTTPS certificates,")
        lines.append("  concise domain names, and legitimate cloud hosting services.")
        lines.append("  Always remain vigilant, verify the sender, and never trust unexpected links.")

    lines.append("-" * 72)
    return "\n".join(lines)


# =============================================================================
# INTERACTIVE CLI APPLICATION LOOP
# =============================================================================

def print_welcome_banner() -> None:
    """Displays the friendly intro banner with instructions and exit commands."""
    print("=" * 72)
    print("       EWB PHISHING URL AWARENESS CHECKER (Defensive Educational Tool)     ")
    print("=" * 72)
    print(" This tool examines URL text patterns for common phishing warning signs:")
    print("   1. '@' symbol userinfo / redirection bypass")
    print("   2. Long URLs (> 100 characters)")
    print("   3. Direct IPv4-address-style hostnames")
    print("   4. Deeply nested hostnames (5+ dot-separated segments)")
    print("   5. Punycode IDN homograph indicators ('xn--')")
    print("   6. Insecure HTTP instead of HTTPS")
    print()
    print(" SAFETY POLICY:")
    print("   • Operates 100% locally. Never visits or opens any website.")
    print("   • No network calls, no DNS queries, no data transmission.")
    print("   • Designed for cybersecurity awareness and education.")
    print()
    print(" Type 'q', 'quit', or 'exit' at the prompt to stop the program.")
    print("=" * 72)


def main() -> None:
    """Main interactive loop for checking multiple URLs without restarting."""
    print_welcome_banner()

    exit_commands = {"q", "quit", "exit"}

    while True:
        try:
            print()
            user_input = input("Enter a URL to check (or 'q' to quit) > ")
        except (KeyboardInterrupt, EOFError):
            print("\n\nSession terminated by user. Stay safe online!")
            break

        cleaned_input = user_input.strip()

        # Check for quit commands
        if cleaned_input.lower() in exit_commands:
            print("\nExiting EWB Phishing URL Awareness Checker. Stay vigilant!")
            break

        # Handle empty input with friendly notice
        if not cleaned_input:
            print("\n[!] Please enter a valid URL. Input cannot be blank.")
            continue

        # Run analysis and print report
        result = analyze_url(cleaned_input)
        report = format_report(result, use_colors=True)
        print(report)


if __name__ == "__main__":
    main()
