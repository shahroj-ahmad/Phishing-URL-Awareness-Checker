# EWB Phishing URL Awareness Checker

> **A Defensive Cybersecurity Educational Tool for Lexical URL Analysis**  
> Built with 100% Python Standard Library. Zero external dependencies. Zero network calls.

---

## 1. Project Overview

The **EWB Phishing URL Awareness Checker** is a beginner-friendly cybersecurity application designed to evaluate suspicious URL text and detect common phishing and spoofing indicators. 

Operating entirely offline, the tool parses and evaluates the visible anatomical structure of any given URL string against six classic threat vectors. It helps students, developers, and everyday users understand the psychological and technical tricks cybercriminals employ to disguise malicious links—without ever putting the user at risk of visiting a harmful destination.

---

## 2. Problem Statement

Phishing remains the primary initial access vector in modern cyberattacks (accounting for over 80% of reported security incidents globally). Cybercriminals routinely use subtle lexical manipulation—such as embedded credentials (`@`), confusing subdomain depths, lookalike Unicode characters (Punycode), raw IP addresses, and obfuscated URLs—to deceive users into surrendering credentials or downloading malware.

Most non-technical users cannot identify these structural anomalies with the naked eye. Furthermore, existing online scanners require uploading URLs to remote third parties, making network requests that can alert attackers or inadvertently trigger web exploitation scripts. There is a strong need for an offline, lightweight, and purely educational tool that safely breaks down URL mechanics for security awareness.

---

## 3. Objectives

- **Defensive Education**: Teach users how to recognize deceptive URL structures and visual spoofing techniques.
- **Safety by Design**: Guarantee 100% local operation without sending HTTP requests, resolving DNS queries, or visiting destinations.
- **Simplicity & Accessibility**: Build an application using only Python's standard library, requiring no API keys, package installations, or complex setup.
- **Comprehensive Lexical Inspection**: Implement six core heuristic checks to highlight surface-level phishing patterns.
- **Actionable Feedback**: Present plain-language risk explanations and defensive recommendations for each detected warning.

---

## 4. Key Features

The application evaluates URLs against six core cybersecurity warning checks:

1. **Userinfo / Redirection Symbol Detection (`@`)**:
   - Detects the `@` character in the URL string or userinfo field.
   - *Risk*: Attackers place trusted names before the `@` (e.g., `https://trustedbank.com@evil-site.com`), tricking victims while browsers actually route to the domain after the `@`.

2. **Excessive URL Length Flag (> 100 characters)**:
   - Evaluates total string length and flags inputs exceeding 100 characters.
   - *Risk*: Length padding pushes malicious domain segments off-screen on mobile devices and narrow address bars.

3. **Raw IPv4 Address Hostname Detection**:
   - Uses regex validation to identify numeric IPv4 addresses (e.g., `192.0.2.10`).
   - *Risk*: Legitimate public services almost universally use domain names. Attackers use direct IPs to evade domain-based reputation filters and avoid domain registration verification.

4. **Deeply Nested Subdomain Segment Analysis (5+ segments)**:
   - Counts dot-separated segments in the hostname.
   - *Risk*: Threat actors construct deep subdomain hierarchies (e.g., `login.secure.bank.verify.example.com`) to visually clone legitimate URLs.

5. **Punycode / IDN Homograph Indicator Detection (`xn--`)**:
   - Detects Internationalized Domain Name (IDN) Punycode encoding prefixes.
   - *Risk*: Attackers substitute Latin letters with visually identical Cyrillic, Greek, or Unicode characters (homograph attack) to spoof trusted domains.

6. **Insecure Protocol Verification (HTTP instead of HTTPS)**:
   - Flags URLs using unencrypted `http://` or lacking a specified secure protocol.
   - *Risk*: Unencrypted HTTP lacks transport security and identity verification, leaving communications vulnerable to interception and Man-in-the-Middle (MitM) attacks.

### Additional Features:
- **Interactive CLI Loop**: Continuous loop allowing multiple URL checks without restarting.
- **Clean Exit Control**: Exit gracefully at any time by typing `q`, `quit`, or `exit`.
- **Defensive Disclaimers**: Prominently warns users that the absence of surface warnings does **not** prove a URL is safe.
- **Graceful Error Handling**: Strips unnecessary whitespace, guards against empty strings, and catches malformed URLs without crashing.

---

## 5. Technology Stack

- **Programming Language**: Python 3.10+ (backwards-compatible with Python 3.9+)
- **Built-in Modules**:
  - `re` (Regular expression engine for IPv4 pattern validation)
  - `urllib.parse` (RFC 3986 URL parsing and component decomposition)
  - `unittest` (Standard unit testing framework)
  - `typing` (Type annotations for clean code architecture)
  - `sys`, `os` (Cross-platform runtime path management)
- **Dependencies**: **None** (Zero third-party libraries, no `pip install` required)
- **Environment**: macOS, Linux, and Windows compatible; optimized for VS Code and macOS Terminal.

---

## 6. Project Folder Structure

```text
phishing-url-awareness/
├── .gitignore                      # Git exclusion rules for bytecode & OS metadata
├── README.md                       # Comprehensive project documentation
├── requirements.txt                # Dependency specification (standard library only)
├── phishing_checker.py             # Main application and interactive CLI engine
├── tests/
│   ├── test_phishing_checker.py    # Automated unit tests using Python unittest
│   └── test_samples.md             # Curated test matrix & honest test execution logs
└── screenshots/
    ├── README.md                   # Exact macOS capture instructions & file info
    ├── sample_run.png              # Visual proof of interactive analysis
    └── test_results.png            # Visual proof of passing automated unit tests
```

---

## 7. Installation and Setup Instructions for macOS

Since the application uses standard Python modules, setup on macOS takes less than a minute.

### Step 1: Open Terminal
Open the **Terminal** app from Spotlight (`Cmd + Space`, type `Terminal`) or launch the integrated terminal in **VS Code** (`Ctrl + \``).

### Step 2: Verify Python Installation
Verify that Python 3 is installed:
```bash
python3 --version
```
*(macOS comes with Python 3 pre-installed via Xcode Command Line Tools).*

### Step 3: Navigate to the Project Directory
```bash
cd "/Users/apple/Desktop/ml program/cyber security project/mini project/phishing-url-awareness"
```

### Step 4: Verify Project Files
```bash
ls -la
```

---

## 8. How to Run the Program

Start the interactive tool:
```bash
python3 phishing_checker.py
```

### Sample Workflow:
1. When prompted (`Enter a URL to check (or 'q' to quit) >`), paste or type any URL.
2. Review the structured analysis report, severity ratings, and defensive tips.
3. Test additional URLs as desired.
4. Type `q`, `quit`, or `exit` to exit cleanly.

---

## 9. How to Run Automated Tests

Run the built-in test suite using the `unittest` discovery runner:

```bash
python3 -m unittest discover -s tests -v
```

Or run the specific test script directly:
```bash
python3 tests/test_phishing_checker.py
```

All 16 tests will execute in milliseconds without making any network requests.

---

## 10. Example Terminal Output

### Interactive Execution Session:
```text
========================================================================
       EWB PHISHING URL AWARENESS CHECKER (Defensive Educational Tool)     
========================================================================
 This tool examines URL text patterns for common phishing warning signs:
   1. '@' symbol userinfo / redirection bypass
   2. Long URLs (> 100 characters)
   3. Direct IPv4-address-style hostnames
   4. Deeply nested hostnames (5+ dot-separated segments)
   5. Punycode IDN homograph indicators ('xn--')
   6. Insecure HTTP instead of HTTPS

 SAFETY POLICY:
   • Operates 100% locally. Never visits or opens any website.
   • No network calls, no DNS queries, no data transmission.
   • Designed for cybersecurity awareness and education.

 Type 'q', 'quit', or 'exit' at the prompt to stop the program.
========================================================================

Enter a URL to check (or 'q' to quit) > http://192.0.2.10
------------------------------------------------------------------------
  EWB Phishing URL Awareness Checker - Analysis Report
------------------------------------------------------------------------
 Analyzed URL : http://192.0.2.10
 Extracted Host: 192.0.2.10
 URL Length    : 17 characters
------------------------------------------------------------------------
 [!] REVIEW CAREFULLY: 2 Potential Phishing Indicator(s) Detected!

  1. Raw IPv4 Address Hostname [HIGH]
     • Observation : Hostname '192.0.2.10' is a direct numeric IPv4 address.
     • Risk Reason : Legitimate institutions and organizations use registered domain names (e.g., 'bank.com') rather than direct numeric IP addresses. Direct IPs are frequently associated with rogue servers or evasion techniques.

  2. Insecure Protocol (HTTP instead of HTTPS) [HIGH]
     • Observation : The URL uses unencrypted 'http://' rather than encrypted 'https://'.
     • Risk Reason : HTTP does not provide encryption or server identity verification. Any sensitive data entered on HTTP websites can be monitored, captured, or modified by attackers on the same network.

 Educational Guidance:
  • Do NOT enter passwords, credit cards, or personal data.
  • Compare the actual hostname with the organization's verified domain.
  • Navigate to trusted websites via bookmarks or official search engines.
------------------------------------------------------------------------

Enter a URL to check (or 'q' to quit) > https://example.com
------------------------------------------------------------------------
  EWB Phishing URL Awareness Checker - Analysis Report
------------------------------------------------------------------------
 Analyzed URL : https://example.com
 Extracted Host: example.com
 URL Length    : 19 characters
------------------------------------------------------------------------
 [*] NO COMMON WARNINGS DETECTED

  The tested URL did not exhibit any of the six surface-level patterns
  checked by this educational awareness tool.

 [!] IMPORTANT DEFENSIVE NOTICE:
  This check DOES NOT prove that the URL or website is safe!
  Modern cybercriminals routinely utilize valid HTTPS certificates,
  concise domain names, and legitimate cloud hosting services.
  Always remain vigilant, verify the sender, and never trust unexpected links.
------------------------------------------------------------------------

Enter a URL to check (or 'q' to quit) > q

Exiting EWB Phishing URL Awareness Checker. Stay vigilant!
```

---

## 11. Test Cases and Honest Results

| Test Category | Input URL | Target Check | Result | Status |
|---|---|---|---|---|
| Clean Baseline | `https://example.com` | Baseline check | 0 warnings | PASS |
| Direct IP over HTTP | `http://192.0.2.10` | Checks 3 & 6 | Flagged (IPv4 + HTTP) | PASS |
| Redirection Symbol | `https://mybank.com@example.invalid/login` | Check 1 | Flagged (`@` symbol) | PASS |
| Deeply Nested Subdomain | `https://login.secure.verify.brand.example.com` | Check 4 | Flagged (6 segments >= 5) | PASS |
| Subdomain Threshold | `https://sub.portal.example.com` | Check 4 negative | 0 warnings (4 segments < 5) | PASS |
| Punycode Homograph | `https://xn--pple-43d.example.com` | Check 5 | Flagged (`xn--` prefix) | PASS |
| Long URL (> 100 chars) | `https://example.com/account/login/verification/session/token=9876543210abcdef9876543210abcdef9876543210` | Check 2 | Flagged (101 chars > 100) | PASS |
| Short URL (< 100 chars) | `https://example.com/about` | Check 2 negative | 0 warnings (25 chars) | PASS |
| Empty Input | `""` | Input validation | Handled gracefully | PASS |
| Whitespace Input | `"   \t  "` | Whitespace stripping | Handled gracefully | PASS |
| Missing Protocol Scheme | `example.com` | Scheme inference | Flagged missing HTTPS | PASS |
| Malformed Path Guard | `https://example.com/path with spaces/test?query=[val]` | Exception handling | Safely processed | PASS |
| Multi-Vector Link | `http://security-alert.paypal.com@login.verify.update.portal.attacker-controlled-site.invalid/session/reset-credentials-step1-now` | Multi-check | 4 warnings detected | PASS |

**Test Summary**: **16 of 16 tests passing (100% success rate)** in `0.002s`.

---

## 12. Instructions for Screenshots

Visual verification artifacts are located in the `screenshots/` directory:

| Screenshot | Path | Description |
|---|---|---|
| Sample Run | `screenshots/sample_run.png` | Terminal view of interactive URL checks with warnings |
| Test Results | `screenshots/test_results.png` | Terminal view of the 16 unit tests passing (`OK`) |

![Sample Run](screenshots/sample_run.png)
*Figure 1: Interactive execution showing detected phishing warnings and educational advice.*

![Test Results](screenshots/test_results.png)
*Figure 2: Automated test execution showing all 16 unit tests passing.*

### Exact macOS Instructions to Capture and Save:
1. **To capture `sample_run.png`**:
   - Run `python3 phishing_checker.py` and analyze 2–3 sample URLs.
   - Press `Cmd + Shift + 4`, then hit `Space` (camera icon appears).
   - Click the Terminal window.
   - Rename the saved desktop image and place it into `screenshots/sample_run.png`:
     ```bash
     mv ~/Desktop/Screenshot*.png screenshots/sample_run.png
     ```
2. **To capture `test_results.png`**:
   - Run `python3 -m unittest discover -s tests -v`.
   - Press `Cmd + Shift + 4`, then hit `Space`, and click the Terminal window.
   - Rename and move the file:
     ```bash
     mv ~/Desktop/Screenshot*.png screenshots/test_results.png
     ```

---

## 13. Improvements Implemented

Beyond the minimum project requirements, three major improvements were engineered:

1. **Intelligent Scheme Inference & Unspecified Protocol Warning**:
   - Standard `urllib.parse.urlparse` fails to extract hostnames when a user inputs a URL without a leading scheme (e.g., `example.com` or `192.0.2.10/login`). The application detects missing schemes, extracts the destination hostname safely, and issues a dedicated warning regarding the absence of an explicit `https://` secure transport protocol.
2. **Multi-Tiered Severity Classification & Educational Guidance**:
   - Every detected indicator is tagged with a risk rating (`HIGH` or `MEDIUM`) along with a dedicated educational explanation ("Observation", "Risk Reason", and "Educational Guidance") advising users on defensive actions (e.g., checking official domain registries, avoiding credential entry, utilizing bookmarks).
3. **Adaptive ANSI Terminal Formatting with Fallback**:
   - Terminal output includes clean ANSI color styling (Red for high severity, Yellow for medium, Green for no warnings, Cyan for headers) while supporting plain-text export for headless scripts and test logs without cluttering logs with raw escape codes.

---

## 14. Limitations

Users and reviewers must understand the inherent technical boundaries of this tool:
- **Lexical Analysis Only**: This tool analyzes URL text structure only. It cannot detect malware hosted on compromised legitimate websites, zero-day phishing kits hosted on short HTTPS domains, or phishing links distributed via QR codes.
- **No Reputation or Threat Intelligence Queries**: To maintain 100% offline privacy and safety, the tool does not query Google Safe Browsing, VirusTotal, or WHOIS databases.
- **No Destination Probing**: It does not download HTML, inspect DOM structures, or analyze SSL/TLS certificate chains.
- **Crucial Rule**: **The absence of warnings DOES NOT prove a URL is safe.** Modern phishing websites frequently use valid SSL certificates (`https://`), short brand names, and normal subdomain depths.

---

## 15. Safety and Ethical-Use Statement

- **Strictly Educational**: This tool is designed solely for classroom study, personal cybersecurity awareness, and security training.
- **No Network Probing**: The code contains no networking modules (`socket`, `requests`, `urllib.request`). It cannot scan servers, perform port scans, or contact third-party infrastructure.
- **No Credential Interception**: It does not capture, store, or transmit credentials or user data.
- **Defensive Ethics**: Use this software defensively to understand social engineering techniques and promote digital literacy.

---

## 16. Author Information

- **Student Name**: `[Your Name Here]`
- **Course**: `[Your Course / Degree Name]`
- **Batch / Semester**: `[Your Batch / Semester]`
- **Institution**: `[Your College / University Name]`
- **GitHub Username**: `[Your GitHub Username]`
- **Repository Name**: `phishing-url-awareness`

---

## 17. GitHub Publishing Commands

To publish this project to your public GitHub repository:

```bash
# 1. Navigate to the project directory
cd "/Users/apple/Desktop/ml program/cyber security project/mini project/phishing-url-awareness"

# 2. Initialize a Git repository with main branch
git init -b main

# 3. Stage all files
git add .

# 4. Commit files
git commit -m "feat: complete EWB Phishing URL Awareness Checker project"

# 5. Link to your public GitHub repository (replace with your actual GitHub username)
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/phishing-url-awareness.git

# 6. Push to GitHub main branch
git push -u origin main
```
