# Test Samples and Automated Test Documentation

This document records the curated test suite, safety rationale, and honest automated test execution results for the **EWB Phishing URL Awareness Checker**.

---

## 1. Safety and RFC Compliance Policy

All test URLs used in this test suite adhere strictly to defensive cybersecurity testing standards:
- **RFC 2606**: Uses reserved Special-Use Domain Names (`example.com`, `example.invalid`, `example.net`). These domains are permanently reserved by IANA and cannot be registered by malicious actors.
- **RFC 5737**: Uses reserved IPv4 Documentation Blocks (`192.0.2.0/24` - TEST-NET-1). These IP addresses are designated strictly for documentation and testing and are not routable on the global public Internet.
- **Defensive Principle**: The application and test suite **never make network connections, DNS queries, or HTTP requests**. All tests run purely via in-memory string parsing and lexical pattern evaluation.

---

## 2. Test Cases Specification Matrix

| ID | Test URL Sample | Targeted Check | Expected Status | Expected Warnings Detected |
|---|---|---|---|---|
| **TC-01** | `https://example.com` | Baseline Legitimate | `NO_WARNINGS` | 0 warnings (Valid HTTPS, clean domain) |
| **TC-02** | `http://192.0.2.10` | Check 3 & Check 6 | `REVIEW_CAREFULLY` | • Raw IPv4 Address Hostname<br>• Insecure Protocol (HTTP) |
| **TC-03** | `https://mybank.com@example.invalid/login` | Check 1 | `REVIEW_CAREFULLY` | • Presence of '@' Credential/Redirection Symbol |
| **TC-04** | `https://login.secure.verify.brand.example.com` | Check 4 | `REVIEW_CAREFULLY` | • Deeply Nested Hostname (6 dot segments >= 5) |
| **TC-05** | `https://sub.portal.example.com` | Segment Count Negative | `NO_WARNINGS` | 0 warnings (4 segments < threshold of 5) |
| **TC-06** | `https://xn--pple-43d.example.com` | Check 5 | `REVIEW_CAREFULLY` | • Punycode / IDN Homograph Indicator (`xn--`) |
| **TC-07** | `https://example.com/account/login/verification/session/token=9876543210abcdef9876543210abcdef9876543210` | Check 2 | `REVIEW_CAREFULLY` | • Excessive URL Length (101 characters > 100) |
| **TC-08** | `https://example.com/about` | Length Negative | `NO_WARNINGS` | 0 warnings (25 characters <= 100) |
| **TC-09** | `""` (Empty string) | Graceful Empty Input | `EMPTY` | Handled gracefully without crash |
| **TC-10** | `"   \t \n  "` (Whitespace) | Graceful Whitespace Input | `EMPTY` | Handled gracefully without crash |
| **TC-11** | `None` | Null Guard Handling | `EMPTY` | Handled gracefully without crash |
| **TC-12** | `https://example.com/path with spaces/test?query=[val]` | Malformed Input Guard | `NO_WARNINGS` | Handled safely by RFC parser without unhandled exception |
| **TC-13** | `example.com` | Missing Scheme Handling | `REVIEW_CAREFULLY` | • Missing Secure Protocol (Scheme Not Specified) |
| **TC-14** | `http://security-alert.paypal.com@login.verify.update.portal.attacker-controlled-site.invalid/session/reset-credentials-step1-now` | Multi-Vector Attack | `REVIEW_CAREFULLY` | • Presence of '@' symbol<br>• Excessive URL Length (> 100)<br>• Deeply Nested Hostname (>= 5 segments)<br>• Insecure HTTP Protocol |

---

## 3. Automated Test Execution Record

The automated test suite was executed locally on macOS using Python's built-in `unittest` runner.

### Execution Command:
```bash
python3 -m unittest discover -s tests -v
```

### Actual Terminal Output:
```text
test_empty_string_input (test_phishing_checker.TestPhishingUrlAwarenessChecker)
Empty input must be handled gracefully without raising an exception. ... ok
test_hostname_five_or_more_segments (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A hostname with 5 or more segments (e.g. login.secure.verify.brand.example.com) ... ok
test_hostname_under_five_segments_not_flagged (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A hostname with fewer than 5 segments must NOT trigger Check 4. ... ok
test_ipv4_hostname_over_http (test_phishing_checker.TestPhishingUrlAwarenessChecker)
An IPv4 address over HTTP (e.g., http://192.0.2.10) should trigger both: ... ok
test_multiple_simultaneous_warnings (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A heavily engineered phishing URL exhibiting multiple warning signs: ... ok
test_none_input (test_phishing_checker.TestPhishingUrlAwarenessChecker)
None input must be handled gracefully without crashing. ... ok
test_normal_https_url (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A standard legitimate HTTPS URL should yield zero warnings. ... ok
test_punycode_hostname (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A hostname containing 'xn--' (e.g., https://xn--pple-43d.example.com) ... ok
test_report_formatting_for_no_warnings (test_phishing_checker.TestPhishingUrlAwarenessChecker)
Verify the report text contains the mandatory disclaimer when no warnings exist. ... ok
test_report_formatting_for_review_carefully (test_phishing_checker.TestPhishingUrlAwarenessChecker)
Verify the report text contains the expected 'REVIEW CAREFULLY' string. ... ok
test_url_exceeding_100_characters (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A URL exceeding 100 characters must trigger Check 2 (Excessive Length). ... ok
test_url_under_100_characters_not_flagged (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A short legitimate URL under 100 characters must NOT trigger Check 2. ... ok
test_url_with_at_symbol (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A URL with an '@' symbol (e.g., https://mybank.com@example.invalid/login) ... ok
test_url_with_unusual_characters (test_phishing_checker.TestPhishingUrlAwarenessChecker)
Test that URLs with unusual characters (e.g., spaces or brackets) ... ok
test_url_without_scheme (test_phishing_checker.TestPhishingUrlAwarenessChecker)
A URL entered without a scheme (e.g. 'example.com') should extract the ... ok
test_whitespace_only_input (test_phishing_checker.TestPhishingUrlAwarenessChecker)
Whitespace-only input must be stripped and handled gracefully. ... ok

----------------------------------------------------------------------
Ran 16 tests in 0.002s

OK
```

### Result Summary:
- **Total Tests Run**: 16
- **Passed**: 16 (100%)
- **Failed**: 0
- **Errors**: 0
- **Duration**: 0.002 seconds
