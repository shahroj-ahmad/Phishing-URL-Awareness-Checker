#!/usr/bin/env python3
"""
=============================================================================
Project Name : EWB Phishing URL Awareness Checker
Module       : tests/test_phishing_checker.py
Description  : Automated unit tests using Python's built-in unittest framework.
Safety Rule  : Uses only safe, reserved example URLs (RFC 2606) and documentation
               IP addresses (RFC 5737). NEVER opens or visits any test URL.
=============================================================================
"""

import os
import sys
import unittest

# Ensure the parent directory is in sys.path so we can import phishing_checker
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from phishing_checker import (
    analyze_url,
    check_at_symbol,
    check_url_length,
    check_ipv4_hostname,
    check_subdomain_segments,
    check_punycode_hostname,
    check_http_scheme,
    parse_url_safely,
    format_report,
)


class TestPhishingUrlAwarenessChecker(unittest.TestCase):
    """Automated test suite verifying all warning checks and edge cases."""

    # -------------------------------------------------------------------------
    # 1. Normal HTTPS URL (Clean Baseline)
    # -------------------------------------------------------------------------
    def test_normal_https_url(self):
        """A standard legitimate HTTPS URL should yield zero warnings."""
        sample = "https://example.com"
        result = analyze_url(sample)

        self.assertFalse(result["is_empty"])
        self.assertFalse(result["is_malformed"])
        self.assertEqual(result["warning_count"], 0)
        self.assertEqual(result["status"], "NO_WARNINGS")
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["scheme"], "https")

    # -------------------------------------------------------------------------
    # 2. IP-Address-Style Hostname over HTTP
    # -------------------------------------------------------------------------
    def test_ipv4_hostname_over_http(self):
        """
        An IPv4 address over HTTP (e.g., http://192.0.2.10) should trigger both:
        - Check 3: Raw IPv4 Hostname
        - Check 6: Insecure HTTP Scheme
        """
        sample = "http://192.0.2.10"
        result = analyze_url(sample)

        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        self.assertGreaterEqual(result["warning_count"], 2)

        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_3_IPV4_HOST", check_ids)
        self.assertIn("CHECK_6_INSECURE_HTTP", check_ids)

    # -------------------------------------------------------------------------
    # 3. URL Containing an '@' Symbol
    # -------------------------------------------------------------------------
    def test_url_with_at_symbol(self):
        """
        A URL with an '@' symbol (e.g., https://mybank.com@example.invalid/login)
        must trigger Check 1.
        """
        sample = "https://mybank.com@example.invalid/login"
        result = analyze_url(sample)

        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_1_AT_SYMBOL", check_ids)

    # -------------------------------------------------------------------------
    # 4. Hostname with Five or More Dot-Separated Segments
    # -------------------------------------------------------------------------
    def test_hostname_five_or_more_segments(self):
        """
        A hostname with 5 or more segments (e.g. login.secure.verify.brand.example.com)
        must trigger Check 4.
        """
        sample = "https://login.secure.verify.brand.example.com"
        result = analyze_url(sample)

        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_4_EXCESSIVE_SEGMENTS", check_ids)

    def test_hostname_under_five_segments_not_flagged(self):
        """A hostname with fewer than 5 segments must NOT trigger Check 4."""
        sample = "https://sub.portal.example.com"  # 4 segments
        result = analyze_url(sample)

        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertNotIn("CHECK_4_EXCESSIVE_SEGMENTS", check_ids)

    # -------------------------------------------------------------------------
    # 5. Punycode-Style Hostname ('xn--')
    # -------------------------------------------------------------------------
    def test_punycode_hostname(self):
        """
        A hostname containing 'xn--' (e.g., https://xn--pple-43d.example.com)
        must trigger Check 5 (Punycode / Homograph Attack).
        """
        sample = "https://xn--pple-43d.example.com"
        result = analyze_url(sample)

        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_5_PUNYCODE", check_ids)

    # -------------------------------------------------------------------------
    # 6. URL Longer Than 100 Characters
    # -------------------------------------------------------------------------
    def test_url_exceeding_100_characters(self):
        """
        A URL exceeding 100 characters must trigger Check 2 (Excessive Length).
        """
        sample = (
            "https://example.com/account/login/verification/session/"
            "token=9876543210abcdef9876543210abcdef9876543210"
        )
        self.assertGreater(len(sample), 100)

        result = analyze_url(sample)
        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_2_LONG_URL", check_ids)

    def test_url_under_100_characters_not_flagged(self):
        """A short legitimate URL under 100 characters must NOT trigger Check 2."""
        sample = "https://example.com/about"
        self.assertLessEqual(len(sample), 100)

        result = analyze_url(sample)
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertNotIn("CHECK_2_LONG_URL", check_ids)

    # -------------------------------------------------------------------------
    # 7. Empty and Whitespace Input Handling
    # -------------------------------------------------------------------------
    def test_empty_string_input(self):
        """Empty input must be handled gracefully without raising an exception."""
        result = analyze_url("")
        self.assertTrue(result["is_empty"])
        self.assertEqual(result["status"], "EMPTY")
        self.assertEqual(result["warning_count"], 0)
        self.assertIsNotNone(result["error_message"])

    def test_whitespace_only_input(self):
        """Whitespace-only input must be stripped and handled gracefully."""
        result = analyze_url("     \t \n  ")
        self.assertTrue(result["is_empty"])
        self.assertEqual(result["status"], "EMPTY")

    def test_none_input(self):
        """None input must be handled gracefully without crashing."""
        result = analyze_url(None)
        self.assertTrue(result["is_empty"])
        self.assertEqual(result["status"], "EMPTY")

    # -------------------------------------------------------------------------
    # 8. Malformed URL Input
    # -------------------------------------------------------------------------
    def test_url_with_unusual_characters(self):
        """
        Test that URLs with unusual characters (e.g., spaces or brackets)
        are handled gracefully without crashing the application.
        """
        sample = "https://example.com/path with spaces/test?query=[val]"
        # Should parse without throwing an unhandled exception
        result = analyze_url(sample)
        self.assertIn(result["status"], ["NO_WARNINGS", "REVIEW_CAREFULLY"])

    # -------------------------------------------------------------------------
    # 9. Missing Scheme / Unspecified Protocol
    # -------------------------------------------------------------------------
    def test_url_without_scheme(self):
        """
        A URL entered without a scheme (e.g. 'example.com') should extract the
        hostname accurately and warn that no secure protocol was provided.
        """
        sample = "example.com"
        result = analyze_url(sample)
        self.assertEqual(result["hostname"], "example.com")
        check_ids = [w["check_id"] for w in result["warnings"]]
        self.assertIn("CHECK_6_MISSING_SCHEME", check_ids)

    # -------------------------------------------------------------------------
    # 10. Multi-Warning Combination Test
    # -------------------------------------------------------------------------
    def test_multiple_simultaneous_warnings(self):
        """
        A heavily engineered phishing URL exhibiting multiple warning signs:
        - HTTP (Check 6)
        - '@' symbol (Check 1)
        - > 100 chars (Check 2)
        - 5+ segments (Check 4)
        """
        sample = (
            "http://security-alert.paypal.com@login.verify.update.portal."
            "attacker-controlled-site.invalid/session/reset-credentials-step1-now"
        )
        result = analyze_url(sample)
        self.assertEqual(result["status"], "REVIEW_CAREFULLY")
        check_ids = [w["check_id"] for w in result["warnings"]]

        self.assertIn("CHECK_1_AT_SYMBOL", check_ids)
        self.assertIn("CHECK_2_LONG_URL", check_ids)
        self.assertIn("CHECK_4_EXCESSIVE_SEGMENTS", check_ids)
        self.assertIn("CHECK_6_INSECURE_HTTP", check_ids)
        self.assertGreaterEqual(result["warning_count"], 4)

    # -------------------------------------------------------------------------
    # 11. Report Formatting Verification
    # -------------------------------------------------------------------------
    def test_report_formatting_for_review_carefully(self):
        """Verify the report text contains the expected 'REVIEW CAREFULLY' string."""
        sample = "http://example.com"
        result = analyze_url(sample)
        report = format_report(result, use_colors=False)

        self.assertIn("REVIEW CAREFULLY", report)
        self.assertIn("Insecure Protocol", report)

    def test_report_formatting_for_no_warnings(self):
        """Verify the report text contains the mandatory disclaimer when no warnings exist."""
        sample = "https://example.com"
        result = analyze_url(sample)
        report = format_report(result, use_colors=False)

        self.assertIn("NO COMMON WARNINGS DETECTED", report)
        self.assertIn("This check DOES NOT prove that the URL or website is safe!", report)


if __name__ == "__main__":
    unittest.main()
