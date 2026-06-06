"""
Tests for checks/header.py

Covers: parse_headers, check_display_name_mismatch, check_reply_to_mismatch.

No network calls — all functions operate on plain strings.
"""

import pytest
from checks.header import parse_headers, check_display_name_mismatch, check_reply_to_mismatch


# ---------------------------------------------------------------------------
# Helpers — sample header blocks
# ---------------------------------------------------------------------------

CLEAN_HEADERS = """\
From: Amazon HR <hr@amazon.com>
To: candidate@example.com
Subject: Job Opportunity
Date: Fri, 06 Jun 2026 10:00:00 +0000
"""

SPOOFED_DISPLAY_HEADERS = """\
From: Amazon HR <hr@totally-fake-domain.com>
To: candidate@example.com
Subject: Exciting Opportunity
Date: Fri, 06 Jun 2026 10:00:00 +0000
"""

REPLY_TO_MISMATCH_HEADERS = """\
From: hr@amazon.com
To: candidate@example.com
Reply-To: attacker@otherdomain.com
Subject: Follow Up
"""

REPLY_TO_MATCH_HEADERS = """\
From: hr@amazon.com
To: candidate@example.com
Reply-To: hr@amazon.com
Subject: Follow Up
"""

BARE_EMAIL_HEADERS = """\
From: hr@amazon.com
To: candidate@example.com
Subject: Test
"""


# ---------------------------------------------------------------------------
# parse_headers
# ---------------------------------------------------------------------------

class TestParseHeaders:
    def test_extracts_from_address(self):
        result = parse_headers(CLEAN_HEADERS)
        assert result["from_address"] == "hr@amazon.com"

    def test_extracts_from_display_name(self):
        result = parse_headers(CLEAN_HEADERS)
        assert result["from_display"] == "Amazon HR"

    def test_extracts_from_domain(self):
        result = parse_headers(CLEAN_HEADERS)
        assert result["from_domain"] == "amazon.com"

    def test_extracts_reply_to(self):
        result = parse_headers(REPLY_TO_MISMATCH_HEADERS)
        assert result["reply_to"] == "attacker@otherdomain.com"
        assert result["reply_to_domain"] == "otherdomain.com"

    def test_no_reply_to_is_none(self):
        result = parse_headers(CLEAN_HEADERS)
        assert result["reply_to"] is None
        assert result["reply_to_domain"] is None

    def test_bare_email_no_display_name(self):
        result = parse_headers(BARE_EMAIL_HEADERS)
        assert result["from_address"] == "hr@amazon.com"
        assert result["from_display"] is None

    def test_empty_input_returns_parse_error(self):
        result = parse_headers("")
        assert result["parse_error"] is True

    def test_whitespace_only_returns_parse_error(self):
        result = parse_headers("   \n\n  ")
        assert result["parse_error"] is True

    def test_parse_error_false_on_valid_input(self):
        result = parse_headers(CLEAN_HEADERS)
        assert result["parse_error"] is False

    def test_result_has_all_keys(self):
        result = parse_headers(CLEAN_HEADERS)
        for key in ("from_display", "from_address", "from_domain",
                    "reply_to", "reply_to_domain", "subject", "date",
                    "received_count", "parse_error"):
            assert key in result


# ---------------------------------------------------------------------------
# check_display_name_mismatch
# ---------------------------------------------------------------------------

class TestCheckDisplayNameMismatch:
    def test_detects_spoofed_display_name(self):
        parsed = parse_headers(SPOOFED_DISPLAY_HEADERS)
        result = check_display_name_mismatch(parsed, "Amazon")
        assert result["mismatch"] is True
        assert "amazon" in result["detail"].lower()

    def test_no_mismatch_when_domain_matches(self):
        parsed = parse_headers(CLEAN_HEADERS)
        result = check_display_name_mismatch(parsed, "Amazon")
        assert result["mismatch"] is False

    def test_no_mismatch_when_display_unrelated(self):
        # Display name mentions neither company nor domain
        headers = "From: Friendly Recruiter <hr@completelydifferent.com>\n"
        parsed = parse_headers(headers)
        result = check_display_name_mismatch(parsed, "Amazon")
        assert result["mismatch"] is False

    def test_parse_error_returns_no_mismatch(self):
        parsed = parse_headers("")
        result = check_display_name_mismatch(parsed, "Amazon")
        assert result["mismatch"] is False

    def test_result_has_required_keys(self):
        parsed = parse_headers(CLEAN_HEADERS)
        result = check_display_name_mismatch(parsed, "Amazon")
        assert "mismatch" in result
        assert "detail" in result


# ---------------------------------------------------------------------------
# check_reply_to_mismatch
# ---------------------------------------------------------------------------

class TestCheckReplyToMismatch:
    def test_detects_reply_to_mismatch(self):
        parsed = parse_headers(REPLY_TO_MISMATCH_HEADERS)
        result = check_reply_to_mismatch(parsed)
        assert result["mismatch"] is True
        assert "otherdomain.com" in result["detail"]

    def test_no_mismatch_when_domains_match(self):
        parsed = parse_headers(REPLY_TO_MATCH_HEADERS)
        result = check_reply_to_mismatch(parsed)
        assert result["mismatch"] is False

    def test_no_reply_to_is_not_a_mismatch(self):
        parsed = parse_headers(CLEAN_HEADERS)
        result = check_reply_to_mismatch(parsed)
        assert result["mismatch"] is False

    def test_parse_error_returns_no_mismatch(self):
        parsed = parse_headers("")
        result = check_reply_to_mismatch(parsed)
        assert result["mismatch"] is False

    def test_result_has_required_keys(self):
        parsed = parse_headers(CLEAN_HEADERS)
        result = check_reply_to_mismatch(parsed)
        assert "mismatch" in result
        assert "detail" in result
