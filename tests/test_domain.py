"""
Tests for checks/domain.py

Covers: extract_domain, is_free_provider, is_ats_platform,
        normalize_homoglyphs, check_domain_vs_company.

No network calls — all functions are pure Python or read local data files.
"""

import pytest
from checks.domain import (
    extract_domain,
    is_free_provider,
    is_ats_platform,
    normalize_homoglyphs,
    check_domain_vs_company,
)


# ---------------------------------------------------------------------------
# extract_domain
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_bare_email(self):
        assert extract_domain("hr@amazon.com") == "amazon.com"

    def test_angle_bracket_format(self):
        assert extract_domain("Amazon HR <hr@amazon.com>") == "amazon.com"

    def test_uppercase_normalized(self):
        assert extract_domain("HR@AMAZON.COM") == "amazon.com"

    def test_subdomain(self):
        assert extract_domain("noreply@mail.greenhouse.io") == "mail.greenhouse.io"

    def test_quoted_display_name(self):
        assert extract_domain('"Acme Jobs" <jobs@acme.com>') == "acme.com"

    def test_no_at_sign_returns_none(self):
        assert extract_domain("notanemail") is None

    def test_empty_string_returns_none(self):
        assert extract_domain("") is None

    def test_only_at_sign_returns_none(self):
        assert extract_domain("@") is None

    def test_whitespace_stripped(self):
        assert extract_domain("  hr@amazon.com  ") == "amazon.com"


# ---------------------------------------------------------------------------
# is_free_provider
# ---------------------------------------------------------------------------

class TestIsFreeProvider:
    def test_gmail_is_free(self):
        assert is_free_provider("gmail.com") is True

    def test_yahoo_is_free(self):
        assert is_free_provider("yahoo.com") is True

    def test_hotmail_is_free(self):
        assert is_free_provider("hotmail.com") is True

    def test_corporate_domain_not_free(self):
        assert is_free_provider("amazon.com") is False

    def test_unknown_domain_not_free(self):
        assert is_free_provider("totallymadefupdomain99.net") is False

    def test_case_insensitive(self):
        assert is_free_provider("Gmail.COM") is True


# ---------------------------------------------------------------------------
# is_ats_platform
# ---------------------------------------------------------------------------

class TestIsAtsPlatform:
    def test_greenhouse_exact(self):
        assert is_ats_platform("greenhouse.io") is True

    def test_greenhouse_subdomain(self):
        assert is_ats_platform("mail.greenhouse.io") is True

    def test_workday_exact(self):
        assert is_ats_platform("myworkday.com") is True

    def test_corporate_domain_not_ats(self):
        assert is_ats_platform("amazon.com") is False

    def test_free_provider_not_ats(self):
        assert is_ats_platform("gmail.com") is False

    def test_case_insensitive(self):
        assert is_ats_platform("Greenhouse.IO") is True


# ---------------------------------------------------------------------------
# normalize_homoglyphs
# ---------------------------------------------------------------------------

class TestNormalizeHomoglyphs:
    def test_zero_to_o(self):
        assert normalize_homoglyphs("amaz0n") == "amazon"

    def test_rn_to_m(self):
        assert normalize_homoglyphs("arnazon") == "amazon"

    def test_vv_to_w(self):
        assert normalize_homoglyphs("vvikipedia") == "wikipedia"

    def test_multiple_substitutions(self):
        # 'rn' → 'm', then '0' → 'o'
        result = normalize_homoglyphs("arnaz0n")
        assert result == "amazon"

    def test_clean_text_unchanged(self):
        assert normalize_homoglyphs("amazon") == "amazon"

    def test_uppercase_lowercased(self):
        assert normalize_homoglyphs("AMAZ0N") == "amazon"

    def test_three_to_e(self):
        # '3' substitutes for 'e' — classic phishing trick
        assert normalize_homoglyphs("3bay") == "ebay"


# ---------------------------------------------------------------------------
# check_domain_vs_company
# ---------------------------------------------------------------------------

class TestCheckDomainVsCompany:
    def test_homoglyph_detected(self):
        result = check_domain_vs_company("amaz0n-careers.net", "Amazon")
        assert result["homoglyph_detected"] is True
        assert "homoglyph" in result["detail"].lower()

    def test_fuzzy_typosquatting(self):
        # "amzon" is 1 edit away from "amazon"
        result = check_domain_vs_company("amzon-jobs.com", "Amazon")
        assert result["fuzzy_match"] is True
        assert result["edit_distance"] <= 3

    def test_clean_domain_no_flags(self):
        result = check_domain_vs_company("amazon.com", "Amazon")
        assert result["homoglyph_detected"] is False
        assert result["fuzzy_match"] is False

    def test_unrelated_domain_no_flags(self):
        result = check_domain_vs_company("totallyunrelated.com", "Amazon")
        assert result["homoglyph_detected"] is False
        assert result["fuzzy_match"] is False

    def test_result_has_required_keys(self):
        result = check_domain_vs_company("amazon.com", "Amazon")
        for key in ("homoglyph_detected", "fuzzy_match", "edit_distance",
                    "normalized_domain", "detail"):
            assert key in result

    def test_detail_is_string(self):
        result = check_domain_vs_company("amaz0n.com", "Amazon")
        assert isinstance(result["detail"], str)
        assert len(result["detail"]) > 0
