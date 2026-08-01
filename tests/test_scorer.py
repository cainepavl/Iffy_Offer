"""
Tests for scorer.py

Verifies that build_score() maps check results to the correct deltas,
totals, and verdict bands. All inputs are synthetic dicts — no network.
"""

import pytest
from scorer import build_score, ScorerOutput, CheckResult


# ---------------------------------------------------------------------------
# Helpers — pre-built "neutral" inputs so each test only overrides what it cares about
# ---------------------------------------------------------------------------

def _neutral_domain_info():
    return {"homoglyph_detected": False, "fuzzy_match": False,
            "edit_distance": 10, "normalized_domain": "amazon",
            "detail": "Domain looks fine."}

def _neutral_whois():
    return {"age_days": 800, "creation_date": "2023-01-01",
            "registrar": "Test Registrar", "detail": "Domain is 800 days old (~2.2 years) — established domain."}

def _neutral_mx():
    return {"found": True, "detail": "MX records found: mail.amazon.com"}

def _neutral_spf():
    return {"found": True, "record": "v=spf1 include:amazon.com ~all",
            "detail": "SPF record found."}

def _neutral_dmarc():
    return {"found": True, "record": "v=DMARC1; p=reject",
            "detail": "DMARC record found."}

def _build(**overrides):
    """Build a ScorerOutput with all-neutral inputs, then apply overrides."""
    kwargs = dict(
        domain="amazon.com",
        company_name="Amazon",
        free_provider=False,
        ats_platform=False,
        domain_info=_neutral_domain_info(),
        whois_info=_neutral_whois(),
        mx_info=_neutral_mx(),
        spf_info=_neutral_spf(),
        dmarc_info=_neutral_dmarc(),
        display_mismatch=None,
        reply_to_mismatch=None,
    )
    kwargs.update(overrides)
    return build_score(**kwargs)


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_scorer_output(self):
        assert isinstance(_build(), ScorerOutput)

    def test_results_is_list_of_check_results(self):
        output = _build()
        assert isinstance(output.results, list)
        assert all(isinstance(r, CheckResult) for r in output.results)

    def test_result_fields_present(self):
        output = _build()
        for r in output.results:
            assert hasattr(r, "name")
            assert hasattr(r, "status")
            assert hasattr(r, "detail")
            assert hasattr(r, "delta")


# ---------------------------------------------------------------------------
# Verdict bands
# ---------------------------------------------------------------------------

class TestVerdictBands:
    def test_zero_score_is_low_risk(self):
        output = _build()
        # Established domain gives +10, everything else neutral → score ≥ 0
        assert output.score >= 0
        assert output.verdict == "Looks Legit"
        assert output.color == "green"

    def test_free_provider_high_risk(self):
        # –40 alone pushes into Yikes! (≤ –30)
        output = _build(free_provider=True)
        assert output.score <= -30
        assert output.verdict == "Yikes!"
        assert output.color == "red"

    def test_medium_risk_band(self):
        # Young domain (–15) + no DMARC (–10) = –25 → MEDIUM RISK
        output = _build(
            whois_info={"age_days": 90, "creation_date": "2026-03-01",
                        "registrar": "Test", "detail": "90 days old — relatively new."},
            dmarc_info={"found": False, "record": None, "detail": "No DMARC record."},
        )
        assert -29 <= output.score <= -1
        assert output.verdict == "Iffy"
        assert output.color == "yellow"

    def test_ats_platform_positive_signal(self):
        output = _build(ats_platform=True)
        # +20 (ATS) + +10 (established domain) = +30 → Looks Legit
        assert output.score > 0
        assert output.verdict == "Looks Legit"


# ---------------------------------------------------------------------------
# Individual check deltas
# ---------------------------------------------------------------------------

class TestScoreDeltas:
    def test_free_provider_penalty(self):
        output = _build(free_provider=True)
        result = next(r for r in output.results if r.name == "Free Email Provider")
        assert result.delta == -40
        assert result.status == "fail"

    def test_free_provider_ok(self):
        output = _build(free_provider=False)
        result = next(r for r in output.results if r.name == "Free Email Provider")
        assert result.delta == 0
        assert result.status == "ok"

    def test_ats_platform_bonus(self):
        output = _build(ats_platform=True)
        result = next(r for r in output.results if r.name == "ATS / Recruiter Platform")
        assert result.delta == +20
        assert result.status == "ok"

    def test_homoglyph_penalty(self):
        domain_info = _neutral_domain_info()
        domain_info["homoglyph_detected"] = True
        domain_info["detail"] = "Homoglyph found."
        output = _build(domain_info=domain_info)
        result = next(r for r in output.results if r.name == "Homoglyph Substitution")
        assert result.delta == -30
        assert result.status == "fail"

    def test_fuzzy_match_penalty(self):
        domain_info = _neutral_domain_info()
        domain_info["fuzzy_match"] = True
        domain_info["detail"] = "Fuzzy match found."
        output = _build(domain_info=domain_info)
        result = next(r for r in output.results if r.name == "Typosquatting Detection")
        assert result.delta == -25
        assert result.status == "fail"

    def test_new_domain_penalty(self):
        whois = {"age_days": 10, "creation_date": "2026-05-27",
                 "registrar": "Test", "detail": "10 days old — VERY NEW."}
        output = _build(whois_info=whois)
        result = next(r for r in output.results if r.name == "Domain Age")
        assert result.delta == -30
        assert result.status == "fail"

    def test_young_domain_penalty(self):
        whois = {"age_days": 60, "creation_date": "2026-04-07",
                 "registrar": "Test", "detail": "60 days old — relatively new."}
        output = _build(whois_info=whois)
        result = next(r for r in output.results if r.name == "Domain Age")
        assert result.delta == -15
        assert result.status == "warning"

    def test_established_domain_bonus(self):
        output = _build()  # neutral whois has 800 days → +10
        result = next(r for r in output.results if r.name == "Domain Age")
        assert result.delta == +10
        assert result.status == "ok"

    def test_no_mx_penalty(self):
        output = _build(mx_info={"found": False, "detail": "No MX records."})
        result = next(r for r in output.results if r.name == "MX Records")
        assert result.delta == -20
        assert result.status == "fail"

    def test_no_spf_penalty(self):
        output = _build(spf_info={"found": False, "record": None, "detail": "No SPF."})
        result = next(r for r in output.results if r.name == "SPF Record")
        assert result.delta == -10
        assert result.status == "warning"

    def test_no_dmarc_penalty(self):
        output = _build(dmarc_info={"found": False, "record": None, "detail": "No DMARC."})
        result = next(r for r in output.results if r.name == "DMARC Record")
        assert result.delta == -10
        assert result.status == "warning"

    def test_reply_to_mismatch_penalty(self):
        mismatch = {"mismatch": True, "detail": "Reply-To domain differs from From domain."}
        output = _build(reply_to_mismatch=mismatch)
        result = next(r for r in output.results if r.name == "Reply-To Mismatch")
        assert result.delta == -20
        assert result.status == "fail"

    def test_display_name_spoofing_penalty(self):
        mismatch = {"mismatch": True, "detail": "Display name references Amazon but domain doesn't."}
        output = _build(display_mismatch=mismatch)
        result = next(r for r in output.results if r.name == "Display Name Spoofing")
        assert result.delta == -15
        assert result.status == "fail"

    def test_none_header_checks_skipped(self):
        output = _build(display_mismatch=None, reply_to_mismatch=None)
        names = [r.name for r in output.results]
        assert "Display Name Spoofing" not in names
        assert "Display Name" not in names
        assert "Reply-To Mismatch" not in names
        assert "Reply-To Header" not in names

    def test_whois_unknown_contributes_zero(self):
        whois = {"age_days": None, "creation_date": None,
                 "registrar": None, "detail": "WHOIS lookup failed."}
        output = _build(whois_info=whois)
        result = next(r for r in output.results if r.name == "Domain Age")
        assert result.delta == 0
        assert result.status == "unknown"


# ---------------------------------------------------------------------------
# Score arithmetic
# ---------------------------------------------------------------------------

class TestScoreArithmetic:
    def test_score_is_sum_of_deltas(self):
        output = _build()
        expected = sum(r.delta for r in output.results)
        assert output.score == expected

    def test_max_penalty_stack(self):
        # Pile on every penalty we can
        output = _build(
            free_provider=True,      # –40
            domain_info={**_neutral_domain_info(), "homoglyph_detected": True, "detail": "x"},
            whois_info={"age_days": 5, "creation_date": "2026-06-01",
                        "registrar": None, "detail": "5 days old."},
            mx_info={"found": False, "detail": "No MX."},
            spf_info={"found": False, "record": None, "detail": "No SPF."},
            dmarc_info={"found": False, "record": None, "detail": "No DMARC."},
            display_mismatch={"mismatch": True, "detail": "Spoofed."},
            reply_to_mismatch={"mismatch": True, "detail": "Hijacked."},
        )
        assert output.score < -30
        assert output.verdict == "Yikes!"


# ---------------------------------------------------------------------------
# Body-language checks (checks.content.analyze_email_body output)
# ---------------------------------------------------------------------------

def _neutral_body_info():
    ok = {"detected": False, "matches": [], "detail": "Nothing found."}
    return {
        "upfront_payment": dict(ok), "premature_pii": dict(ok),
        "offplatform_comms": dict(ok), "urgency_language": dict(ok),
        "instant_hire": dict(ok), "generic_greeting": dict(ok),
    }


class TestBodyInfoScoring:
    def test_none_body_info_adds_no_results(self):
        output = _build(body_info=None)
        names = [r.name for r in output.results]
        assert "Upfront Payment Request" not in names

    def test_neutral_body_info_contributes_zero(self):
        output = _build(body_info=_neutral_body_info())
        result = next(r for r in output.results if r.name == "Upfront Payment Request")
        assert result.delta == 0
        assert result.status == "ok"

    def test_upfront_payment_penalty(self):
        body_info = _neutral_body_info()
        body_info["upfront_payment"] = {"detected": True, "matches": ["gift card"], "detail": "Asks for a gift card."}
        output = _build(body_info=body_info)
        result = next(r for r in output.results if r.name == "Upfront Payment Request")
        assert result.delta == -35
        assert result.status == "fail"

    def test_generic_greeting_penalty(self):
        body_info = _neutral_body_info()
        body_info["generic_greeting"] = {"detected": True, "matches": ["dear applicant"], "detail": "Generic greeting."}
        output = _build(body_info=body_info)
        result = next(r for r in output.results if r.name == "Generic Greeting")
        assert result.delta == -5
        assert result.status == "warning"


# ---------------------------------------------------------------------------
# Attachment checks (checks.attachment.analyze_attachment output)
# ---------------------------------------------------------------------------

def _neutral_attachment_info():
    ok = {"detected": False, "matches": [], "detail": "Nothing found."}
    return {
        "error": None,
        "extension_flag": dict(ok), "signature_mismatch": dict(ok),
        "archive_contents": dict(ok), "container_flag": dict(ok),
        "pdf_action_flag": dict(ok),
        "macro_analysis": {"detected": False, "severity": "none", "matches": [], "detail": "No macros."},
    }


class TestAttachmentInfoScoring:
    def test_none_attachment_info_adds_no_results(self):
        output = _build(attachment_info=None)
        names = [r.name for r in output.results]
        assert "Attachment File Type" not in names

    def test_error_adds_single_unknown_result(self):
        output = _build(attachment_info={"error": "File is too large to analyze.", "extension_flag": None,
                                          "signature_mismatch": None, "macro_analysis": None,
                                          "pdf_action_flag": None, "archive_contents": None, "container_flag": None})
        result = next(r for r in output.results if r.name == "Attachment Analysis")
        assert result.status == "unknown"
        assert result.delta == 0
        names = [r.name for r in output.results]
        assert "Attachment File Type" not in names

    def test_dangerous_extension_penalty(self):
        attachment_info = _neutral_attachment_info()
        attachment_info["extension_flag"] = {"detected": True, "matches": [".exe"], "detail": "Dangerous extension."}
        output = _build(attachment_info=attachment_info)
        result = next(r for r in output.results if r.name == "Attachment File Type")
        assert result.delta == -35
        assert result.status == "fail"

    def test_macro_high_severity_penalty(self):
        attachment_info = _neutral_attachment_info()
        attachment_info["macro_analysis"] = {
            "detected": True, "severity": "high", "matches": ["AutoOpen"], "detail": "High-risk macros.",
        }
        output = _build(attachment_info=attachment_info)
        result = next(r for r in output.results if r.name == "Attachment Macros")
        assert result.delta == -40
        assert result.status == "fail"

    def test_macro_unknown_contributes_zero(self):
        attachment_info = _neutral_attachment_info()
        attachment_info["macro_analysis"] = {
            "detected": None, "severity": "unknown", "matches": [], "detail": "Could not analyze.",
        }
        output = _build(attachment_info=attachment_info)
        result = next(r for r in output.results if r.name == "Attachment Macros")
        assert result.delta == 0
        assert result.status == "unknown"
