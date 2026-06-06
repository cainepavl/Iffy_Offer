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
        assert output.verdict == "LOW RISK"
        assert output.color == "green"

    def test_free_provider_high_risk(self):
        # –40 alone pushes into HIGH RISK (≤ –30)
        output = _build(free_provider=True)
        assert output.score <= -30
        assert output.verdict == "HIGH RISK"
        assert output.color == "red"

    def test_medium_risk_band(self):
        # Young domain (–15) + no DMARC (–10) = –25 → MEDIUM RISK
        output = _build(
            whois_info={"age_days": 90, "creation_date": "2026-03-01",
                        "registrar": "Test", "detail": "90 days old — relatively new."},
            dmarc_info={"found": False, "record": None, "detail": "No DMARC record."},
        )
        assert -29 <= output.score <= -1
        assert output.verdict == "MEDIUM RISK"
        assert output.color == "yellow"

    def test_ats_platform_positive_signal(self):
        output = _build(ats_platform=True)
        # +20 (ATS) + +10 (established domain) = +30 → LOW RISK
        assert output.score > 0
        assert output.verdict == "LOW RISK"


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
        assert output.verdict == "HIGH RISK"
