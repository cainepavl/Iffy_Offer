"""
Tests for checks/content.py

Covers all six email-body heuristics plus the analyze_email_body() aggregator.
No network calls — all functions operate on plain strings.
"""

import pytest
from checks.content import (
    check_upfront_payment_request,
    check_premature_pii_request,
    check_offplatform_comms,
    check_urgency_language,
    check_instant_hire,
    check_generic_greeting,
    analyze_email_body,
)


BENIGN_BODY = """\
Hi Jordan,

Thanks again for speaking with our engineering team last week. We'd like to
move forward with a formal offer for the Backend Engineer role. Our HR team
will follow up through our applicant portal with next steps and paperwork.

Best,
Amazon Recruiting
"""


# ---------------------------------------------------------------------------
# check_upfront_payment_request
# ---------------------------------------------------------------------------

class TestCheckUpfrontPaymentRequest:
    def test_detects_gift_card_request(self):
        result = check_upfront_payment_request("Please send a $200 gift card to cover your training fee.")
        assert result["detected"] is True
        assert "gift card" in result["matches"]

    def test_detects_wire_transfer(self):
        result = check_upfront_payment_request("We'll need a wire transfer to process your onboarding.")
        assert result["detected"] is True

    def test_benign_body_not_flagged(self):
        result = check_upfront_payment_request(BENIGN_BODY)
        assert result["detected"] is False
        assert result["matches"] == []

    def test_result_has_required_keys(self):
        result = check_upfront_payment_request(BENIGN_BODY)
        assert "detected" in result
        assert "matches" in result
        assert "detail" in result


# ---------------------------------------------------------------------------
# check_premature_pii_request
# ---------------------------------------------------------------------------

class TestCheckPrematurePiiRequest:
    def test_detects_ssn_request(self):
        result = check_premature_pii_request("Please reply with your social security number to proceed.")
        assert result["detected"] is True

    def test_word_boundary_avoids_false_positive(self):
        # "ssn" should not fire on unrelated text that happens to contain the substring
        result = check_premature_pii_request("This assignment is due tomorrow.")
        assert result["detected"] is False

    def test_benign_body_not_flagged(self):
        result = check_premature_pii_request(BENIGN_BODY)
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_offplatform_comms
# ---------------------------------------------------------------------------

class TestCheckOffplatformComms:
    def test_detects_whatsapp_push(self):
        result = check_offplatform_comms("Message me on WhatsApp to continue this conversation.")
        assert result["detected"] is True

    def test_benign_body_not_flagged(self):
        result = check_offplatform_comms(BENIGN_BODY)
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_urgency_language
# ---------------------------------------------------------------------------

class TestCheckUrgencyLanguage:
    def test_detects_urgency_phrase(self):
        result = check_urgency_language("You must act now, this offer expires today.")
        assert result["detected"] is True

    def test_benign_body_not_flagged(self):
        result = check_urgency_language(BENIGN_BODY)
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_instant_hire
# ---------------------------------------------------------------------------

class TestCheckInstantHire:
    def test_detects_instant_hire_claim(self):
        result = check_instant_hire("Congratulations, you are hired! No interview necessary.")
        assert result["detected"] is True

    def test_benign_body_not_flagged(self):
        result = check_instant_hire(BENIGN_BODY)
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# check_generic_greeting
# ---------------------------------------------------------------------------

class TestCheckGenericGreeting:
    def test_detects_dear_applicant(self):
        result = check_generic_greeting("Dear Applicant, we are pleased to inform you...")
        assert result["detected"] is True

    def test_detects_to_whom_it_may_concern(self):
        result = check_generic_greeting("To Whom It May Concern, please see the attached offer.")
        assert result["detected"] is True

    def test_personalized_greeting_not_flagged(self):
        result = check_generic_greeting(BENIGN_BODY)
        assert result["detected"] is False


# ---------------------------------------------------------------------------
# analyze_email_body
# ---------------------------------------------------------------------------

class TestAnalyzeEmailBody:
    def test_returns_all_sub_checks(self):
        result = analyze_email_body(BENIGN_BODY)
        for key in (
            "upfront_payment", "premature_pii", "offplatform_comms",
            "urgency_language", "instant_hire", "generic_greeting",
        ):
            assert key in result

    def test_benign_body_flags_nothing(self):
        result = analyze_email_body(BENIGN_BODY)
        assert all(not sub["detected"] for sub in result.values())

    def test_scam_body_flags_multiple_signals(self):
        scam_body = (
            "Dear Applicant, congratulations, you are hired! No interview necessary. "
            "Act now — this offer expires today. Please send a $150 processing fee "
            "via gift card and text me on WhatsApp to confirm."
        )
        result = analyze_email_body(scam_body)
        assert result["upfront_payment"]["detected"] is True
        assert result["offplatform_comms"]["detected"] is True
        assert result["urgency_language"]["detected"] is True
        assert result["instant_hire"]["detected"] is True
        assert result["generic_greeting"]["detected"] is True
