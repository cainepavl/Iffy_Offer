"""
Tests for checks/whois_check.py

Covers get_domain_age(), _safe_registrar(), and the bootstrap-cache
graceful-degradation logic. whoisit itself is mocked throughout -- these
tests exercise our wrapping/error-handling code, not RDAP servers or the
network, so they stay fast and deterministic.
"""

from datetime import datetime, timedelta, timezone

import pytest

import checks.whois_check as whois_check
from checks.whois_check import get_domain_age, _safe_registrar, _ensure_bootstrapped


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain_result(registration_date=None, entities=None):
    return {
        'registration_date': registration_date,
        'entities': entities or {},
    }


# ---------------------------------------------------------------------------
# _safe_registrar
# ---------------------------------------------------------------------------

class TestSafeRegistrar:
    def test_extracts_registrar_name(self):
        result = _domain_result(entities={'registrar': [{'name': 'Markmonitor Inc.', 'type': 'entity'}]})
        assert _safe_registrar(result) == 'Markmonitor Inc.'

    def test_missing_registrar_key_returns_none(self):
        result = _domain_result(entities={'registrant': [{'name': 'Someone'}]})
        assert _safe_registrar(result) is None

    def test_empty_entities_returns_none(self):
        result = _domain_result(entities={})
        assert _safe_registrar(result) is None

    def test_registrar_list_present_but_empty_returns_none(self):
        result = _domain_result(entities={'registrar': []})
        assert _safe_registrar(result) is None

    def test_registrar_entry_missing_name_returns_none(self):
        result = _domain_result(entities={'registrar': [{'type': 'entity'}]})
        assert _safe_registrar(result) is None


# ---------------------------------------------------------------------------
# get_domain_age (whoisit mocked, bootstrap assumed already loaded)
# ---------------------------------------------------------------------------

class TestGetDomainAge:
    def _bootstrapped(self, monkeypatch):
        monkeypatch.setattr(whois_check.whoisit, 'is_bootstrapped', lambda: True)
        monkeypatch.setattr(whois_check, '_ensure_bootstrapped', lambda: None)

    def test_established_domain(self, monkeypatch):
        self._bootstrapped(monkeypatch)
        created = datetime.now(timezone.utc) - timedelta(days=1000)
        monkeypatch.setattr(
            whois_check.whoisit, 'domain',
            lambda d: _domain_result(registration_date=created, entities={'registrar': [{'name': 'Test Registrar'}]}),
        )
        result = get_domain_age('amazon.com')
        assert result['age_days'] == 1000
        assert result['registrar'] == 'Test Registrar'
        assert 'established domain' in result['detail']

    def test_very_new_domain_flagged(self, monkeypatch):
        self._bootstrapped(monkeypatch)
        created = datetime.now(timezone.utc) - timedelta(days=5)
        monkeypatch.setattr(whois_check.whoisit, 'domain', lambda d: _domain_result(registration_date=created))
        result = get_domain_age('freshly-registered-scam.com')
        assert result['age_days'] == 5
        assert 'VERY NEW' in result['detail']

    def test_naive_datetime_normalized_to_utc(self, monkeypatch):
        self._bootstrapped(monkeypatch)
        naive_created = datetime.now() - timedelta(days=50)  # no tzinfo
        monkeypatch.setattr(whois_check.whoisit, 'domain', lambda d: _domain_result(registration_date=naive_created))
        result = get_domain_age('example.com')
        assert result['age_days'] is not None

    def test_no_registration_date_returns_unknown(self, monkeypatch):
        self._bootstrapped(monkeypatch)
        monkeypatch.setattr(whois_check.whoisit, 'domain', lambda d: _domain_result(registration_date=None))
        result = get_domain_age('privacy-redacted.example')
        assert result['age_days'] is None
        assert 'no registration date' in result['detail'].lower()

    def test_rdap_lookup_exception_degrades_gracefully(self, monkeypatch):
        self._bootstrapped(monkeypatch)

        def _raise(domain):
            raise RuntimeError("simulated RDAP failure")

        monkeypatch.setattr(whois_check.whoisit, 'domain', _raise)
        result = get_domain_age('example.com')
        assert result['age_days'] is None
        assert 'RDAP lookup failed' in result['detail']

    def test_bootstrap_unavailable_degrades_gracefully(self, monkeypatch):
        monkeypatch.setattr(whois_check, '_ensure_bootstrapped', lambda: None)
        monkeypatch.setattr(whois_check.whoisit, 'is_bootstrapped', lambda: False)
        result = get_domain_age('example.com')
        assert result['age_days'] is None
        assert result['registrar'] is None
        assert 'bootstrap data unavailable' in result['detail'].lower()

    def test_result_has_all_keys(self, monkeypatch):
        self._bootstrapped(monkeypatch)
        monkeypatch.setattr(whois_check.whoisit, 'domain', lambda d: _domain_result())
        result = get_domain_age('example.com')
        for key in ('age_days', 'creation_date', 'registrar', 'detail'):
            assert key in result


# ---------------------------------------------------------------------------
# _ensure_bootstrapped (cache-file graceful degradation)
# ---------------------------------------------------------------------------

class TestEnsureBootstrapped:
    def test_already_bootstrapped_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr(whois_check.whoisit, 'is_bootstrapped', lambda: True)
        calls = []
        monkeypatch.setattr(whois_check.whoisit, 'bootstrap', lambda **kw: calls.append('bootstrap'))
        _ensure_bootstrapped()
        assert calls == []

    def test_falls_back_to_stale_cache_when_refresh_fails(self, monkeypatch, tmp_path):
        cache_path = tmp_path / 'rdap_bootstrap.json'
        cache_path.write_text('{"fake": "bootstrap data"}')
        monkeypatch.setattr(whois_check, 'BOOTSTRAP_CACHE_PATH', str(cache_path))

        load_calls = []
        monkeypatch.setattr(whois_check.whoisit, 'is_bootstrapped', lambda: False)
        monkeypatch.setattr(whois_check.whoisit, 'load_bootstrap_data', lambda data, overrides=False: load_calls.append(data))
        monkeypatch.setattr(whois_check.whoisit, 'bootstrap_is_older_than', lambda days: True)
        monkeypatch.setattr(whois_check.whoisit, 'clear_bootstrapping', lambda: None)

        def _raise_bootstrap(**kwargs):
            raise RuntimeError('simulated network failure')

        monkeypatch.setattr(whois_check.whoisit, 'bootstrap', _raise_bootstrap)

        _ensure_bootstrapped()

        # Loaded once from cache, then reloaded again as the fallback after
        # the live refresh attempt failed.
        assert load_calls.count('{"fake": "bootstrap data"}') == 2

    def test_no_cache_and_no_network_does_not_raise(self, monkeypatch, tmp_path):
        missing_path = tmp_path / 'does_not_exist.json'
        monkeypatch.setattr(whois_check, 'BOOTSTRAP_CACHE_PATH', str(missing_path))
        monkeypatch.setattr(whois_check.whoisit, 'is_bootstrapped', lambda: False)

        def _raise_bootstrap(**kwargs):
            raise RuntimeError('simulated network failure')

        monkeypatch.setattr(whois_check.whoisit, 'bootstrap', _raise_bootstrap)

        _ensure_bootstrapped()  # should not raise
