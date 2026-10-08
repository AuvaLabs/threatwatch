"""Tests for bounded, cached observable provider lookups."""

from modules.ioc_enrichment import ThreatFoxProvider, UrlhausProvider


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Session:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response(self.payload)


def test_threatfox_uses_exact_authenticated_search():
    session = _Session({"query_status": "ok", "data": [{"ioc": "185.220.101.50", "malware": "Example"}]})

    result = ThreatFoxProvider("secret", session=session).lookup("ipv4", "185.220.101.50")

    assert result["status"] == "matched"
    _, request = session.calls[0]
    assert request["headers"]["Auth-Key"] == "secret"
    assert request["json"]["exact_match"] is True


def test_urlhaus_only_queries_urls():
    provider = UrlhausProvider("secret", session=_Session({"query_status": "ok", "url_status": "online"}))

    assert provider.lookup("domains", "bad.example") is None
    assert provider.lookup("urls", "https://bad.example/payload")["status"] == "matched"
