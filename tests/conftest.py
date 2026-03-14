"""Pre-install lightweight mocks for heavy optional dependencies so test
collection succeeds in environments where those packages are not installed.

Only installed if the real package is absent — real packages take precedence.
"""

import sys
import types
from unittest.mock import MagicMock


def _make_anthropic_mock():
    """Minimal anthropic mock with the exception hierarchy tests depend on."""
    mod = types.ModuleType("anthropic")

    class APIError(Exception):
        def __init__(self, message="", *, request=None, body=None):
            super().__init__(message)
            self.request = request
            self.body = body

    class APIConnectionError(APIError):
        pass

    class APITimeoutError(APIError):
        pass

    class InternalServerError(APIError):
        pass

    mod.APIError = APIError
    mod.APIConnectionError = APIConnectionError
    mod.APITimeoutError = APITimeoutError
    mod.InternalServerError = InternalServerError
    mod.Anthropic = MagicMock
    return mod


def _make_feedparser_mock():
    """Minimal feedparser mock — parse() returns empty .entries by default."""
    mod = types.ModuleType("feedparser")

    def parse(content_or_url, **kwargs):
        result = MagicMock()
        result.entries = []
        return result

    mod.parse = parse
    return mod


def _make_trafilatura_mock():
    """Minimal trafilatura mock — fetch_url returns None, extract returns None."""
    mod = types.ModuleType("trafilatura")

    def fetch_url(url, **kwargs):
        return None

    def extract(content, **kwargs):
        return None

    mod.fetch_url = fetch_url
    mod.extract = extract
    return mod


def _make_lingua_mock():
    """Minimal lingua mock — always detects English."""
    mod = types.ModuleType("lingua")

    class _IsoCode639_1:
        name = "EN"

    class _Language:
        iso_code_639_1 = _IsoCode639_1()

    class _Detector:
        def detect_language_of(self, text):
            return _Language()

    class _Builder:
        def build(self):
            return _Detector()

        def with_preloaded_language_models(self):
            return self

    class LanguageDetectorBuilder:
        @classmethod
        def from_all_languages(cls):
            return _Builder()

    mod.LanguageDetectorBuilder = LanguageDetectorBuilder
    return mod


def _make_bs4_mock():
    """Minimal bs4 mock."""
    mod = types.ModuleType("bs4")

    class BeautifulSoup:
        def __init__(self, markup="", parser="html.parser", **kwargs):
            self._markup = markup

        def find(self, *args, **kwargs):
            return None

        def find_all(self, *args, **kwargs):
            return []

        def __call__(self, *args, **kwargs):
            return []

        def decompose(self):
            pass

    mod.BeautifulSoup = BeautifulSoup
    return mod


def _make_feedgen_mock():
    """Minimal feedgen mock."""
    mod = types.ModuleType("feedgen")
    feed_mod = types.ModuleType("feedgen.feed")

    class FeedEntry:
        def title(self, *a, **kw): pass
        def link(self, *a, **kw): pass
        def description(self, *a, **kw): pass
        def pubDate(self, *a, **kw): pass

    class FeedGenerator:
        def id(self, *a, **kw): pass
        def title(self, *a, **kw): pass
        def link(self, *a, **kw): pass
        def language(self, *a, **kw): pass
        def description(self, *a, **kw): pass

        def add_entry(self):
            return FeedEntry()

        def rss_file(self, path, **kw):
            pass

    feed_mod.FeedGenerator = FeedGenerator
    mod.feed = feed_mod
    sys.modules["feedgen.feed"] = feed_mod
    return mod


if "anthropic" not in sys.modules:
    sys.modules["anthropic"] = _make_anthropic_mock()

if "feedparser" not in sys.modules:
    sys.modules["feedparser"] = _make_feedparser_mock()

if "trafilatura" not in sys.modules:
    sys.modules["trafilatura"] = _make_trafilatura_mock()

if "lingua" not in sys.modules:
    sys.modules["lingua"] = _make_lingua_mock()

if "bs4" not in sys.modules:
    sys.modules["bs4"] = _make_bs4_mock()

if "feedgen" not in sys.modules:
    sys.modules["feedgen"] = _make_feedgen_mock()
