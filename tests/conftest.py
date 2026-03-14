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


def _make_newspaper_mock():
    """Minimal newspaper3k mock."""
    mod = types.ModuleType("newspaper")

    class Article:
        def __init__(self, url, **kwargs):
            self.url = url
            self.text = ""

        def download(self):
            pass

        def parse(self):
            pass

    mod.Article = Article
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

if "newspaper" not in sys.modules:
    sys.modules["newspaper"] = _make_newspaper_mock()

def _make_langdetect_mock():
    """Minimal langdetect mock — always returns English."""
    mod = types.ModuleType("langdetect")

    def detect(text):
        return "en"

    mod.detect = detect
    mod.LangDetectException = Exception
    return mod


if "bs4" not in sys.modules:
    sys.modules["bs4"] = _make_bs4_mock()

if "feedgen" not in sys.modules:
    sys.modules["feedgen"] = _make_feedgen_mock()

if "langdetect" not in sys.modules:
    sys.modules["langdetect"] = _make_langdetect_mock()
