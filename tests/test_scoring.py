"""Tests for search scoring algorithms."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from main import SearchIntent, SearchBlocker, DOMAIN_AUTHORITY, get_info_box


class TestSearchIntent:
    def test_discussion_intent(self):
        intent = SearchIntent("best python ide vs pycharm")
        assert 'discussion' in intent.detected_intents
        assert intent.wants_discussion()

    def test_navigational_intent(self):
        intent = SearchIntent("facebook login")
        assert 'navigational' in intent.detected_intents
        assert intent.is_navigational()

    def test_transactional_intent(self):
        intent = SearchIntent("buy python course")
        assert 'transactional' in intent.detected_intents
        assert intent.is_transactional()

    def test_informational_fallback(self):
        intent = SearchIntent("quantum physics")
        assert 'informational' in intent.detected_intents

    def test_local_intent(self):
        intent = SearchIntent("restaurants near me")
        assert 'local' in intent.detected_intents


class TestSearchBlocker:
    def test_ad_domain_blocked(self):
        assert SearchBlocker.is_ad("https://taboola.com/some-ad", "Sponsored", "")

    def test_ad_keywords_high_score(self):
        title = "sponsored promoted advertisement"
        snippet = "paid partner affiliate"
        url = "https://example.com/normal"
        assert SearchBlocker.is_ad(url, title, snippet)

    def test_normal_content_not_blocked(self):
        url = "https://github.com/python/cpython"
        title = "cpython source code"
        snippet = "Official Python source code repository"
        assert not SearchBlocker.is_ad(url, title, snippet)


class TestDomainAuthority:
    def test_wikipedia_high_authority(self):
        assert DOMAIN_AUTHORITY.get('wikipedia.org', 0) >= 90

    def test_knowledge_panels(self):
        panel = get_info_box("python programming tutorial")
        assert panel is not None
        assert "Python" in panel["title"]
        assert get_info_box("asdfghjkl12345") is None
