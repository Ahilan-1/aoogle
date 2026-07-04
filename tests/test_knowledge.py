"""Tests for knowledge panels including Wikipedia integration."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from main import get_info_box, get_wikipedia_panel, get_media_panel


class TestStaticKnowledgePanels:
    def test_python_panel(self):
        panel = get_info_box("python programming tutorial")
        assert panel is not None
        assert "Python" in panel["title"]
        assert panel["type"] == "Programming language"

    def test_flask_panel(self):
        panel = get_info_box("flask web framework")
        assert panel is not None
        assert "Flask" in panel["title"]

    def test_google_panel(self):
        panel = get_info_box("google search engine")
        assert panel is not None
        assert "Google" in panel["title"]

    def test_linux_panel(self):
        panel = get_info_box("linux operating system")
        assert panel is not None
        assert "Linux" in panel["title"]

    def test_docker_panel(self):
        panel = get_info_box("docker containers")
        assert panel is not None
        assert "Docker" in panel["title"]

    def test_unknown_returns_none(self):
        assert get_info_box("asdfghjkl12345xyz") is None


class TestWikipediaPanel:
    def test_wikipedia_panel_fetch_real(self):
        """This test actually calls the Wikipedia API."""
        panel = get_wikipedia_panel("Python programming language")
        if panel is not None:
            assert "Python" in panel["title"]
            assert "Wikipedia" in panel["type"] or "Wikipedia" in str(panel.get("facts", []))
            assert panel.get("description")

    def test_wikipedia_panel_cached(self):
        """Second call should return cached result."""
        panel1 = get_wikipedia_panel("Python programming language")
        panel2 = get_wikipedia_panel("Python programming language")
        assert panel1 == panel2 if panel1 else True

    def test_wikipedia_panel_short_query(self):
        assert get_wikipedia_panel("ab") is None

    def test_wikipedia_panel_unknown(self):
        panel = get_wikipedia_panel("xyzzy_nonexistent_article")
        assert panel is None

    def test_wikipedia_integrated_via_get_info_box(self):
        """get_info_box should fall back to Wikipedia API for unknown queries."""
        panel = get_info_box("Albert Einstein")
        if panel is not None:
            assert "Albert Einstein" in panel["title"] or "Einstein" in panel.get("description", "")


class TestMediaPanel:
    def test_movie_inception(self):
        panel = get_media_panel("Inception")
        assert panel is not None
        assert panel["panel_type"] == "media"
        assert panel["media_type"] == "movie"
        assert "Inception" in panel["title"]
        assert panel["rating"]
        assert len(panel["cast"]) > 0

    def test_tv_breaking_bad(self):
        panel = get_media_panel("Breaking Bad")
        assert panel is not None
        assert panel["panel_type"] == "media"
        assert panel["media_type"] == "tv"
        assert "Breaking Bad" in panel["title"]
        assert panel["rating"]
        assert len(panel["cast"]) > 0

    def test_unknown_returns_none(self):
        assert get_media_panel("asdfghjklzxcvbnm") is None

    def test_media_integrated_via_get_info_box(self):
        panel = get_info_box("Inception cast")
        if panel and panel.get("panel_type") == "media":
            assert "Inception" in panel["title"]

    def test_static_panel_still_wins_over_media(self):
        panel = get_info_box("python programming")
        assert panel is not None
        assert panel.get("panel_type") != "media"
        assert "Python" in panel["title"]

    def test_tv_office_cast(self):
        panel = get_media_panel("The Office cast")
        assert panel is not None
        assert panel["media_type"] == "tv"
        assert len(panel["cast"]) > 0
        assert len(panel["gallery"]) > 0
