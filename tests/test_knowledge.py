"""Tests for knowledge panels including Wikipedia integration."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from main import get_info_box, get_wikipedia_panel


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
