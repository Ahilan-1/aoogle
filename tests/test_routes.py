"""Tests for Flask routes including bang redirects."""
from urllib.parse import quote


class TestRoutes:
    def test_home_page(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'arlong' in resp.data

    def test_health(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200
        assert resp.data == b'ok'

    def test_bang_redirect_google(self, client):
        resp = client.get('/search?q=!g+hello+world')
        assert resp.status_code == 302
        assert 'google.com' in resp.location
        assert quote('hello world') in resp.location or 'hello+world' in resp.location

    def test_bang_redirect_wikipedia(self, client):
        resp = client.get('/search?q=!wiki+Python')
        assert resp.status_code == 302
        assert 'wikipedia.org' in resp.location

    def test_bang_redirect_chatgpt(self, client):
        resp = client.get('/search?q=!ch+hello')
        assert resp.status_code == 302
        assert 'chatgpt.com' in resp.location

    def test_normal_search_no_redirect(self, client):
        resp = client.get('/search?q=python+tutorial')
        assert resp.status_code == 200

    def test_bang_only_no_query_redirects(self, client):
        resp = client.get('/search?q=!wiki')
        assert resp.status_code == 302
        assert 'wikipedia.org' in resp.location

    def test_unknown_bang_shows_search(self, client):
        resp = client.get('/search?q=!zzzz nonsense')
        assert resp.status_code == 200

    def test_crisis_detection_route(self, client):
        resp = client.get('/search?q=i+want+to+die')
        assert resp.status_code == 200

    def test_images_route(self, client):
        resp = client.get('/images?q=python')
        assert resp.status_code == 200

    def test_videos_route(self, client):
        resp = client.get('/videos?q=python')
        assert resp.status_code == 200

    def test_about_page(self, client):
        resp = client.get('/about')
        assert resp.status_code == 302

    def test_docs_page(self, client):
        resp = client.get('/docs')
        assert resp.status_code == 200

    def test_stats_page(self, client):
        resp = client.get('/stats')
        assert resp.status_code == 200

    def test_blog_page(self, client):
        resp = client.get('/blog')
        assert resp.status_code == 302

    def test_crisis_page(self, client):
        resp = client.get('/crisis')
        assert resp.status_code == 200

    def test_policy_page(self, client):
        resp = client.get('/policy')
        assert resp.status_code == 200
        assert b'Submit your website' in resp.data or b'Privacy' in resp.data

    def test_submit_page(self, client):
        resp = client.get('/submit')
        assert resp.status_code == 200
        assert b'submit' in resp.data.lower()

    def test_faq_page(self, client):
        resp = client.get('/faq')
        assert resp.status_code == 200
        assert b'FAQ' in resp.data or b'frequently' in resp.data.lower()

    def test_robots_txt(self, client):
        resp = client.get('/robots.txt')
        assert resp.status_code == 200
        assert b'User-agent' in resp.data
        assert b'Disallow' in resp.data

    def test_api_bangs(self, client):
        resp = client.get('/api/bangs')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) >= 70
        assert data[0].get('bang') == '!a'
        assert data[0].get('domain')
        assert data[0].get('favicon')
