"""Tests for Flask routes including bang redirects.

`/search` streams: the page shell with inline skeleton cards is flushed first,
then the server swaps in the rendered results fragment (see
templates/results_fragment.html). `/s` is now a plain redirect into `/search`.
Bang redirects are answered server-side on `/search`. The tests below exercise
the current behavior.
"""
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

    def test_search_streams_results(self, client):
        resp = client.get('/search?q=python+tutorial')
        assert resp.status_code == 200
        assert b'arlong' in resp.data
        assert b'results-skeleton' in resp.data

    def test_bang_redirect_google(self, client):
        resp = client.get('/search?q=!g+hello+world&sr=1')
        assert resp.status_code == 302
        assert 'google.com' in resp.location
        assert quote('hello world') in resp.location or 'hello+world' in resp.location

    def test_bang_redirect_wikipedia(self, client):
        resp = client.get('/search?q=!wiki+Python&sr=1')
        assert resp.status_code == 302
        assert 'wikipedia.org' in resp.location

    def test_bang_redirect_chatgpt(self, client):
        resp = client.get('/search?q=!ch+hello&sr=1')
        assert resp.status_code == 302
        assert 'chatgpt.com' in resp.location

    def test_s_route_redirects_to_search(self, client):
        resp = client.get('/s?q=python+tutorial')
        assert resp.status_code == 302
        assert '/search?q=' in resp.headers['Location']

    def test_bang_only_no_query_redirects(self, client):
        resp = client.get('/search?q=!wiki&sr=1')
        assert resp.status_code == 302
        assert 'wikipedia.org' in resp.location

    def test_unknown_bang_redirects_to_search(self, client):
        resp = client.get('/s?q=!zzzz nonsense')
        assert resp.status_code == 302
        assert '/search?q=' in resp.headers['Location']

    def test_crisis_detection_route(self, client):
        resp = client.get('/search?q=i+want+to+die&sr=1')
        assert resp.status_code == 200
        assert b'You matter' in resp.data

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
        assert resp.status_code == 200

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

    def test_official_domain_brand_boost(self):
        """A query term matching the domain base wins a strong navigational
        boost (e.g. 'mullvad browser features' -> mullvad.net)."""
        from main import ImprovedSearch, SearchResult
        f = ImprovedSearch._score_official_domain_boost

        brand = SearchResult('Mullvad Browser', 'https://mullvad.net/en/', 'Private browsing. No ads.')
        assert f(None, 'mullvad browser features', brand) >= 140
        assert f(None, 'best mullvad vpn settings', brand) >= 140
        assert f(None, 'python tutorial', SearchResult('Python', 'https://www.python.org/', 'Docs')) >= 140

        unrelated = SearchResult('Post', 'https://blogspot.com/x', 's')
        assert f(None, 'mullvad browser features', unrelated) == 0

        generic = SearchResult('Browser', 'https://browser.com/', 'browser')
        assert f(None, 'browser download', generic) < 140


class TestAIHelpers:
    def test_ai_history_skips_pending_and_declined(self):
        from main import _ai_history
        chat = {'messages': [
            {'role': 'user', 'content': 'hi'},
            {'role': 'assistant', 'content': '', 'pending': True},
            {'role': 'assistant', 'content': '', 'declined': True},
            {'role': 'assistant', 'content': 'answer'},
        ]}
        hist = _ai_history(chat)
        assert [x['content'] for x in hist] == ['hi', 'answer']

    def test_ai_build_messages_report_mode(self):
        from main import _ai_build_messages
        results = [
            {'title': 'Mullvad', 'url': 'https://mullvad.net', 'snippet': 'x', 'group': 'VPN services'},
            {'title': 'Proton', 'url': 'https://protonvpn.com', 'snippet': 'y', 'group': 'VPN services'},
        ]
        report = _ai_build_messages([{'role': 'user', 'content': 'best vpn?'}], results, report=True)
        assert report[0]['role'] == 'system'
        assert 'Deep Research' in report[0]['content']
        assert 'VPN services' in report[-1]['content']
        normal = _ai_build_messages([], results, report=False)
        assert 'Deep Research' not in normal[0]['content']

    def test_ai_append_message_stores_pending_flag(self):
        from main import _ai_append_message
        chat = {'messages': []}
        ok = _ai_append_message(chat, 'assistant', '',
                                query='q', sources=[], groups=[],
                                multitask=True, pending=True)
        assert ok
        msg = chat['messages'][-1]
        assert msg.get('pending') is True
        assert msg.get('multitask') is True
        assert msg.get('query') == 'q'

    def test_api_ai_report_decline_endpoint(self, client):
        import main as m
        chat = {'chat_id': 'abc123', 'title': 't', 'messages': [],
                'created_at': 'x', 'updated_at': 'x'}
        m._ai_append_message(chat, 'user', 'what is the best vpn?')
        m._ai_append_message(chat, 'assistant', '',
                             query='what is the best vpn?', sources=[],
                             groups=[], multitask=True, pending=True)
        m.data_manager.save_ai_chat('u1', chat)
        with client.session_transaction() as sess:
            sess['user_id'] = 'u1'
            sess['_csrf_token'] = 'test-csrf-token'
        resp = client.post('/api/ai/report-decline', json={
            'chat_id': 'abc123', '_csrf_token': 'test-csrf-token'
        })
        assert resp.status_code == 200
        saved = m.data_manager.get_ai_chat('u1', 'abc123')
        last = saved['messages'][-1]
        assert last.get('pending') is False
        assert last.get('declined') is True


