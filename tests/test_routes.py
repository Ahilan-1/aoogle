"""Tests for Flask routes including bang redirects.

`/search` streams: the page shell with inline skeleton cards is flushed first,
then the server swaps in the rendered results fragment (see
templates/results_fragment.html). `/s` is now a plain redirect into `/search`.
Bang redirects are answered server-side on `/search`. The tests below exercise
the current behavior.
"""
from urllib.parse import quote
import main as m


class TestRoutes:
    def test_benchmark_wrapper_executes_embedded_research_query(self):
        query = (
            'Benchmark three AI web search APIs - Exa, Arlong Search, and Parallel Search - '
            'using exactly the same query: "What are the latest developments in AI agent '
            'security in 2026? Focus on indirect prompt injection, tool poisoning, web-agent '
            'security, agent security benchmarks, real-world incidents, and architectural '
            'defenses." Evaluate relevance, freshness, source quality, coverage, factual '
            'grounding, citation quality, and handling of adversarial/prompt-injection content. '
            'Return enough evidence to compare the three search systems objectively.'
        )

        contract = m._arlong_build_answer_contract(query)
        plan = m._arlong_compile_retrieval_plan(query, contract, mode='deep')
        planned_queries = [branch['query'].lower() for branch in plan]

        assert contract['benchmark_wrapper_detected'] is True
        assert contract['task'] == 'factual_answer'
        assert contract['entities'] == []
        assert contract['research_query'].startswith(
            'What are the latest developments in AI agent security in 2026?')
        assert contract['temporal_window']['basis'] == 'year_to_date'
        assert contract['temporal_window']['start'] == '2026-01-01'
        assert {facet['id'] for facet in contract['topic_facets']} == {
            'topic:indirect_prompt_injection',
            'topic:tool_poisoning',
            'topic:web_agent_security',
            'topic:security_benchmarks',
            'topic:real_world_incidents',
            'topic:architectural_defenses',
        }
        assert planned_queries[0].replace('"', '') == 'ai agent security 2026'
        assert any('indirect prompt injection' in item for item in planned_queries)
        assert any('tool and mcp poisoning' in item for item in planned_queries)
        assert any('architectural defenses' in item for item in planned_queries)
        assert all('three search systems objectively' not in item for item in planned_queries)

    def test_direct_comparison_still_compiles_as_comparison(self):
        query = 'Compare Exa, Arlong Search, and Parallel Search on source grounding and citations.'
        contract = m._arlong_build_answer_contract(query)

        assert contract['benchmark_wrapper_detected'] is False
        assert contract['task'] == 'comparison'
        assert contract['entities'] == ['Exa', 'Arlong Search', 'Parallel Search']

    def test_security_research_brief_keeps_question_intent_and_every_facet(self):
        query = (
            'What are the latest developments in AI agent security in 2026? Focus on '
            'indirect prompt injection, tool poisoning, web-agent security, agent security '
            'benchmarks, real-world incidents, and architectural defenses. Prefer recent '
            'primary research, official security guidance, and high-quality technical '
            'sources. Identify major developments and cite evidence.'
        )

        contract = m._arlong_build_answer_contract(query)
        plan = m._arlong_compile_retrieval_plan(query, contract, mode='deep')
        planned = ' '.join(branch['query'].lower() for branch in plan)

        assert contract['task'] == 'factual_answer'
        assert contract['entity_type'] is None
        assert contract['temporal_window']['start'] == '2026-01-01'
        assert len(plan) <= 8
        assert plan[0]['query'].replace('"', '') == 'AI agent security 2026'
        assert 'ai model releases' not in planned
        for facet in (
                'indirect prompt injection', 'tool and mcp poisoning', 'web-agent security',
                'agent security benchmarks', 'real-world security incidents',
                'architectural defenses'):
            assert facet.lower() in planned

    def test_recovery_can_force_puri_after_usable_recall_collapses(self, monkeypatch):
        from types import SimpleNamespace

        primary = [SimpleNamespace(url=f'https://primary.example/{index}') for index in range(5)]
        secondary = [SimpleNamespace(url='https://secondary.example/evidence')]
        calls = []
        monkeypatch.setattr(m, '_search_serper', lambda *args, **kwargs: primary)
        monkeypatch.setattr(
            m, '_search_puri',
            lambda *args, **kwargs: calls.append(args[0]) or secondary,
        )

        results, used_secondary = m._arlong_fetch_recovery_query(
            'AI agent security architectural defenses 2026', force_secondary=True)

        assert used_secondary is True
        assert calls == ['AI agent security architectural defenses 2026']
        assert len(results) == 6

    def test_empty_authenticated_result_is_refunded(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            m, '_arlong_refund_gate_credits',
            lambda gate, credits: calls.append((gate, credits)) or True,
        )
        gate = ({'allowed': True}, 'key', 'test-key')

        assert m._arlong_refund_empty_result(
            gate, {'returned_results': 0, 'evidence_atoms': []}, 12) is True
        assert calls == [(gate, 12)]
        assert m._arlong_refund_empty_result(
            gate, {'returned_results': 1}, 12) is False

    def test_navigation_and_hydration_text_cannot_become_evidence_claims(self):
        assert m._arlong_is_boilerplate_claim(
            'Apps Menu News Homepage Latest News Video Gallery Programmes Photo Gallery '
            'News Bulletins News Archive Live Video News Home OpenAI takes it slow') is True
        assert m._arlong_is_boilerplate_claim(
            'id: 11788492708561 title: Story firstPublishedDate: 2026-09-04 '
            'lastPublishedDate: 2026-09-04 keywords: artificial intelligence') is True
        assert m._arlong_is_boilerplate_claim(
            'Researchers measured indirect prompt-injection attacks across thirteen models '
            'and reported the successful attack rate in their evaluation.') is False

    def test_home_page(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'Secure Web Search API for AI Agents' in resp.data
        assert b'Arlong Evidence Graph Search' in resp.data
        assert b'class="search-form" action="/login"' in resp.data
        assert b'name="redirect" value="/playground"' in resp.data
        assert b'rel="canonical" href="https://arlong.org/"' in resp.data
        assert b'application/ld+json' in resp.data

    def test_legacy_landing_redirects_to_canonical_home(self, client):
        resp = client.get('/land')
        assert resp.status_code == 301
        assert resp.headers['Location'].endswith('/')

    def test_health(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200
        assert resp.data == b'ok'

    def test_people_search_is_discontinued(self, client):
        assert client.get('/people').status_code == 404
        assert client.get('/api/arlong/people?query=engineers').status_code == 404
        assert client.post('/api/people/search', json={
            'query': 'software engineers',
        }).status_code == 404
        assert 'arlong_people' not in {tool['name'] for tool in m.MCP_TOOLS}

    def test_mcp_oauth_accepts_existing_arlong_password_account(self, client):
        import base64
        import hashlib
        from urllib.parse import parse_qs, urlparse

        user, error = m.data_manager.create_user(
            'oauthreviewer', 'strong-review-password', 'none', 'none',
            '127.0.0.1', 'oauth-review@example.com'
        )
        assert error is None and user
        registration = client.post('/oauth/register', json={
            'client_name': 'OpenAI review client',
            'redirect_uris': ['https://chatgpt.com/callback'],
        })
        assert registration.status_code == 201
        client_id = registration.get_json()['client_id']
        verifier = 'review-verifier-' + ('x' * 43)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')
        authorize = client.get('/oauth/authorize', query_string={
            'client_id': client_id, 'redirect_uri': 'https://chatgpt.com/callback',
            'response_type': 'code', 'code_challenge': challenge,
            'code_challenge_method': 'S256', 'state': 'review-state',
        })
        assert authorize.status_code == 200
        assert b'Continue with Google' in authorize.data
        assert b'Email or username' in authorize.data
        with client.session_transaction() as sess:
            csrf = sess['_csrf_token']
        approved = client.post('/oauth/authorize/password', data={
            '_csrf_token': csrf, 'identifier': 'oauth-review@example.com',
            'password': 'strong-review-password',
        })
        assert approved.status_code == 302
        query = parse_qs(urlparse(approved.location).query)
        assert query['state'] == ['review-state']
        token = client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'code': query['code'][0],
            'code_verifier': verifier, 'client_id': client_id,
        })
        assert token.status_code == 200
        assert token.get_json()['access_token'].startswith('mcp_oauth_')

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
        assert b'arlong.org/sitemap.xml' in resp.data
        assert b'aoogle-production' not in resp.data

    def test_sitemap_lists_canonical_public_pages(self, client):
        resp = client.get('/sitemap.xml')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/xml'
        assert b'<loc>https://arlong.org/</loc>' in resp.data
        assert b'<loc>https://arlong.org/docs</loc>' in resp.data
        assert b'/admin' not in resp.data

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


class TestCommunitySupport:
    @staticmethod
    def _login_user(client, username='supporter'):
        import main as m
        user, error = m.data_manager.create_user(
            username, 'StrongPassword123!', 'question', 'answer', '127.0.0.1',
            f'{username}@example.com')
        assert error is None
        with client.session_transaction() as sess:
            sess['user_id'] = user['user_id']
            sess['username'] = user['username']
            sess['_csrf_token'] = 'support-csrf'
        return user

    def test_support_requires_registered_account(self, client):
        response = client.get('/support')
        assert response.status_code == 302
        assert '/login' in response.location or '/signup' in response.location

    def test_retired_ai_chat_redirects_to_playground(self, client):
        self._login_user(client, 'appearanceuser')
        response = client.get('/ai/chat')
        assert response.status_code == 302
        assert response.location.endswith('/playground')

    def test_pricing_uses_one_balance_and_keeps_subscription_prices(self, client):
        page = client.get('/premium')
        assert page.status_code == 200
        assert b'ONE BALANCE' in page.data
        assert b'2,500' in page.data
        assert b'4,000' in page.data
        assert b'6,000' in page.data
        assert b'$3' in page.data
        assert b'$5' in page.data
        assert b'$52' in page.data
        assert b'Save $8 compared with 12 Pro months' in page.data
        assert b'Normal Search runs' not in page.data
        assert b'API &amp; MCP credits every month' not in page.data

    def test_openai_apps_domain_verification_challenge(self, client):
        response = client.get('/.well-known/openai-apps-challenge')
        assert response.status_code == 200
        assert response.mimetype == 'text/plain'
        assert response.get_data(as_text=True) == 'zCN9OEIpUmErDO_8uqNoYidXBlAPA9YR0Es9w_uEjwY'

    def test_customer_can_create_and_reply_to_private_ticket(self, client):
        import main as m
        user = self._login_user(client)
        response = client.post('/support', data={
            '_csrf_token': 'support-csrf', 'category': 'api_mcp',
            'subject': 'Claude MCP authentication fails',
            'description': 'Claude Code returns an OAuth error whenever I connect the Arlong MCP server.',
            'client': 'Claude Code', 'steps': 'Run the MCP add command and authenticate.',
            'expected': 'The server connects.', 'actual': 'OAuth returns an error.',
        })
        assert response.status_code == 302
        ticket = m.data_manager.get_support_tickets(user['user_id'])[0]
        assert response.location.endswith('/support/tickets/' + ticket['id'] + '?created=1')
        assert ticket['status'] == 'new'

        detail = client.get('/support/tickets/' + ticket['id'])
        assert detail.status_code == 200
        assert b'Claude MCP authentication fails' in detail.data

        reply = client.post('/support/tickets/' + ticket['id'] + '/reply', data={
            '_csrf_token': 'support-csrf', 'message': 'The exact error code is invalid_redirect_uri.',
        })
        assert reply.status_code == 302
        updated = m.data_manager.get_support_ticket(ticket['id'], user['user_id'])
        assert updated['status'] == 'open'
        assert len(updated['messages']) == 2

    def test_customer_cannot_read_another_users_ticket(self, client):
        import main as m
        owner = self._login_user(client, 'ticketowner')
        ticket, error = m.data_manager.create_support_ticket(
            owner['user_id'], owner['username'], owner['email'], 'account',
            'Account email cannot be changed',
            'The account screen rejects my valid password when I save a new email address.')
        assert error is None
        other, error = m.data_manager.create_user(
            'otheruser', 'StrongPassword123!', 'question', 'answer', '127.0.0.2',
            'otheruser@example.com')
        assert error is None
        with client.session_transaction() as sess:
            sess['user_id'] = other['user_id']
            sess['username'] = other['username']
        assert client.get('/support/tickets/' + ticket['id']).status_code == 404

    def test_admin_can_reply_and_set_ticket_workflow(self, client, monkeypatch):
        import main as m
        user = self._login_user(client, 'adminreplyuser')
        ticket, error = m.data_manager.create_support_ticket(
            user['user_id'], user['username'], user['email'], 'billing',
            'Invoice is not visible in billing',
            'My successful subscription payment is visible but the invoice link is missing.')
        assert error is None
        monkeypatch.setattr(m, 'send_resend_email', lambda *args, **kwargs: True)
        with client.session_transaction() as sess:
            sess.clear()
            sess['admin_logged_in'] = True
            sess['_csrf_token'] = 'admin-csrf'
        response = client.post('/admin/tickets/' + ticket['id'] + '/reply', data={
            '_csrf_token': 'admin-csrf', 'message': 'We found the payment and are regenerating your invoice.',
            'status': 'waiting_on_customer',
        })
        assert response.status_code == 302
        updated = m.data_manager.get_support_ticket(ticket['id'])
        assert updated['status'] == 'waiting_on_customer'
        assert updated['first_response_at']
        assert updated['unread_by_customer'] is True
        queue = client.get('/admin/tickets?ticket=' + ticket['id'])
        assert queue.status_code == 200
        assert b'We found the payment' in queue.data

    def test_support_membership_and_paid_discount_workflow(self, client):
        import main as m
        from datetime import datetime, timedelta, timezone
        user = self._login_user(client, 'paidticketuser')
        uid = str(user['user_id'])
        with m.data_manager._lock:
            m.data_manager.data.setdefault('billing_subscriptions', {})[uid] = {
                'plan': 'annual', 'status': 'active', 'subscription_id': 'sub_test',
                'customer_id': 'cus_test', 'cancel_at_period_end': False,
                'current_period_end': (datetime.now(timezone.utc) + timedelta(days=20)).isoformat(),
            }
            m._save_json(m.data_manager.data)
        membership = m._support_membership(uid)
        assert membership['label'] == 'Pro Annual'
        assert membership['auto_renew'] is True
        ticket, error = m.data_manager.create_support_ticket(
            uid, user['username'], user['email'], 'billing',
            'Request billing assistance',
            'I need help understanding a renewal charge on my paid subscription.')
        assert error is None
        with client.session_transaction() as sess:
            sess.clear(); sess['admin_logged_in'] = True; sess['_csrf_token'] = 'admin-csrf'
        page = client.get('/admin/tickets?ticket=' + ticket['id'])
        assert b'Pro Annual' in page.data and b'Auto-renew' in page.data
        response = client.post('/admin/tickets/' + ticket['id'] + '/discount', data={
            '_csrf_token': 'admin-csrf', 'code': 'CARE20',
            'offer': '20% off the next eligible billing cycle', 'cycles': '1',
        })
        assert response.status_code == 302
        saved = m.data_manager.get_support_ticket(ticket['id'])
        assert saved['discount_offer']['code'] == 'CARE20'
        assert 'does not automatically change your current renewal' in saved['messages'][-1]['message']

    def test_admin_credit_compensation_is_capped_and_audited(self, client):
        import main as m
        user = self._login_user(client, 'creditcompuser')
        ticket, error = m.data_manager.create_support_ticket(
            user['user_id'], user['username'], user['email'], 'reliability',
            'Search outage consumed credits',
            'Several API requests failed during a confirmed service incident.')
        assert error is None
        with client.session_transaction() as sess:
            sess.clear(); sess['admin_logged_in'] = True; sess['_csrf_token'] = 'admin-csrf'
        rejected = client.post(f'/admin/tickets/{ticket["id"]}/credits', data={
            '_csrf_token': 'admin-csrf', 'credits': '91', 'reason': 'Service incident'})
        assert rejected.status_code == 400
        granted = client.post(f'/admin/tickets/{ticket["id"]}/credits', data={
            '_csrf_token': 'admin-csrf', 'credits': '90', 'reason': 'Confirmed service incident'})
        assert granted.status_code == 302
        wallet = m.data_manager.get_api_credit_wallet(user['user_id'])
        assert wallet['balance'] == 90
        assert wallet['ledger'][0]['source'] == 'support_compensation'

    def test_credit_purchase_webhook_is_idempotent(self, client):
        import main as m
        user = self._login_user(client, 'creditbuyer')
        payload = {'type': 'payment.succeeded', 'data': {'object': {
            'payment_id': 'pay_credit_test',
            'metadata': {'arlong_user_id': str(user['user_id']), 'arlong_credit_pack': '300'},
        }}}
        processed, uid = m.data_manager.process_dodo_webhook('wh_credit_1', payload)
        assert processed is True and uid == str(user['user_id'])
        processed_again, _ = m.data_manager.process_dodo_webhook('wh_credit_1', payload)
        assert processed_again is False
        assert m.data_manager.get_api_credit_wallet(user['user_id'])['balance'] == 300

    def test_free_user_can_spend_prepaid_credits_after_unified_allowance(self, client):
        import main as m
        user = self._login_user(client, 'freecredituser')
        uid = user['user_id']
        assert m.data_manager.consume_plan_usage(uid, 'api', 100)['allowed'] is True
        assert m.data_manager.consume_plan_usage(uid, 'api', 1)['allowed'] is False
        m.data_manager.grant_api_credits(uid, 2, 'Purchased test credits', source='test')
        result = m.data_manager.consume_plan_usage(uid, 'api', 1)
        assert result['allowed'] is True
        assert result['bonus_remaining'] == 1

    def test_failed_deep_search_usage_can_be_restored(self, client):
        import main as m
        user = self._login_user(client, 'deeprefunduser')
        uid = user['user_id']
        consumed = m.data_manager.consume_plan_usage(
            uid, 'deep', m.CREDIT_COSTS['playground_research'])
        assert consumed['allowed'] is True
        assert consumed['used'] == 12
        restored = m.data_manager.refund_plan_usage(
            uid, 'deep', m.CREDIT_COSTS['playground_research'])
        assert restored['used'] == 0
        assert restored['remaining'] == restored['limit']

    def test_playground_api_and_mcp_share_one_credit_balance(self, client):
        import main as m
        user = self._login_user(client, 'unifiedcredituser')
        uid = user['user_id']
        m.data_manager.consume_plan_usage(uid, 'standard', 3)
        m.data_manager.consume_plan_usage(uid, 'api', 2)
        usage = m.data_manager.get_plan_usage(uid)['usage']
        assert usage['credits']['used'] == 5
        assert usage['standard']['used'] == 5
        assert usage['api']['used'] == 5
        assert m.PLAN_LIMITS['free']['credits'] == 100
        assert m.CREDIT_COSTS['arlong_deep'] == 12
        assert m.CREDIT_PACKS[100]['price'] == 1.49


