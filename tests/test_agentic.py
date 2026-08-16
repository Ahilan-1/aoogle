"""Tests for the Gen-2 agentic search layer: planner, parallel fan-out,
full-page grounding, and grounded-context formatting. All LLM/network
dependencies are stubbed so the tests are deterministic and offline-safe."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pytest
import main as m


class TestAgenticPlanOffline:
    def test_failing_multi_hop_example_splits(self, monkeypatch):
        monkeypatch.setattr(m, 'AI_MODE_GROQ_API_KEY', '')
        plan = m._ai_agentic_plan(
            'Find the birth city of the director who won the Academy Award for '
            'Best Director the year that the movie Everything Everywhere All at '
            'Once won Best Picture. What is the current population of that city?',
        )
        assert plan['mode'] == 'multi'
        assert len(plan['tasks']) >= 2

    def test_simple_query_stays_single(self, monkeypatch):
        monkeypatch.setattr(m, 'AI_MODE_GROQ_API_KEY', '')
        for q in ('python tutorial', 'what is the capital of france',
                  'population of london 2026', 'who directed inception'):
            plan = m._ai_agentic_plan(q)
            assert plan['mode'] == 'single', q
            assert plan.get('query')

    def test_empty_query(self):
        plan = m._ai_agentic_plan('')
        assert plan['mode'] == 'single'
        assert plan.get('query')

    def test_offline_no_key_delegates(self, monkeypatch):
        monkeypatch.setattr(m, 'AI_MODE_GROQ_API_KEY', '')
        assert m._ai_agentic_plan_offline(
            'Who directed inception. What is his birth city?', max_tasks=3)['mode'] == 'multi'
        assert m._ai_agentic_plan_offline('single query here')['mode'] == 'single'


class TestAgenticGather:
    def _fake_top(self, query, limit=5):
        return [
            {'title': f'{query} title', 'url': f'https://{query.replace(" ", "-")}.com',
             'snippet': f'snippet for {query}'},
            {'title': 'shared result', 'url': 'https://shared.example.com',
             'snippet': 'appears in both'},
        ]

    def test_gather_fanout_dedupes_by_url(self, monkeypatch):
        monkeypatch.setattr(m, '_ai_top_results', self._fake_top)
        tasks = [
            {'label': 'One', 'query': 'first query'},
            {'label': 'Two', 'query': 'second query'},
        ]
        flat, groups = m._ai_agentic_gather('user question', tasks, per_query=5)
        urls = [r['url'] for r in flat]
        assert len(urls) == len(set(urls)), 'duplicate URLs must be removed'
        assert len(groups) == 2
        assert all(len(g['results']) >= 1 for g in groups)

    def test_gather_groups_share_objects(self, monkeypatch):
        monkeypatch.setattr(m, '_ai_top_results', self._fake_top)
        tasks = [{'label': 'One', 'query': 'first query'}]
        flat, groups = m._ai_agentic_gather('q', tasks)
        flat[0]['group'] = 'edited'
        assert groups[0]['results'][0]['group'] == 'edited'

    def test_gather_empty_tasks(self, monkeypatch):
        monkeypatch.setattr(m, '_ai_top_results', self._fake_top)
        flat, groups = m._ai_agentic_gather('fallback query', [])
        assert flat


class TestAgenticGround:
    def test_ground_attaches_content(self, monkeypatch):
        def fake_fetch(url):
            return 'A real page body with plenty of text ' * 10
        monkeypatch.setattr(m, '_arlong_page_text', fake_fetch)
        monkeypatch.setattr(m, '_is_junk_body', lambda head: False)
        results = [{'url': 'https://a.com', 'title': 'A'}, {'url': 'https://b.com', 'title': 'B'}]
        m._ai_ground_results('q', results, per_fetch=4, max_fetch=8)
        assert all(r.get('content') for r in results)

    def test_ground_skips_junk_bodies(self, monkeypatch):
        monkeypatch.setattr(m, '_arlong_page_text', lambda url: 'okay body text' * 10)
        monkeypatch.setattr(m, '_is_junk_body', lambda head: True)
        results = [{'url': 'https://a.com', 'title': 'A'}]
        m._ai_ground_results('q', results, per_fetch=4, max_fetch=8)
        assert 'content' not in results[0]


class TestAgenticContext:
    def test_context_format(self):
        grounded = [
            {'url': 'https://a.com', 'title': 'Alpha',
             'content': 'body of alpha', 'snippet': 'snip'},
        ]
        extra, ctx = m._ai_agentic_context(grounded)
        assert len(extra) == 1
        assert extra[0]['url'] == 'https://a.com'
        assert '[Source 1]' in ctx
        assert 'URL: https://a.com' in ctx
        assert 'Content: body of alpha' in ctx

    def test_context_skips_ungrounded(self):
        grounded = [{'url': 'https://a.com', 'title': 'Alpha'}]
        extra, ctx = m._ai_agentic_context(grounded)
        assert extra == []
        assert ctx == ''
