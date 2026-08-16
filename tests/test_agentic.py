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


class TestFollowupRetrieve:
    def test_uses_agentic_fanout_and_grounding(self, monkeypatch):
        flat = [
            {'url': 'https://gdp-a.com', 'title': 'GDP A', 'snippet': 's'},
            {'url': 'https://gdp-b.com', 'title': 'GDP B', 'snippet': 's'},
        ]

        def fake_gather(q, tasks, per_query=4):
            assert len(tasks) >= 1
            return flat, [{'label': 'Follow-up 1', 'query': tasks[0]['query'], 'results': flat}]

        captured = {}
        def fake_ground(q, results, per_fetch=4, max_fetch=8):
            for r in results:
                r['content'] = 'GDP of the United Kingdom is 3.6 trillion dollars. ' * 5
            captured['grounded'] = True
            return results

        monkeypatch.setattr(m, '_ai_agentic_gather', fake_gather)
        monkeypatch.setattr(m, '_ai_ground_results', fake_ground)
        extra, ctx = m._arlong_followup_retrieve(
            'UK GDP', ['United Kingdom nominal GDP 2026'], limit=3)
        assert extra, 'follow-up retrieval must return grounded sources'
        assert all(e.get('content') for e in extra)
        assert captured.get('grounded')

    def test_returns_empty_on_no_results(self, monkeypatch):
        monkeypatch.setattr(m, '_ai_agentic_gather', lambda q, tasks, per_query=4: ([], []))
        extra, ctx = m._arlong_followup_retrieve('q', ['a b'], limit=3)
        assert extra == []
        assert ctx == ''


class TestRecursiveFollowup:
    def test_loops_until_complete(self, monkeypatch):
        calls = {'completeness': 0, 'retrieve': 0, 'answer': 0}

        def fake_check(q, answer, sources):
            calls['completeness'] += 1
            return ['United Kingdom GDP 2026'] if calls['completeness'] == 1 else []

        def fake_retrieve(q, queries):
            calls['retrieve'] += 1
            return ([{'url': 'https://gdp.com', 'title': 'GDP', 'content': '3.6 trillion'}], '\n[Follow-up] x')

        def fake_answer(q, results, extra_sources=None, extra_context=None, followup_round=None):
            calls['answer'] += 1
            assert followup_round == 2
            return ('Round two answer', [{'url': 'https://gdp.com', 'title': 'GDP'}])

        monkeypatch.setattr(m, '_arlong_completeness_check', fake_check)
        monkeypatch.setattr(m, '_arlong_followup_retrieve', fake_retrieve)
        monkeypatch.setattr(m, 'arlong_ai_answer', fake_answer)
        answer, sources, followup = m._arlong_recursive_followup(
            'q', 'round one', [{'url': 'https://a.com', 'title': 'A'}],
            [{'url': 'https://a.com', 'title': 'A', 'content': 'round1 content'}],
            '', max_rounds=3,
        )
        assert answer == 'Round two answer'
        assert followup['ran'] is True
        assert followup['rounds'] == 2
        assert followup['queries'] == ['United Kingdom GDP 2026']

    def test_merges_prior_and_followup_sources(self, monkeypatch):
        seen = {}

        def fake_check(q, answer, sources):
            return ['missing metric']

        def fake_retrieve(q, queries):
            return ([{'url': 'https://new.com', 'title': 'New', 'content': 'raw number'}], '')

        def fake_answer(q, results, extra_sources=None, extra_context=None, followup_round=None):
            seen['urls'] = {s.get('url') for s in (extra_sources or [])}
            return ('ans', [])

        monkeypatch.setattr(m, '_arlong_completeness_check', fake_check)
        monkeypatch.setattr(m, '_arlong_followup_retrieve', fake_retrieve)
        monkeypatch.setattr(m, 'arlong_ai_answer', fake_answer)
        m._arlong_recursive_followup(
            'q', 'ans', [],
            [{'url': 'https://old.com', 'title': 'Old', 'content': 'prior'}],
            '', max_rounds=3,
        )
        assert seen.get('urls') == {'https://old.com', 'https://new.com'}

    def test_stops_when_complete(self, monkeypatch):
        monkeypatch.setattr(m, '_arlong_completeness_check', lambda q, a, s: [])
        monkeypatch.setattr(m, '_arlong_followup_retrieve', lambda q, qs: ([], ''))
        answer, sources, followup = m._arlong_recursive_followup('q', 'ans', [], [], '', max_rounds=3)
        assert answer == 'ans'
        assert followup['ran'] is False
        assert followup['rounds'] == 1

    def test_keeps_last_answer_when_all_models_busy(self, monkeypatch):
        class Busy(Exception):
            pass

        def fake_check(q, a, s):
            return ['missing']

        def fake_retrieve(q, qs):
            return ([{'url': 'https://x.com', 'content': 'c'}], '')

        def fake_answer(*a, **k):
            raise Busy()

        monkeypatch.setattr(m, '_arlong_completeness_check', fake_check)
        monkeypatch.setattr(m, '_arlong_followup_retrieve', fake_retrieve)
        monkeypatch.setattr(m, 'arlong_ai_answer', fake_answer)
        answer, sources, followup = m._arlong_recursive_followup('q', 'round1', [], [], '', max_rounds=3)
        assert answer == 'round1'
        assert followup['ran'] is True
