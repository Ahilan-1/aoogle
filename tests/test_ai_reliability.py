from types import SimpleNamespace

import main


def test_partial_link_evaluations_are_completed(monkeypatch):
    monkeypatch.setattr(
        main, '_ai_link_evaluations',
        lambda query, results: ({1: 'Useful official reference.'}, {1: 'primary'}, None),
    )
    results = [
        {'title': 'Official', 'url': 'https://example.gov/a', 'snippet': 'quota reference'},
        {'title': 'Guide', 'url': 'https://example.com/b', 'snippet': 'quota guide'},
        {'title': 'Forum', 'url': 'https://discuss.example.com/c', 'snippet': 'quota discussion'},
    ]
    evaluations, tags = main._ai_complete_link_evaluations(
        'quota limits', results, {1: 'Useful official reference.'}, {1: 'primary'})

    assert set(evaluations) == {1, 2, 3}
    assert set(tags) == {1, 2, 3}
    assert evaluations[1] == 'Useful official reference.'
    assert tags[3] == 'community'
    assert all('%' not in text for text in evaluations.values())
    assert all('verify important claims' not in text.lower() for text in evaluations.values())


def test_groq_rate_limit_uses_backup_account(monkeypatch):
    monkeypatch.setattr(main, 'GEMINI_API_KEY', '')
    monkeypatch.setattr(main, 'AI_MODE_GROQ_API_KEY', 'primary-key')
    monkeypatch.setattr(main, 'AI_MODE_GROQ_BACKUP_API_KEY', 'backup-key')
    monkeypatch.setattr(main, 'AI_GROQ_PRIMARY_COOLDOWN_UNTIL', 0.0)
    monkeypatch.setattr(main._ai_router_module, 'get_router', lambda: None)
    calls = []

    def provider(model, messages, max_tokens, temperature, timeout, **kwargs):
        calls.append(kwargs.get('api_key'))
        if kwargs.get('api_key') == 'primary-key':
            error = RuntimeError('429 rate limit')
            error.status_code = 429
            raise error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='ok'))])

    monkeypatch.setattr(main, '_ai_provider_call', provider)
    response = main._ai_completion(
        [{'role': 'user', 'content': 'test'}], models=['openai/gpt-oss-20b'])

    assert response.choices[0].message.content == 'ok'
    assert calls == ['primary-key', 'backup-key']
    assert main._ai_groq_key_for_call() == 'backup-key'


def test_groq_lane_falls_back_to_gemini_before_global_outage(monkeypatch):
    monkeypatch.setattr(main, 'GEMINI_API_KEY', 'gemini-key')
    monkeypatch.setattr(main, 'GEMINI_MODELS', ('gemini-2.5-flash-lite',))
    monkeypatch.setattr(main, 'AI_MODE_GROQ_API_KEY', 'groq-key')
    monkeypatch.setattr(main, 'AI_MODE_GROQ_BACKUP_API_KEY', '')
    monkeypatch.setattr(main, 'AI_MODE_GROQ_TERTIARY_API_KEY', '')
    monkeypatch.setattr(main, 'AI_GROQ_PRIMARY_COOLDOWN_UNTIL', 0.0)
    monkeypatch.setattr(main._ai_router_module, 'get_router', lambda: None)
    attempted = []

    def provider(model, *args, **kwargs):
        attempted.append(model)
        if model == 'groq-model':
            error = RuntimeError('429 rate limit')
            error.status_code = 429
            raise error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='ok'))])

    monkeypatch.setattr(main, '_ai_provider_call', provider)
    monkeypatch.setattr(main, '_open_operational_incident',
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError('false global incident')))
    response = main._ai_completion(
        [{'role': 'user', 'content': 'test'}], models=['groq-model'])
    assert response.choices[0].message.content == 'ok'
    assert attempted == ['groq-model', 'gemini-2.5-flash-lite']


def test_evaluation_fallback_understands_source_type_and_query_match():
    results = [
        {
            'title': 'Benchmarks | Supabase Docs',
            'url': 'https://supabase.com/docs/guides/realtime/benchmarks',
            'snippet': '2 weeks ago - Performance in production environments may vary. Workloads demonstrate throughput and scalability.',
        },
        {
            'title': 'Supabase vs PostgreSQL (2026) - YouTube',
            'url': 'https://youtube.com/watch?v=123',
            'snippet': 'A full breakdown comparing performance, scalability, and ease of use.',
        },
        {
            'title': 'pgvector vs Pinecone: cost and performance',
            'url': 'https://supabase.com/blog/pgvector-vs-pinecone',
            'snippet': 'A comparison of Postgres pgvector and Pinecone for AI workloads.',
        },
    ]

    evaluations, tags = main._ai_complete_link_evaluations(
        'Supabase benchmarks', results)

    assert evaluations[1].startswith('Worth opening')
    assert '2 weeks ago' not in evaluations[1]
    assert 'production environments may vary' not in evaluations[1]
    assert evaluations[3].startswith('Useful background')
    assert tags[1] == 'primary'
    assert tags[2] == 'community'


def test_partial_topic_match_is_useful_background_not_rejected():
    results = [{
        'title': 'PostgreSQL vs Supabase (2026) - Detailed Comparison',
        'url': 'https://example.com/postgresql-vs-supabase',
        'snippet': 'Compare PostgreSQL and Supabase performance, scalability, and ease of use.',
    }]

    evaluations, _tags = main._ai_complete_link_evaluations(
        'Comparison of PostgreSQL vs Supabase for local LLM vector storage performance benchmarks',
        results,
    )

    assert evaluations[1].startswith('Useful background')
    assert 'Probably skip' not in evaluations[1]
    assert 'performance' in evaluations[1].lower()
    assert '; missing' not in evaluations[1].lower()


def test_compact_evaluation_never_cuts_through_a_word():
    text = ('Worth opening: provides a concrete comparison of retrieval latency, '
            'indexing cost, filtering controls, and production tradeoffs for teams.')
    compact = main._ai_compact_evaluation(text, 90)

    assert len(compact) <= 91
    assert compact.endswith('.')
    assert not compact.endswith('team.')
    assert compact[-2].isalnum()


def test_link_evaluation_uses_novel_preview_detail_instead_of_title():
    results = [{
        'title': 'How to Avoid Stress',
        'url': 'https://medium.com/blog/how-to-avoid-stress',
        'snippet': ('How to avoid stress. The author recommends a four-step breathing '
                    'exercise and keeping a seven-day trigger journal.'),
    }]

    evaluations, _tags = main._ai_complete_link_evaluations(
        'how to avoid stress', results)

    assert evaluations[1].startswith('Worth opening:')
    assert 'four-step breathing' in evaluations[1]
    assert 'directly matches' not in evaluations[1].lower()
    assert len(evaluations[1]) <= 151


def test_link_evaluation_admits_when_preview_adds_nothing():
    evaluations, _tags = main._ai_complete_link_evaluations(
        'how to avoid stress', [{
            'title': 'How to Avoid Stress',
            'url': 'https://example.com/how-to-avoid-stress',
            'snippet': 'In this article we will talk about how to avoid stress.',
        }])

    assert evaluations[1] == 'Direct match, but the preview reveals no detail beyond the title.'


def test_cve_query_excludes_results_for_other_vulnerabilities():
    results = [
        {'title': 'CVE-2026-15741 PostgreSQL SQL injection',
         'url': 'https://nvd.nist.gov/vuln/detail/CVE-2026-15741',
         'snippet': 'CVE-2026-15741 affects expression deparse consumers.'},
        {'title': 'CVE-2026-40415 Windows TCP/IP issue',
         'url': 'https://example.com/CVE-2026-40415',
         'snippet': 'A different remote code execution vulnerability.'},
    ]

    cleaned = main._ai_clean_sources('Explain CVE-2026-15741', results)
    assert [r['url'] for r in cleaned] == [results[0]['url']]
    evaluations, _tags = main._ai_complete_link_evaluations(
        'Explain CVE-2026-15741', results,
        {2: 'Worth opening: describes remote code execution.'},
    )
    assert evaluations[2] == 'Skip: this result concerns a different exact identifier.'


def test_link_evaluation_never_exposes_missing_token_diagnostics():
    compact = main._ai_compact_evaluation(
        'Useful background: PostgreSQL expression parsing; missing 15741/called.'
    )
    assert compact == 'Useful background: PostgreSQL expression parsing.'
    assert 'missing' not in compact.lower()


def test_security_advisory_rules_are_in_standard_and_deep_prompts():
    standard = main._ai_build_messages([], [], report=False)[0]['content']
    deep = main._ai_build_messages([], [], report=True)[0]['content']
    for prompt in (standard, deep):
        assert 'boundary versions contain the fixes' in prompt
        assert 'package status and upstream status separate' in prompt
        assert 'missing/default metadata' in prompt
        assert 'Preserve CVSS vector semantics exactly' in prompt


def test_overview_context_excludes_evaluations_and_ungrounded_previews():
    results = [{
        'title': 'Example advisory', 'url': 'https://example.com/advisory',
        'snippet': 'UNRELIABLE_PREVIEW says version 4 is vulnerable',
        'ai_evaluation': {'summary': 'HALLUCINATED_EVALUATION'},
    }, {
        'title': 'Grounded advisory', 'url': 'https://example.org/advisory',
        'snippet': 'ANOTHER_UNRELIABLE_PREVIEW',
        'content': 'GROUND_TRUTH says versions before 4 are affected.',
        'evaluation': 'ANOTHER_HALLUCINATED_EVALUATION',
    }]

    messages = main._ai_build_messages([], results)
    context = messages[-1]['content']
    assert 'GROUND_TRUTH' in context
    assert 'UNRELIABLE_PREVIEW' not in context
    assert 'HALLUCINATED_EVALUATION' not in context
    assert 'NO PAGE EVIDENCE' in context


def test_exact_identifier_matching_covers_non_cve_queries():
    assert main._ai_exact_identifiers('Read RFC 9110 and CWE-89') == {'RFC-9110', 'CWE-89'}
    assert main._ai_exact_identifiers('GHSA-abcd-1234-wxyz') == {'GHSA-ABCD-1234-WXYZ'}
