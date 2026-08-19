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
    assert 'llm' in evaluations[1].lower() or 'vector' in evaluations[1].lower()


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
