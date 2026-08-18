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
