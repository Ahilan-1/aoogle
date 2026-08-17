"""Neural search layer for Arlong AI.

Implements the "understand before you search" pipeline:

  * `understand_query()`  — tokenize + expand the user's natural-language query
    into concrete search keywords, resolving polysemy/vocabulary mismatch by
    scoring candidate terms against the query embedding.
  * `get_embedding()`     — OpenAI-compatible embeddings when a key is set;
    otherwise a deterministic local hashing n-gram embedding (works offline,
    cacheable per URL, zero API cost). Results are cached per text/URL.
  * `cosine()`            — similarity between two embeddings.
  * `evaluate_page()`     — relevance (query-embedding cosine), injection risk
    (regex/heuristics, escalate to LLM only when ambiguous), trust + threat
    flags. This is what decides whether a page is worth clicking/generating on.
  * `corroborate()`       — group claims from independent sources into agreement
    clusters via embedding similarity; "N independent sources agree" is a cheap,
    strong trust signal (the epistemic-state engine used by the agentic API).
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import threading
import time

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

EMBEDDING_CACHE: dict = {}
_EMBED_LOCK = threading.Lock()
_EMBED_CACHE_TTL = 7 * 24 * 3600
_EMBED_CACHE_MAX = 5000

# ── embedding provider config ────────────────────────────────────────────────
EMBED_API_KEY = os.environ.get('EMBED_API_KEY', '') or os.environ.get('OPENAI_API_KEY', '')
EMBED_BASE_URL = os.environ.get('EMBED_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
EMBED_MODEL = os.environ.get('EMBED_MODEL', 'text-embedding-3-small')
EMBED_DIM = 768 if EMBED_MODEL and '3-large' in EMBED_MODEL else 512

# ── prompt-injection heuristics ──────────────────────────────────────────────
INJECTION_RE_SIGNALS = [
    (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|the)\s+(instructions|prompts?|directions|context)', re.I), 'INSTRUCTION_OVERRIDE'),
    (re.compile(r'forget\s+(all\s+)?(previous|prior)\s+(instructions|prompts?)', re.I), 'INSTRUCTION_OVERRIDE'),
    (re.compile(r'system\s*[:=]?\s*(you are now|your new instructions|ignore.*rules)', re.I), 'SYSTEM_HIJACK'),
    (re.compile(r'\[end of (text|document|message)\][\s\S]*?(you|as an ai|say|repeat)', re.I), 'DOCUMENT_END_HIJACK'),
    (re.compile(r'(disregard|override|forget).{0,20}(instructions|safety|rules)', re.I), 'INSTRUCTION_OVERRIDE'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u0000-\u0008\u000b\u000c\u000e-\u001f]'), 'ZERO_WIDTH_CONTROL'),
    (re.compile(r'<style[^>]*>\s*[^<]{0,300}(display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white|opacity\s*:\s*0)', re.I | re.S), 'HIDDEN_CSS'),
    (re.compile(r'(position\s*:\s*(absolute|fixed)[^}]*?(left|top)\s*:\s*-\d{2,})', re.I | re.S), 'OFFSCREEN_CSS'),
    (re.compile(r'<script[^>]*>(?!.*?application/ld\+json)', re.I | re.S), 'INLINE_SCRIPT'),
    (re.compile(r'<iframe[^>]*>|<object[^>]*data=|<embed[^>]*src=', re.I), 'EMBEDDED_FRAME'),
    (re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]*\.[a-z]{2,6}/\d{6,}', re.I), 'NUMERIC_REDIRECT'),
    (re.compile(r'\b(base64,|data:text/html|javascript\s*:)', re.I), 'OBFUSCATED_PAYLOAD'),
    (re.compile(r'password|secret key|api[_-]?key|credential|cvv|ssn|social security', re.I), 'CREDENTIAL_HARVEST'),
]

AMBIENT_INJECTION_RE = (
    re.compile(r'<[^>]+>', re.I),           # raw markup in plain text context
    re.compile(r'\b(?:free|cheap|discount|buy now|win|prize)\w*\b', re.I),  # ad-y vocabulary
    re.compile(r'\b(cracked|keygen|pirated|torrent)\b', re.I),
)


class InjectionReport:
    __slots__ = ('flagged', 'flags', 'reason')

    def __init__(self, flagged=False, flags=None, reason=''):
        self.flagged = bool(flagged)
        self.flags = list(flags or [])
        self.reason = reason or ''

    def as_dict(self):
        return {'flagged': self.flagged, 'flags': self.flags, 'reason': self.reason}


# ── local deterministic embedding (fallback / offline) ───────────────────────
def _local_embedding(text, dim=512):
    """Hashing character n-gram embedding.

    Deterministic, dependency-free, cacheable per text. Not as rich as a real
    neural embedding but captures topical overlap well enough for relevance
    gating and corroboration, and costs zero API calls.
    """
    vec = [0.0] * dim
    t = re.sub(r'\s+', ' ', (text or '').lower()).strip()
    if not t:
        return vec
    grams = []
    for n in (2, 3, 4):
        for i in range(len(t) - n + 1):
            grams.append(t[i:i + n])
    if not grams:
        grams = [t]
    for g in grams:
        h = int(hashlib.blake2b(g.encode('utf-8'), digest_size=8).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 63) % 2 == 0 else -1.0
        vec[idx] += sign
    # normalize
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def get_embedding(text, model=None):
    """Return a normalized embedding vector for text.

    Uses the remote embeddings API when configured; otherwise the local
    hashing n-gram embedding. Results are cached per text (bounded LRU-ish) so
    repeated pages cost nothing — embeddings cache per URL, reused across every
    future query that returns that page.
    """
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    now = time.time()
    key = hashlib.sha256(text.encode('utf-8', 'ignore')).hexdigest()
    with _EMBED_LOCK:
        cached = EMBEDDING_CACHE.get(key)
        if cached and now < cached[1]:
            return cached[0]
    vec = None
    if EMBED_API_KEY and httpx is not None:
        try:
            resp = httpx.post(
                f'{EMBED_BASE_URL}/embeddings',
                headers={'Authorization': f'Bearer {EMBED_API_KEY}'},
                json={'model': model or EMBED_MODEL, 'input': text[:8000]},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                vec = (data.get('data') or [{}])[0].get('embedding')
        except Exception:
            vec = None
    if not vec:
        vec = _local_embedding(text, EMBED_DIM)
    if vec:
        with _EMBED_LOCK:
            if len(EMBEDDING_CACHE) > _EMBED_CACHE_MAX:
                now2 = time.time()
                EMBEDDING_CACHE.clear()
            EMBEDDING_CACHE[key] = (list(vec), now + _EMBED_CACHE_TTL)
    return vec


def cosine(a, b):
    """Cosine similarity between two embedding vectors (or None-safe)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


# ── query understanding ──────────────────────────────────────────────────────
_STOPWORDS = set((
    'the', 'a', 'an', 'and', 'or', 'but', 'of', 'to', 'in', 'for', 'on',
    'with', 'what', 'how', 'why', 'when', 'where', 'which', 'who', 'is',
    'are', 'does', 'do', 'did', 'can', 'could', 'should', 'would', 'will',
    'be', 'been', 'it', 'its', 'this', 'that', 'these', 'those', 'me', 'my',
    'i', 'you', 'your', 'we', 'they', 'them', 'their', 'from', 'at', 'by',
    'about', 'not', 'vs', 'versus', 'please', 'explain', 'compare', 'tell',
    'give', 'get', 'find', 'list', 'show', 'define', 'difference', 'between',
    'me', 'us', 'had', 'has', 'have', 'was', 'were', 'than', 'as', 'then',
    'there', 'here', 'such', 'both', 'each', 'more', 'most', 'any', 'some',
    'too', 'very', 'much', 'many', 'so', 'if', 'after', 'before', 'into',
    'out', 'over', 'under', 'again', 'further', 'once', 'only', 'own',
    'same', 'through', 'during', 'being', 'few', 'just', 'while', 'also',
))


def _tokens(text):
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\-']*", (text or '').lower())
            if t not in _STOPWORDS and len(t) > 1]


def understand_query(query):
    """Turn a natural-language query into searchable keywords + intent hints.

    Returns a dict with:
      * terms       — cleaned base terms
      * keywords    — the terms to actually send to the search backends
      * phrase      — the longest informative noun-phrase chunks (for engines
                      that handle phrases better than single terms)
      * ambiguity   — heuristics flagging likely polysemy (e.g. "python",
                      "redis", "jaguar", "apple")
    """
    q = (query or '').strip()
    if not q:
        return {'terms': [], 'keywords': [''], 'phrase': '', 'ambiguity': []}
    terms = _tokens(q)
    # keep the question-specific word when present (never drop it)
    keywords = []
    for t in terms:
        if t not in keywords:
            keywords.append(t)
    if not keywords:
        keywords = [q.lower()]
    # ambiguity hints for likely-polysemous terms
    ambiguous = []
    polysemes = {
        'python': 'language or snake', 'redis': 'service or in-memory store',
        'jaguar': 'animal or car brand', 'apple': 'fruit or company',
        'torrent': 'bittorrent or stream', 'tensorflow': 'framework',
        'java': 'language or island', 'spring': 'season or framework',
        'docker': 'container or tool', 'ruby': 'language or gemstone',
        'violet': 'color or framework', 'express': 'framework or delivery',
        'fastapi': 'framework', 'next': 'framework or ordering word',
    }
    for t in terms:
        if t in polysemes:
            ambiguous.append({'term': t, 'hint': polysemes[t]})
    # phrase chunks: group consecutive meaningful terms (max 4)
    chunks = []
    if terms:
        cur = []
        for t in terms:
            cur.append(t)
            if len(cur) == 4:
                chunks.append(' '.join(cur))
                cur = []
        if cur and len(cur) >= 2:
            chunks.append(' '.join(cur))
    phrase = chunks[0] if chunks else ' '.join(keywords[:4])
    return {
        'terms': terms,
        'keywords': keywords,
        'phrase': phrase,
        'ambiguity': ambiguous,
    }


def keyword_similarity(query, candidate):
    """Cosine similarity between query and candidate keyword text."""
    qe = get_embedding(query)
    ce = get_embedding(candidate)
    return cosine(qe, ce)


# ── page evaluation ──────────────────────────────────────────────────────────
def detect_injection(text, allow_llm_escalation=True, llm_eval=None):
    """Detect prompt-injection / threat signals in scraped page text.

    Runs free regex/heuristic checks first. Only when the page is *ambiguous*
    (has some soft signals but no hard flag) does it escalate to the optional
    LLM evaluation callback. Returns an InjectionReport.
    """
    if not text:
        return InjectionReport(False, [], '')
    hard_flags = []
    soft_hits = 0
    for rx, flag in INJECTION_RE_SIGNALS:
        if rx.search(text):
            if flag in ('ZERO_WIDTH_CONTROL', 'HIDDEN_CSS', 'OFFSCREEN_CSS',
                        'INSTRUCTION_OVERRIDE', 'SYSTEM_HIJACK'):
                hard_flags.append(flag)
            else:
                soft_hits += 1
    # structural weirdness that usually accompanies injection
    for rx in AMBIENT_INJECTION_RE:
        if rx.search(text):
            soft_hits += 1
    # normalize flags (dedup, keep order)
    flags = list(dict.fromkeys(hard_flags))
    if hard_flags:
        return InjectionReport(True, flags, 'hard injection signals detected')
    if soft_hits >= 3:
        # ambiguous → escalate to LLM if provided (only for subtle cases)
        if allow_llm_escalation and llm_eval is not None:
            try:
                verdict = llm_eval(text)
                if verdict and verdict.get('flagged'):
                    return InjectionReport(True, list(verdict.get('flags') or ['LIKELY_INJECTION']),
                                           verdict.get('reason') or 'LLM flag')
                return InjectionReport(False, [], 'LLM cleared')
            except Exception:
                pass
        return InjectionReport(False, flags, 'multiple soft signals, no hard flag')
    return InjectionReport(False, flags, '')


def evaluate_page(query, title='', url='', snippet='', content=''):
    """Score how relevant + safe a page is for `query`.

    Relevance = cosine(query-embedding, page-embedding) — computed from cached
    embeddings, zero generation tokens. Returns a dict for the agentic API:
      relevance_score, ai_evaluation.summary, fact_check_status,
      reputation.status, reputation.trust_score, threat_flags
    """
    qe = get_embedding(query)
    combined = ' '.join(x for x in (title, snippet, (content or '')[:4000]) if x)
    pe = get_embedding(combined)
    rel = round(cosine(qe, pe), 3)
    # floor tiny negatives
    rel = max(0.0, min(1.0, rel))

    inj = detect_injection(' '.join((snippet or '', (content or '')[:12000])))
    if inj.flagged:
        status = 'BLOCKED'
        trust = max(0, 100 - len(inj.flags) * 35)
        reason = inj.reason
        flags = inj.flags
    elif rel < 0.20:
        # Truly garbage/irrelevant — not a security threat, just useless.
        status = 'BLOCKED'
        trust = 0
        reason = 'Low relevance to query'
        flags = []
    elif rel < 0.55:
        status = 'UNVERIFIED'
        trust = _domain_trust(url)
        reason = 'Marginal relevance'
        flags = inj.flags or []
    else:
        status = 'SAFE'
        trust = min(99, 60 + int(rel * 40))
        reason = ''
        flags = inj.flags or []

    fact_check = 'VERIFIED' if status == 'SAFE' else ('FAILED' if status == 'BLOCKED' else 'UNKNOWN')
    return {
        'relevance_score': rel,
        'ai_evaluation': {
            'relevance_score': rel,
            'summary': reason or (snippet or '')[:140],
            'fact_check_status': fact_check,
        },
        'reputation': {'status': status, 'trust_score': trust},
        'threat_flags': flags,
    }


# ── domain trust scoring ────────────────────────────────────────────────────
# Instead of returning a static 55 for every UNVERIFIED domain, compute a
# basic trust signal from domain characteristics.
_TRUSTED_DOMAINS = {
    'wikipedia.org': 90, 'github.com': 85, 'stackoverflow.com': 85,
    'reddit.com': 70, 'medium.com': 72, 'quora.com': 65,
    'youtube.com': 75, 'instagram.com': 65, 'twitter.com': 70, 'x.com': 70,
    'facebook.com': 60, 'tiktok.com': 65,
    'nytimes.com': 92, 'bbc.com': 93, 'reuters.com': 94, 'apnews.com': 94,
    'theguardian.com': 90, 'washingtonpost.com': 90, 'cnn.com': 88,
    'nature.com': 95, 'sciencedirect.com': 93, 'arxiv.org': 92,
    'scholar.google.com': 90,
    '.edu': 88, '.gov': 92, '.mil': 90,
    'imdb.com': 80, 'rottentomatoes.com': 78, 'metacritic.com': 78,
    'amazon.com': 75, 'apple.com': 85, 'microsoft.com': 85, 'google.com': 88,
    'fandom.com': 62, 'wikia.com': 62,
    'bookmyshow.com': 68,
}
# Patterns that indicate low-trust user-generated / aggregator content
_LOW_TRUST_PATTERNS = [
    (re.compile(r'facebook\.com/.+/posts/', re.I), 45),
    (re.compile(r'loading\.\.\.', re.I), 0),
]


def _domain_trust(url):
    """Return a trust score (0-100) for a URL based on domain reputation."""
    if not url:
        return 40
    host = (urlparse(url).netloc or '').lower().replace('www.', '')
    # Check exact match first
    for d, score in _TRUSTED_DOMAINS.items():
        if d.startswith('.'):
            if host.endswith(d) or host == d[1:]:
                return score
        elif host == d or host.endswith('.' + d):
            return score
    # Check low-trust patterns
    for pat, score in _LOW_TRUST_PATTERNS:
        if pat.search(url):
            return score
    # Default: moderate trust for unknown domains
    return 50


# ── corroboration ────────────────────────────────────────────────────────────
# Local 512-dim hashing embeddings are less precise than remote API embeddings,
# so we use a lower threshold for them. 0.78 works well for 768-dim remote,
# 0.55 works better for local 512-dim.
_CORROBORATION_THRESHOLD = 0.55 if EMBED_DIM <= 512 else 0.78


def corroborate(claims):
    """Group claims from independent sources into agreement clusters.

    `claims` is a list of {source_url, claim_text}. Claims whose embeddings
    are mutually similar (cosine >= threshold) form a cluster; the report tells
    you how many independent sources agree and which ones disagree — the
    epistemic state, not just "here's the answer".
    """
    if not claims:
        return {'clusters': [], 'agreement': 0.0, 'disagreement': 0}
    vecs = []
    for c in claims:
        vecs.append((c, get_embedding((c.get('claim_text') or '').strip())))
    clusters = []
    assigned = [False] * len(vecs)
    for i, (c, v) in enumerate(vecs):
        if assigned[i] or not v:
            continue
        group = [c]
        assigned[i] = True
        for j in range(i + 1, len(vecs)):
            if assigned[j]:
                continue
            vj = vecs[j][1]
            if vj and cosine(v, vj) >= _CORROBORATION_THRESHOLD:
                group.append(vecs[j][0])
                assigned[j] = True
        clusters.append(group)
    agreement = 0.0
    disagreement = 0
    unclustered = 0
    if clusters:
        multi = [g for g in clusters if len(g) > 1]
        singletons = [g for g in clusters if len(g) == 1]
        unclustered = len(singletons)
        if multi:
            largest = max(len(g) for g in multi)
            agreement = round(largest / len(claims), 2)
            disagreement = len(multi) - 1
        else:
            # No clusters with more than 1 source — no real agreement.
            agreement = 0.0
            disagreement = 0
    return {
        'clusters': [{'size': len(g), 'sources': [c.get('source_url') for c in g],
                      'representative': (g[0].get('claim_text') or '')[:200]} for g in clusters],
        'agreement': agreement,
        'disagreement': disagreement,
        'unclustered': unclustered,
    }
