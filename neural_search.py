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
import base64
import html
import math
import os
import re
import socket
import threading
import time
import ipaddress
import unicodedata
from urllib.parse import urlparse

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

# High-signal, model-directed behavior. These patterns intentionally require
# an action or instruction near the sensitive target so ordinary pages that
# merely mention passwords, APIs, or prompt injection are not blocked.
BEHAVIOR_RE_SIGNALS = [
    (re.compile(r'\b(?:send|upload|post|transmit|exfiltrat\w*|forward)\b.{0,90}\b(?:secret|token|password|credential|api[_ -]?key|environment variable|\.env|private key|seed phrase)\b', re.I | re.S), 'SECRET_EXFILTRATION', 6),
    (re.compile(r'\b(?:enter|provide|paste|submit|verify|reveal)\b.{0,70}\b(?:password|credential|api[_ -]?key|private key|seed phrase|recovery phrase|cvv|social security)\b', re.I | re.S), 'CREDENTIAL_SOLICITATION', 5),
    (re.compile(r'\b(?:run|execute|invoke|call|use)\b.{0,60}\b(?:shell|terminal|command|tool|function|powershell|bash|cmd(?:\.exe)?)\b', re.I | re.S), 'TOOL_EXECUTION_REQUEST', 4),
    (re.compile(r'\b(?:download|install)\b.{0,80}\b(?:and|then)\b.{0,30}\b(?:run|execute|open)\b', re.I | re.S), 'DOWNLOAD_EXECUTE', 5),
    (re.compile(r'\b(?:do not|never)\b.{0,35}\b(?:tell|inform|mention|reveal)\b.{0,40}\b(?:user|developer|operator|human)\b', re.I | re.S), 'HIDE_FROM_USER', 4),
    (re.compile(r'(?:^|\n)\s*(?:system|assistant|developer|tool)\s*(?:message)?\s*:', re.I), 'ROLE_IMPERSONATION', 4),
    (re.compile(r'<\|(?:system|assistant|developer|tool|im_start|im_end)[^>]*\|>|\[/?(?:system|assistant|developer|tool)\]', re.I), 'MODEL_CONTROL_TOKEN', 5),
]

_SECURITY_CACHE = {}
_SECURITY_CACHE_LOCK = threading.Lock()
_SECURITY_CACHE_MAX = 10000
_SECURITY_SCAN_LIMIT = 48000
DETECTOR_VERSION = '3.0'

AMBIENT_INJECTION_RE = (
    re.compile(r'<[^>]+>', re.I),           # raw markup in plain text context
    re.compile(r'\b(?:free|cheap|discount|buy now|win|prize)\w*\b', re.I),  # ad-y vocabulary
    re.compile(r'\b(cracked|keygen|pirated|torrent)\b', re.I),
)


class InjectionReport:
    __slots__ = ('flagged', 'flags', 'reason', 'risk_score', 'action', 'scanned_chars')

    def __init__(self, flagged=False, flags=None, reason='', risk_score=0,
                 action=None, scanned_chars=0):
        self.flagged = bool(flagged)
        self.flags = list(flags or [])
        self.reason = reason or ''
        self.risk_score = max(0, min(int(risk_score or 0), 100))
        self.action = action or ('block' if self.flagged else ('review' if self.risk_score else 'allow'))
        self.scanned_chars = int(scanned_chars or 0)

    def as_dict(self):
        return {
            'flagged': self.flagged, 'flags': self.flags, 'reason': self.reason,
            'risk_score': self.risk_score, 'action': self.action,
            'scanned_chars': self.scanned_chars, 'detector_version': DETECTOR_VERSION,
        }


def _security_canonical_forms(raw):
    """Return bounded, detector-only views resilient to common obfuscation.

    This deliberately does not alter the text returned to users. It gives the
    detector a normalized view of HTML entities, Unicode compatibility forms,
    zero-width controls, and percent-encoded fragments.
    """
    source = str(raw or '')[:_SECURITY_SCAN_LIMIT]
    decoded = html.unescape(source)
    normalized = unicodedata.normalize('NFKC', decoded)
    normalized = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff\x00-\x1f]', ' ', normalized)
    try:
        from urllib.parse import unquote
        normalized = unquote(normalized)
    except Exception:
        pass
    # Preserve the raw form for DOM/CSS signals and scan a whitespace-collapsed
    # form for instructions split by markup or invisible characters.
    compact = re.sub(r'\s+', ' ', normalized).strip()
    forms = [source, compact]
    for token in re.findall(r'(?:base64,|base64\s*[:=]\s*)([A-Za-z0-9+/]{24,}={0,2})', source, re.I):
        try:
            candidate = base64.b64decode(token, validate=False).decode('utf-8', 'ignore')
            if candidate:
                forms.append(candidate[:8000])
        except Exception:
            pass
    return forms


_CONCEALED_HTML_RE = re.compile(
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[.;}\s]|$)|'
    r'font-size\s*:\s*(?:0|1)px|color\s*:\s*transparent|'
    r'rgba\([^)]*,\s*0(?:\.0+)?\s*\)|left\s*:\s*-\d{2,}|top\s*:\s*-\d{2,})',
    re.I,
)


def _has_concealed_instruction(raw, canonical):
    """Detect instruction-shaped text placed in HTML that is hidden to readers."""
    if not _CONCEALED_HTML_RE.search(raw or ''):
        return False
    return bool(re.search(
        r'\b(?:ignore|disregard|override|forget|follow|execute|run|reveal|send|upload)\b.{0,160}'
        r'\b(?:instruction|prompt|rule|system|assistant|tool|command|secret|credential|user)\b',
        canonical or '', re.I | re.S,
    ))


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


def assess_search_coverage(query, results, minimum_score=0.26):
    """Semantically judge whether a result set answers a search request.

    A single embedding is built for the query and compared to each title,
    snippet, and URL record. The score is blended with meaningful-term coverage
    so a generic page such as "How to Survive" cannot pass a query about a
    crowd stampede just because it shares an action verb.

    Returns small, serializable diagnostics. Callers should fall back to a
    second provider when ``sufficient`` is false. Embeddings are cached, so the
    same query/results do not repeatedly incur embedding work.
    """
    q = (query or '').strip()
    query_terms = set(_tokens(q))
    if not q or not results:
        return {'sufficient': False, 'reason': 'no_results', 'best_score': 0.0,
                'relevant_count': 0, 'scores': []}
    q_embedding = get_embedding(q)
    # Estimate every query term's discriminative value from THIS result set.
    # Terms appearing on almost every candidate carry little routing evidence;
    # rare query terms carry more. This is IDF-style constraint coverage, not a
    # manually maintained list of verbs, domains, or safety topics.
    corpus_terms = []
    normalized = []
    for item in list(results)[:12]:
        if isinstance(item, dict):
            title = str(item.get('title') or '')
            snippet = str(item.get('snippet') or item.get('description') or '')
            url = str(item.get('url') or '')
        else:
            title = str(getattr(item, 'title', '') or '')
            snippet = str(getattr(item, 'snippet', '') or '')
            url = str(getattr(item, 'url', '') or '')
        text = f'{title}\n{snippet}\n{url}'[:3000]
        normalized.append(text)
        corpus_terms.append(set(_tokens(text)))
    n_docs = len(normalized)
    idf = {
        term: math.log((n_docs + 1) / (1 + sum(term in doc for doc in corpus_terms))) + 1.0
        for term in query_terms
    }
    idf_total = sum(idf.values()) or 1.0
    scores = []
    for text, result_terms in zip(normalized, corpus_terms):
        semantic = max(0.0, cosine(q_embedding, get_embedding(text)))
        constraint_coverage = sum(idf[term] for term in query_terms if term in result_terms) / idf_total
        # Embeddings handle synonymy and phrasing; adaptive constraint coverage
        # prevents generic pages from winning due to similar prose alone.
        score = round(semantic * 0.65 + constraint_coverage * 0.35, 4)
        scores.append((score, constraint_coverage))
    ranked = sorted((score for score, _anchor in scores), reverse=True)
    relevant = sum(1 for score, constraint_coverage in scores
                   if score >= minimum_score and constraint_coverage >= 0.45)
    best = ranked[0] if ranked else 0.0
    # Required corroboration grows with independent query constraints rather
    # than a fixed “three good links” heuristic. A one-term navigation request
    # needs one strong hit; a multi-constraint request needs multiple matches.
    required = max(1, min(n_docs, int(math.ceil(math.log2(len(query_terms) + 1)))))
    sufficient = best >= max(minimum_score, 0.32) and relevant >= required
    reason = 'semantic_coverage_ok' if sufficient else 'weak_semantic_coverage'
    return {
        'sufficient': sufficient,
        'reason': reason,
        'best_score': round(best, 4),
        'relevant_count': relevant,
        'required_relevant': required,
        'scores': [score for score, _anchor in scores],
        'embedding_backend': 'remote' if EMBED_API_KEY else 'local_hashing',
    }


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
def _url_threat_flags(url):
    """Cheap URL deception checks. Flags are signals, not reputation claims."""
    if not url:
        return []
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        flags = []
        if parsed.scheme not in ('http', 'https'):
            flags.append('UNSAFE_URL_SCHEME')
        if parsed.username or parsed.password:
            flags.append('URL_USERINFO_DECEPTION')
        if host.startswith('xn--') or '.xn--' in host:
            flags.append('PUNYCODE_HOST')
        try:
            ipaddress.ip_address(host.strip('[]'))
            flags.append('IP_LITERAL_HOST')
        except ValueError:
            pass
        if parsed.port and parsed.port not in (80, 443):
            flags.append('UNUSUAL_PORT')
        raw = str(url)
        if raw.count('%') >= 5 or re.search(r'%0[ad]|%25(?:2f|5c)|%u[0-9a-f]{4}', raw, re.I):
            flags.append('URL_ENCODING_EVASION')
        if re.search(r'\.(?:exe|msi|scr|bat|cmd|ps1|jar|apk)(?:$|[?#])', parsed.path, re.I):
            flags.append('EXECUTABLE_DOWNLOAD')
        return list(dict.fromkeys(flags))
    except Exception:
        return ['MALFORMED_URL']


def detect_injection(text, allow_llm_escalation=True, llm_eval=None, url=''):
    """Detect prompt-injection / threat signals in scraped page text.

    Runs free regex/heuristic checks first. Only when the page is *ambiguous*
    (has some soft signals but no hard flag) does it escalate to the optional
    LLM evaluation callback. Returns an InjectionReport.
    """
    raw = str(text or '')
    forms = _security_canonical_forms(raw)
    scan = forms[1] if len(forms) > 1 else raw[:_SECURITY_SCAN_LIMIT]
    classifier_mode = 'secondary' if allow_llm_escalation and llm_eval is not None else 'local'
    cache_key = hashlib.sha256(
        (DETECTOR_VERSION + '\0' + url + '\0' + classifier_mode + '\0' + scan).encode('utf-8', 'ignore')).hexdigest()
    with _SECURITY_CACHE_LOCK:
        cached = _SECURITY_CACHE.get(cache_key)
    if cached:
        return InjectionReport(**cached)

    weighted_flags = []
    risk = 0
    soft_hits = 0
    educational_context = bool(re.search(
        r'\b(?:prompt injection|security research|attack example|example attack|detection rule|red team|threat model)\b',
        scan, re.I))
    raw_scan = forms[0]
    for rx, flag in INJECTION_RE_SIGNALS:
        if any(rx.search(form) for form in forms):
            if flag in ('ZERO_WIDTH_CONTROL', 'HIDDEN_CSS', 'OFFSCREEN_CSS',
                        'INSTRUCTION_OVERRIDE', 'SYSTEM_HIJACK'):
                weight = 5 if flag in ('INSTRUCTION_OVERRIDE', 'SYSTEM_HIJACK') else 3
                if educational_context and flag in ('INSTRUCTION_OVERRIDE', 'SYSTEM_HIJACK'):
                    weight = 3
                weighted_flags.append((flag, weight))
                risk += weight
            else:
                soft_hits += 1
    for rx, flag, weight in BEHAVIOR_RE_SIGNALS:
        if any(rx.search(form) for form in forms):
            weighted_flags.append((flag, weight))
            risk += weight
    # A directive hidden from a human reader is materially different from a
    # security article quoting one. Treat concealment + model-direction as a
    # high-confidence boundary violation before synthesis.
    if _has_concealed_instruction(raw_scan, scan):
        weighted_flags.append(('CONCEALED_INSTRUCTION', 7))
        risk += 7
    url_flags = _url_threat_flags(url)
    for flag in url_flags:
        weight = 5 if flag in ('UNSAFE_URL_SCHEME', 'URL_USERINFO_DECEPTION',
                               'EXECUTABLE_DOWNLOAD') else 2
        weighted_flags.append((flag, weight))
        risk += weight
    # structural weirdness that usually accompanies injection
    for rx in AMBIENT_INJECTION_RE:
        if any(rx.search(form) for form in forms):
            soft_hits += 1
    if soft_hits >= 3:
        weighted_flags.append(('MULTIPLE_SUSPICIOUS_SIGNALS', 2))
        risk += 2

    flags = list(dict.fromkeys(flag for flag, _weight in weighted_flags))
    # Convert the small additive score into a stable public 0-100 risk value.
    public_risk = min(100, risk * 12)
    flagged = risk >= 5 or any(f in flags for f in (
        'SECRET_EXFILTRATION', 'CREDENTIAL_SOLICITATION', 'MODEL_CONTROL_TOKEN',
        'DOWNLOAD_EXECUTE', 'EXECUTABLE_DOWNLOAD', 'URL_USERINFO_DECEPTION'))
    flagged = flagged or 'CONCEALED_INSTRUCTION' in flags
    reason = 'high-confidence model or browser threat signals detected' if flagged else ''

    if not flagged and risk in (3, 4):
        # ambiguous → escalate to LLM if provided (only for subtle cases)
        if allow_llm_escalation and llm_eval is not None:
            try:
                verdict = llm_eval(scan)
                if verdict and verdict.get('flagged'):
                    flagged = True
                    flags = list(dict.fromkeys(flags + list(verdict.get('flags') or ['LIKELY_INJECTION'])))
                    public_risk = max(public_risk, 72)
                    reason = verdict.get('reason') or 'secondary classifier flag'
            except Exception:
                pass
    report = InjectionReport(flagged, flags, reason, public_risk,
                             'block' if flagged else ('review' if risk else 'allow'), len(scan))
    cached_value = {
        'flagged': report.flagged, 'flags': report.flags, 'reason': report.reason,
        'risk_score': report.risk_score, 'action': report.action,
        'scanned_chars': report.scanned_chars,
    }
    with _SECURITY_CACHE_LOCK:
        if len(_SECURITY_CACHE) >= _SECURITY_CACHE_MAX:
            _SECURITY_CACHE.clear()
        _SECURITY_CACHE[cache_key] = cached_value
    return report


def evaluate_page(query, title='', url='', snippet='', content='', security_report=None):
    """Score how relevant + safe a page is for `query`.

    Relevance = cosine(query-embedding, page-embedding) — computed from cached
    embeddings, zero generation tokens. Returns a dict for the agentic API:
      relevance_score, ai_evaluation.summary, fact_check_status,
      reputation.status, reputation.trust_score, threat_flags
    """
    qe = get_embedding(query)
    combined = ' '.join(x for x in (title, url, snippet, (content or '')[:4000]) if x)
    pe = get_embedding(combined)
    semantic_rel = max(0.0, cosine(qe, pe))
    # Hash embeddings understate exact topical matches. Blend in lexical
    # coverage so good official pages do not all appear "marginal".
    q_terms = {t for t in re.findall(r'[a-z0-9]{2,}', (query or '').lower())
               if t not in {'the', 'and', 'for', 'what', 'with', 'from', 'this', 'that'}}
    page_low = combined.lower()
    coverage = (sum(1 for t in q_terms if t in page_low) / len(q_terms)) if q_terms else 0.0
    phrase_bonus = 0.12 if (query or '').lower() in page_low else 0.0
    rel = round(min(1.0, semantic_rel * 0.30 + coverage * 0.70 + phrase_bonus), 3)
    # floor tiny negatives
    rel = max(0.0, min(1.0, rel))

    inj = security_report or detect_injection(
        ' '.join((title or '', snippet or '', (content or '')[:12000])), url=url
    )
    if inj.flagged:
        status = 'BLOCKED'
        # Blocked sources must always score below UNVERIFIED (55) and unknown (50).
        trust = max(0, 30 - len(inj.flags) * 15)
        reason = inj.reason
        flags = inj.flags
    elif rel < 0.15:
        # Truly garbage/irrelevant — not a security threat, just useless.
        status = 'BLOCKED'
        trust = 0
        reason = 'Low relevance to query'
        flags = []
    elif rel < 0.30:
        status = 'UNVERIFIED'
        trust = _domain_trust(url)
        reason = 'Low relevance'
        flags = inj.flags or []
    elif rel < 0.42:
        status = 'RELEVANT'
        trust = _domain_trust(url)
        reason = ''
        flags = inj.flags or []
    else:
        status = 'SAFE'
        trust = min(99, 60 + int(rel * 40))
        reason = ''
        flags = inj.flags or []

    fact_check = 'UNVERIFIED' if status in ('SAFE', 'RELEVANT') else ('FAILED' if status == 'BLOCKED' else 'UNKNOWN')
    return {
        'relevance_score': rel,
        'ai_evaluation': {
            'relevance_score': rel,
            'summary': reason or (snippet or '')[:140],
            'fact_check_status': fact_check,
        },
        'reputation': {'status': status, 'trust_score': trust},
        'threat_flags': flags,
        'security_analysis': inj.as_dict(),
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
_CORROBORATION_THRESHOLD = 0.32 if EMBED_DIM <= 512 else 0.58


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
        group_vecs = [v]
        for j in range(i + 1, len(vecs)):
            if assigned[j]:
                continue
            vj = vecs[j][1]
            centroid = [sum(vals) / len(vals) for vals in zip(*group_vecs)]
            left_terms = set(re.findall(r'[a-z0-9]{3,}', ' '.join(x.get('claim_text', '') for x in group).lower()))
            right_terms = set(re.findall(r'[a-z0-9]{3,}', (vecs[j][0].get('claim_text') or '').lower()))
            overlap = len(left_terms & right_terms) / max(1, min(len(left_terms), len(right_terms)))
            if vj and (cosine(centroid, vj) >= _CORROBORATION_THRESHOLD or overlap >= 0.35):
                group.append(vecs[j][0])
                group_vecs.append(vj)
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
