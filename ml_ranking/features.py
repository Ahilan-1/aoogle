import re
import math
import numpy as np
from collections import Counter
from urllib.parse import urlparse


def _tokenize(text):
    if not text:
        return []
    text = text.lower()
    tokens = re.findall(r'\w+', text)
    return tokens


def _term_frequency(tokens):
    return Counter(tokens)


def _compute_bm25(query_tokens, doc_tokens, avg_dl=200, k1=1.5, b=0.75):
    doc_len = len(doc_tokens)
    if doc_len == 0:
        return 0.0
    doc_tf = _term_frequency(doc_tokens)
    query_tf = _term_frequency(query_tokens)
    score = 0.0
    n_docs = 1000000
    for qt in set(query_tokens):
        tf = doc_tf.get(qt, 0)
        if tf == 0:
            continue
        idf = math.log((n_docs - 0 + 0.5) / (0 + 0.5) + 1)
        score += idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * doc_len / avg_dl))
    return score


def _compute_tfidf_cosine(query_tokens, doc_tokens):
    q_tf = _term_frequency(query_tokens)
    d_tf = _term_frequency(doc_tokens)
    all_terms = set(q_tf.keys()) | set(d_tf.keys())
    q_vec = []
    d_vec = []
    for t in all_terms:
        q_vec.append(q_tf.get(t, 0))
        d_vec.append(d_tf.get(t, 0))
    q_norm = math.sqrt(sum(v*v for v in q_vec)) or 1
    d_norm = math.sqrt(sum(v*v for v in d_vec)) or 1
    dot = sum(a*b for a,b in zip(q_vec, d_vec))
    return dot / (q_norm * d_norm)


def _query_term_overlap(query_tokens, doc_tokens, text):
    q_set = set(query_tokens)
    d_set = set(doc_tokens)
    overlap = len(q_set & d_set)
    overlap_ratio = overlap / max(len(q_set), 1)
    exact_phrase = 1.0 if ' '.join(query_tokens) in text.lower() else 0.0
    return overlap, overlap_ratio, exact_phrase


def _doc_length_stats(tokens):
    return {
        'word_count': len(tokens),
        'char_count': sum(len(t) for t in tokens),
        'avg_word_len': np.mean([len(t) for t in tokens]) if tokens else 0,
        'unique_ratio': len(set(tokens)) / max(len(tokens), 1),
    }


def _readability_score(text):
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return 0, 0, 0
    words = _tokenize(text)
    avg_sentence_len = len(words) / max(len(sentences), 1)
    syllable_count = sum(max(1, len(re.findall(r'[aeiouy]+', w.lower()))) for w in words)
    if len(words) == 0:
        return 0, 0, 0
    flesch = 206.835 - 1.015 * avg_sentence_len - 84.6 * (syllable_count / len(words))
    return flesch, avg_sentence_len, len(sentences)


def _title_relevance(query_tokens, title):
    title_tokens = _tokenize(title or '')
    title_overlap = len(set(query_tokens) & set(title_tokens))
    title_overlap_ratio = title_overlap / max(len(query_tokens), 1)
    q_lower = ' '.join(query_tokens)
    exact_in_title = 1.0 if q_lower in (title or '').lower() else 0.0
    return title_overlap, title_overlap_ratio, exact_in_title


def _domain_features(url):
    try:
        parsed = urlparse(url or '')
        domain = parsed.netloc.lower()
        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        path_depth = len([p for p in parsed.path.split('/') if p])
        has_params = 1.0 if parsed.query else 0.0
        domain_len = len(domain)
        return tld, path_depth, has_params, domain_len
    except:
        return '', 0, 0.0, 0


FEATURE_FUNCTIONS = [
    'bm25', 'tfidf_cosine', 'term_overlap', 'term_overlap_ratio',
    'exact_phrase_match', 'word_count', 'char_count',
    'avg_word_len', 'unique_ratio', 'flesch_score',
    'avg_sentence_len', 'num_sentences',
    'title_overlap', 'title_overlap_ratio', 'exact_title_match',
    'path_depth', 'has_url_params', 'domain_len',
    'query_length', 'doc_token_overlap_pct',
]


def extract_features(query, documents, feature_names=None):
    query_tokens = _tokenize(query)
    if not query_tokens:
        return None

    rows = []
    for doc in documents:
        title = doc.get('title', '')
        snippet = doc.get('snippet', '')
        url = doc.get('url', '')
        page_content = doc.get('page_content', '')
        text = page_content or f"{title} {snippet}"
        doc_tokens = _tokenize(text)

        if not doc_tokens:
            doc_tokens = query_tokens[:]

        bm25 = _compute_bm25(query_tokens, doc_tokens)
        tfidf = _compute_tfidf_cosine(query_tokens, doc_tokens)
        overlap, overlap_ratio, exact_phrase = _query_term_overlap(query_tokens, doc_tokens, text)
        dl = _doc_length_stats(doc_tokens)
        flesch, avg_sent_len, num_sents = _readability_score(text)
        title_overlap, title_overlap_ratio, exact_title = _title_relevance(query_tokens, title)
        tld, path_depth, has_params, domain_len = _domain_features(url)

        overlap_pct = overlap / max(len(query_tokens), 1) * 100

        row = [
            bm25,
            tfidf,
            overlap,
            overlap_ratio,
            exact_phrase,
            dl['word_count'],
            dl['char_count'],
            dl['avg_word_len'],
            dl['unique_ratio'],
            flesch,
            avg_sent_len,
            num_sents,
            title_overlap,
            title_overlap_ratio,
            exact_title,
            path_depth,
            has_params,
            domain_len,
            len(query_tokens),
            overlap_pct,
        ]
        rows.append(row)

    X = np.array(rows, dtype=np.float32)
    if feature_names is not None:
        missing = set(FEATURE_FUNCTIONS) - set(feature_names)
        if missing:
            pad = np.zeros((X.shape[0], len(missing)), dtype=np.float32)
            X = np.hstack([X, pad])
    return X
