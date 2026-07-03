import os
import gzip
import csv
import pickle
import random
import math
import numpy as np
from collections import defaultdict

import xgboost as xgb

from .features import extract_features, FEATURE_FUNCTIONS


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'feature_names.pkl')

ORCAS_QUERIES = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'orcas-doctrain-queries.tsv')
ORCAS_QRELS = os.path.join(DATA_DIR, 'orcas-doctrain-qrels.tsv.gz')
DOCS_CORPUS = os.path.join(DATA_DIR, 'msmarco-docs.tsv.gz')

N_QUERIES = 50000
NEGATIVES_PER_QUERY = 5
NEG_POOL_SIZE = 200000
RANDOM_SEED = 42


def _select_eligible_qids(qrels_path, n_queries):
    qrels = defaultdict(list)
    with gzip.open(qrels_path, 'rt', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4:
                qid, did = parts[0], parts[2]
                rel = int(parts[3])
                if rel > 0:
                    qrels[qid].append(did)

    eligible = [qid for qid, dids in qrels.items() if len(dids) >= 2]
    print(f"  queries with 2+ positive docs: {len(eligible):,}")
    random.seed(RANDOM_SEED)
    sampled = set(random.sample(eligible, min(n_queries, len(eligible))))
    print(f"  sampled {len(sampled)} queries")
    return {qid: dids for qid, dids in qrels.items() if qid in sampled}


def _load_queries_for_qids(path, needed_qids):
    queries = {}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            if len(row) >= 2:
                qid = row[0]
                if qid in needed_qids:
                    query = row[1].strip()
                    if query:
                        queries[qid] = query
    print(f"  loaded {len(queries)} queries for sampled qids")
    return queries


def _load_corpus_with_negatives(path, positive_dids, neg_pool_size):
    docs = {}
    neg_buffer = []
    seen = 0
    reservoir_rng = random.Random(RANDOM_SEED + 1)

    with gzip.open(path, 'rt', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 4:
                continue
            did = parts[0].strip()

            if did in positive_dids:
                docs[did] = {
                    'url': parts[1].strip(),
                    'title': parts[2].strip(),
                    'snippet': parts[3].strip()[:500],
                }
            else:
                seen += 1
                reservoir_rng = random.Random(RANDOM_SEED + 1 + seen)
                if len(neg_buffer) < neg_pool_size:
                    neg_buffer.append(did)
                else:
                    j = reservoir_rng.randint(0, seen - 1)
                    if j < neg_pool_size:
                        neg_buffer[j] = did

    neg_set = set(neg_buffer) - positive_dids
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 4:
                continue
            did = parts[0].strip()
            if did in neg_set:
                docs[did] = {
                    'url': parts[1].strip(),
                    'title': parts[2].strip(),
                    'snippet': parts[3].strip()[:500],
                }

    print(f"  loaded {len(positive_dids & set(docs.keys()))} positive + {len(neg_set & set(docs.keys()))} negative pool docs")
    return docs


def _build_training_data(sampled_qrels, queries, docs):
    random.seed(RANDOM_SEED)

    all_pos_dids = set()
    for dids in sampled_qrels.values():
        all_pos_dids.update(dids)
    neg_candidates = [d for d in docs.keys() if d not in all_pos_dids]
    print(f"  negative candidate pool: {len(neg_candidates):,} docs")

    query_groups = {}
    dropped_no_query = 0
    dropped_few_pos = 0

    for qid, pos_dids in sampled_qrels.items():
        query = queries.get(qid, '')
        if not query:
            dropped_no_query += 1
            continue

        pos_docs = [docs[d] for d in pos_dids if d in docs]
        if len(pos_docs) < 2:
            dropped_few_pos += 1
            continue

        neg_needed = max(NEGATIVES_PER_QUERY, len(pos_docs))
        if len(neg_candidates) >= neg_needed:
            sampled_neg_dids = random.sample(neg_candidates, neg_needed)
        else:
            sampled_neg_dids = random.choices(neg_candidates, k=neg_needed) if neg_candidates else []
        neg_docs = [docs[d] for d in sampled_neg_dids if d in docs]

        group_docs = []
        for d in pos_docs:
            group_docs.append({**d, 'relevance': 1})
        for d in neg_docs:
            group_docs.append({**d, 'relevance': 0})

        query_groups[qid] = {
            'query': query,
            'docs': group_docs,
        }

    if dropped_no_query or dropped_few_pos:
        print(f"  dropped (no query): {dropped_no_query}, (few pos in corpus): {dropped_few_pos}")
    print(f"  built {len(query_groups)} query groups")
    return query_groups


def _extract_features_from_groups(query_groups):
    X_list, y_list, group_list = [], [], []

    for qid, group in query_groups.items():
        query = group['query']
        doc_texts = []
        relevances = []
        for d in group['docs']:
            doc_texts.append({
                'title': d['title'],
                'snippet': d['snippet'],
                'url': d['url'],
            })
            relevances.append(d['relevance'])

        X = extract_features(query, doc_texts)
        if X is None:
            continue

        X_list.append(X)
        y_list.extend(relevances)
        group_list.append(len(relevances))

    if not X_list:
        return None, None, None

    X_all = np.vstack(X_list)
    y_all = np.array(y_list, dtype=np.float32)
    return X_all, y_all, group_list


def run_training(output_dir=None):
    output_dir = output_dir or os.path.dirname(__file__)
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    print("=" * 60)
    print("ML Ranking Training Pipeline (ORCAS)")
    print("Data:    ORCAS click-based + MS MARCO Document Corpus")
    print("Model:   XGBoost LambdaMART (rank:ndcg)")
    print("=" * 60)

    print("\n[1/5] Scanning qrels to sample eligible queries...")
    sampled_qrels = _select_eligible_qids(ORCAS_QRELS, N_QUERIES)
    if len(sampled_qrels) < 10:
        print("ERROR: Too few eligible queries")
        return False

    print("\n[2/5] Loading query text for sampled queries...")
    queries = _load_queries_for_qids(ORCAS_QUERIES, set(sampled_qrels.keys()))
    if len(queries) < 10:
        print("ERROR: Too few queries loaded")
        return False

    print("\n[3/5] Loading documents with negative pool sampling...")
    needed_dids = set()
    for dids in sampled_qrels.values():
        needed_dids.update(dids)
    print(f"  {len(needed_dids):,} unique positive doc IDs needed")
    docs = _load_corpus_with_negatives(DOCS_CORPUS, needed_dids, NEG_POOL_SIZE)
    if len(docs) < 100:
        print("ERROR: Too few docs loaded from corpus")
        return False

    print("\n[4/5] Building training data with negative sampling...")
    query_groups = _build_training_data(sampled_qrels, queries, docs)
    if len(query_groups) < 2:
        print("ERROR: Too few query groups")
        return False

    print("\nExtracting features...")
    X, y, groups = _extract_features_from_groups(query_groups)
    if X is None:
        print("ERROR: Could not extract features")
        return False

    print(f"\nFeature matrix: {X.shape}")
    print(f"Number of query groups: {len(groups)}")
    print(f"Total samples: {len(y)}")
    print(f"Features ({len(FEATURE_FUNCTIONS)}): {FEATURE_FUNCTIONS}")

    rel_counts = np.bincount(y.astype(int))
    print("Relevance distribution:")
    for i, c in enumerate(rel_counts):
        if c > 0:
            print(f"  rel={i}: {c} samples ({c/len(y)*100:.1f}%)")

    if len(groups) < 2:
        print("ERROR: Need at least 2 query groups")
        return False

    group_ids = np.repeat(np.arange(len(groups)), groups)
    unique_gids = np.arange(len(groups))
    np.random.shuffle(unique_gids)
    split_idx = max(1, int(len(unique_gids) * 0.8))
    train_gids = set(unique_gids[:split_idx])
    val_gids = set(unique_gids[split_idx:])

    train_mask = np.array([gid in train_gids for gid in group_ids])
    val_mask = np.array([gid in val_gids for gid in group_ids])

    print(f"\nTrain queries: {len(train_gids)}, Val queries: {len(val_gids)}")
    print(f"Train samples: {np.sum(train_mask)}, Val samples: {np.sum(val_mask)}")

    def _build_group_array(mask):
        groups_out = []
        seen = set()
        for i in range(len(y)):
            if mask[i]:
                gid = group_ids[i]
                if gid not in seen:
                    seen.add(gid)
                    groups_out.append(1)
                else:
                    groups_out[-1] += 1
        return groups_out

    train_groups = _build_group_array(train_mask)
    val_groups = _build_group_array(val_mask)

    print(f"\n[5/5] Training XGBoost LambdaMART...")
    model = xgb.XGBRanker(
        objective='rank:ndcg',
        learning_rate=0.1,
        max_depth=6,
        n_estimators=200,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        reg_alpha=0.1,
        eval_metric=['ndcg@5', 'ndcg@10'],
        random_state=RANDOM_SEED,
        verbosity=1,
    )

    if np.sum(train_mask) > 0 and np.sum(val_mask) > 0:
        model.fit(
            X[train_mask], y[train_mask],
            group=train_groups,
            eval_set=[(X[val_mask], y[val_mask])],
            eval_group=[val_groups],
            verbose=True,
        )

    model_path = os.path.join(output_dir, 'model.pkl')
    features_path = os.path.join(output_dir, 'feature_names.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    with open(features_path, 'wb') as f:
        pickle.dump(FEATURE_FUNCTIONS, f)
    print(f"\nModel saved: {model_path}")

    print("\n--- Test inference ---")
    test_query = "what is python list comprehension"
    test_docs = [
        {'title': 'Python List Comprehensions', 'snippet': 'List comprehensions provide a concise way to create lists in Python. They consist of brackets containing an expression followed by a for clause. They are faster than traditional loops.', 'url': 'https://docs.python.org/3/tutorial/'},
        {'title': 'Python For Loops Guide', 'snippet': 'Python for loops iterate over sequences. You can use range() to repeat a block of code a specific number of times.', 'url': 'https://example.com/loops'},
        {'title': 'Programming Blog Post', 'snippet': 'In this article we will explore the world of programming with Python and learn about various coding techniques.', 'url': 'https://example.com/blog'},
    ]
    X_test = extract_features(test_query, test_docs)
    if X_test is not None:
        scores = model.predict(X_test)
        print(f"Query: '{test_query}'")
        for i, doc in enumerate(test_docs):
            print(f"  [{scores[i]:.4f}] {doc['title']}")

    feature_importance = model.feature_importances_
    print("\nFeature importance:")
    for name, imp in sorted(zip(FEATURE_FUNCTIONS, feature_importance), key=lambda x: -x[1]):
        print(f"  {name}: {imp:.3f}")

    print("\nTraining complete!")
    return True


if __name__ == '__main__':
    run_training()
