import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")
RAW1 = os.path.join(RESULTS, "raw")
RAW2 = os.path.join(RESULTS, "raw_queries2")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def scores_map(path):
    s = load(path)
    out = {}
    for k, v in s.items():
        eng, qid = k.split("|", 1)
        out[(eng, qid)] = v
    return out


def build_benchmark(idx, out_file, queries_file, judge_file, raw_dir, name):
    records = load(os.path.join(RESULTS, out_file))
    qdata = load(queries_file)
    scores = scores_map(os.path.join(RESULTS, judge_file))

    queries = []
    for q in qdata["queries"]:
        queries.append({
            "id": q["id"],
            "query": q["query"],
            "category": q.get("category", ""),
            "expected": q.get("expected", []),
        })
    qby = {q["id"]: q for q in queries}

    by_key = {}
    for r in records:
        key = (r["engine"], r["query_id"], r["mode"])
        by_key[key] = r

    enriched = []
    for (eng, qid, mode), r in by_key.items():
        rec = {
            "query_id": qid,
            "query": r["query"],
            "category": qby.get(qid, {}).get("category", ""),
            "expected": qby.get(qid, {}).get("expected", []),
            "engine": eng,
            "mode": mode,
            "latency_s": r.get("latency"),
            "cost_usd": r.get("cost"),
            "results": [
                {"title": x.get("title"), "url": x.get("url"), "snippet": x.get("snippet")}
                for x in (r.get("results") or [])
            ],
            "citations": r.get("citations") or [],
        }
        if mode == "answer":
            rec["answer"] = r.get("answer")
            js = scores.get((eng, qid))
            rec["judge"] = js
            rec["judge_model"] = qdata.get("meta", {}).get("judge_model", "openai/gpt-oss-20b")
        enriched.append(rec)

    enriched.sort(key=lambda r: (r["query_id"], r["engine"], r["mode"]))

    return {
        "id": idx,
        "name": name,
        "queries_file": queries_file,
        "engines": qdata.get("meta", {}).get("engines", []),
        "queries": queries,
        "records": enriched,
    }


def main():
    b1 = build_benchmark(1, "bench_output.json", os.path.join(HERE, "queries.json"),
                         "judge_scores_1.json", RAW1, "General Queries")
    b2 = build_benchmark(2, "bench_output_queries2.json", os.path.join(HERE, "queries2.json"),
                         "judge_scores_2.json", RAW2, "Advanced Queries")

    total_cost = sum(r.get("cost_usd") or 0 for b in (b1, b2) for r in b["records"])

    final = {
        "meta": {
            "title": "AI Search Engine Benchmark 2026",
            "generated": "2026-08-15",
            "total_queries": len(b1["queries"]) + len(b2["queries"]),
            "total_records": len(b1["records"]) + len(b2["records"]),
            "engines_tested": ["arlong", "exa", "perplexity", "parallel"],
            "judge": {
                "provider": "Groq",
                "model": "openai/gpt-oss-20b",
                "prompt": "Score each answer 1-5 for factual correctness, completeness, and citation quality. Blind to engine.",
                "scale": "1 (wrong/unhelpful) to 5 (correct, complete, well-cited)",
            },
            "metrics": {
                "factoid": "Answer must contain expected fact (case/ascii-insensitive).",
                "auth_links": "Top-3 results contain an authoritative domain.",
                "citations": "Answer returned with at least one cited source URL.",
                "latency_s": "Wall-clock seconds for the request.",
                "cost_usd": "Estimated API cost (0.0 for local/self-hosted Arlong).",
            },
            "total_cost_usd": round(total_cost, 4),
            "notes": [
                "Linkup was removed: API account returns 402 Payment Required (no credits).",
                "Arlong is self-hosted and runs search+answer in-process; cost 0.0.",
                "Parallel search answers in set 1 are terse (some single words).",
                "Some Arlong answers in set 2 begin with '<think>' chain-of-thought leakage.",
            ],
        },
        "benchmarks": [b1, b2],
    }

    out = os.path.join(RAW1, "final_bench.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)
    print("Wrote", out, "({:,} bytes)".format(os.path.getsize(out)))


if __name__ == "__main__":
    main()
