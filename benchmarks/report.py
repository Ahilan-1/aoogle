import argparse
import json
import os
import re
import unicodedata

from config import load_config

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(HERE, "results", "bench_output.json")
DEFAULT_OUTPUT = os.path.join(HERE, "results", "report.md")

ENGINE_LABELS = {
    "arlong": "Arlong",
    "exa": "Exa",
    "perplexity": "Perplexity",
    "parallel": "Parallel",
    "linkup": "Linkup",
}


def normalize(text):
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def expected_match(expected, answer):
    ans = normalize(answer)
    if not ans:
        return False
    for e in expected or []:
        e_norm = normalize(e)
        if not e_norm:
            continue
        if e_norm in ans:
            return True
        if len(e_norm) <= 3 and re.search(r"(?<![a-z0-9])" + re.escape(e_norm) + r"(?![a-z0-9])", ans):
            return True
    return False


def dom(url):
    m = re.match(r"https?://([^/:]+)", url or "")
    return m.group(1).replace("www.", "") if m else ""


AUTHORITY_TLDS = (".gov", ".edu", ".mil")
AUTHORITY_DOMAINS = {
    "wikipedia.org", "britannica.com", "nasa.gov", "arxiv.org", "nature.com",
    "nejm.org", "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk", "cnbc.com",
    "imf.org", "nobelprize.org", "pubmed.ncbi.nlm.nih.gov", "pmc.ncbi.nlm.nih.gov",
    "ncbi.nlm.nih.gov", "congress.gov", "govtrack.us", "usa.gov", "piie.com",
    "nber.org", "theconversation.com", "sciencedirect.com", "springer.com",
    "onlinelibrary.wiley.com", "aclanthology.org", "openreview.net", "pytorch.org",
    "amd.com", "intel.com", "nvidia.com", "olympics.com", "teamusa.com",
    "consumerfinance.gov", "oecd.ai", "brookings.edu", "ieee.org", "acm.org",
}


def is_authoritative(url):
    d = dom(url)
    return d in AUTHORITY_DOMAINS or d.endswith(AUTHORITY_TLDS)


def run_judge(records, cfg):
    from groq import Groq
    client = Groq(api_key=cfg["groq_api_key"])
    system = (
        "You are an impartial judge evaluating answers from different AI search engines. "
        'For each question and candidate answer, score factual correctness and completeness from 1 (wrong/unhelpful) '
        'to 5 (correct, complete, well-cited). Respond ONLY with a JSON object like {"score": 4, "reason": "short"}.'
    )
    scores = {}
    for rec in records:
        if rec.get("mode") != "answer":
            continue
        ans = rec.get("answer") or ""
        if not ans.strip():
            scores[(rec["engine"], rec["query_id"])] = None
            continue
        try:
            resp = client.chat.completions.create(
                model=cfg["judge_model"],
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": f'Question: {rec["query"]}\n\nCandidate answer:\n{ans}\n\nScore:'},
                ],
                temperature=0,
                max_tokens=120,
            )
            content = resp.choices[0].message.content or ""
            m = re.search(r"\{.*\}", content, re.DOTALL)
            obj = json.loads(m.group(0)) if m else {}
            scores[(rec["engine"], rec["query_id"])] = obj.get("score")
        except Exception:
            scores[(rec["engine"], rec["query_id"])] = None
    return scores


def compute_engine_stats(records, scores):
    stats = {}
    for rec in records:
        eng = rec["engine"]
        s = stats.setdefault(eng, {
            "search_n": 0, "answer_n": 0, "latencies": [], "cost": 0.0,
            "factoid_hits": 0, "factoid_n": 0, "answers_present": 0,
            "citations_present": 0, "citations_grounded": 0,
            "results_ok": 0, "snippet_ok": 0, "auth_links": 0,
            "judge": [], "expected_failures": [],
        })
        s["cost"] += rec.get("cost", 0.0)
        if rec.get("latency", -1) >= 0:
            s["latencies"].append(rec["latency"])
        if rec.get("mode") == "search":
            s["search_n"] += 1
            results = rec.get("results") or []
            if results:
                s["results_ok"] += 1
                if any(r.get("snippet") for r in results):
                    s["snippet_ok"] += 1
                if any(is_authoritative(r.get("url")) for r in results[:3]):
                    s["auth_links"] += 1
        else:
            s["answer_n"] += 1
            answer = rec.get("answer") or ""
            if answer.strip():
                s["answers_present"] += 1
            if rec.get("expected"):
                s["factoid_n"] += 1
                if expected_match(rec.get("expected"), answer):
                    s["factoid_hits"] += 1
                else:
                    s["expected_failures"].append((rec["query_id"], answer[:120]))
            cites = rec.get("citations") or []
            if cites:
                s["citations_present"] += 1
                result_doms = {dom(r.get("url")) for r in (rec.get("results") or [])}
                if any(dom(c) in result_doms for c in cites):
                    s["citations_grounded"] += 1
            if scores and (eng, rec["query_id"]) in scores:
                sc = scores[(eng, rec["query_id"])]
                if sc is not None:
                    s["judge"].append(sc)
    return stats


def fmt_lat(ms, n):
    if not ms or not n:
        return "-"
    avg_s = sum(ms) / n
    if avg_s >= 1:
        return f"{avg_s:.1f}s"
    return f"{avg_s * 1000:.0f}ms"


def render(records, cfg, scores, out_path):
    stats = compute_engine_stats(records, scores)
    lines = []
    lines.append("# AI Search Benchmark Report")
    lines.append("")
    lines.append(f"Run generated: {cfg['meta']['generated']}  |  queries: {cfg['meta']['queries']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Engine | Search n | Answer n | Avg latency | Est. cost | Factoid acc. | Answers | Citations | Auth links | Judge avg |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for eng in ENGINE_LABELS:
        if eng not in stats:
            continue
        s = stats[eng]
        acc = f"{s['factoid_hits']}/{s['factoid_n']}" if s["factoid_n"] else "-"
        judge = f"{sum(s['judge'])/len(s['judge']):.2f}" if s["judge"] else "-"
        lat = fmt_lat(s["latencies"], s["search_n"] + s["answer_n"])
        lines.append(
            f"| {ENGINE_LABELS[eng]} | {s['search_n']} | {s['answer_n']} | {lat} | "
            f"${s['cost']:.4f} | {acc} | {s['answers_present']}/{s['answer_n']} | "
            f"{s['citations_present']}/{s['answer_n']} | {s['auth_links']}/{s['search_n']} | {judge} |"
        )
    lines.append("")
    lines.append("## Per-query: top-3 results (domain) and answer")
    lines.append("")
    by_query = {}
    for rec in records:
        by_query.setdefault(rec["query_id"], []).append(rec)
    for qid in sorted(by_query):
        recs = by_query[qid]
        query = recs[0]["query"]
        expected = recs[0].get("expected") or []
        lines.append(f"### {qid}: {query}")
        if expected:
            lines.append(f"\nExpected: {', '.join(expected)}")
        lines.append("")
        lines.append("| Engine | Top results | Answer | Citations |")
        lines.append("|---|---|---|---|")
        for rec in recs:
            tops = ", ".join(dom(r.get("url")) for r in (rec.get("results") or [])[:5]) or "-"
            ans = (rec.get("answer") or "").strip().replace("|", "/")[:180] or "-"
            cites = len(rec.get("citations") or [])
            lines.append(f"| {ENGINE_LABELS.get(rec['engine'], rec['engine'])} | {tops} | {ans} | {cites} |")
        lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Factoid accuracy checks whether the engine's answer contains the expected fact (case/ascii-insensitive).")
    lines.append("- 'Auth links' = queries whose top-3 search results include an authoritative source (.gov/.edu/.mil or a curated domain like wikipedia.org, arxiv.org, reuters.com).")
    lines.append("- 'Grounded cit.' = at least one cited URL shares a domain with the engine's own top-10 results.")
    lines.append("- Costs are estimated from published list prices; Arlong runs locally and costs $0 in infra.")
    lines.append("- Perplexity returns citations (not raw results), so its 'top results' are its cited sources.")
    report = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report


def print_console(stats):
    print("\n=== ENGINE SUMMARY ===")
    header = f"{'Engine':10s} {'#search':>7s} {'#ans':>5s} {'latency':>8s} {'cost':>9s} {'factoid':>9s} {'cites':>7s} {'authL':>6s} {'judge':>6s}"
    print(header)
    print("-" * len(header))
    for eng in ENGINE_LABELS:
        if eng not in stats:
            continue
        s = stats[eng]
        acc = f"{s['factoid_hits']}/{s['factoid_n']}" if s["factoid_n"] else "-"
        judge = f"{sum(s['judge'])/len(s['judge']):.2f}" if s["judge"] else "-"
        lat = fmt_lat(s["latencies"], s["search_n"] + s["answer_n"])
        print(f"{ENGINE_LABELS[eng]:10s} {s['search_n']:7d} {s['answer_n']:5d} {lat:>8s} "
              f"${s['cost']:.4f} {acc:>9s} {s['citations_present']:>5d}/{s['answer_n']:<3d} "
              f"{s['auth_links']:>5d}/{s['search_n']:<3d} {judge:>6s}")
        if s["expected_failures"]:
            for qid, ans in s["expected_failures"]:
                print(f"    factoid miss {qid}: {ans}")


def main():
    parser = argparse.ArgumentParser(description="Generate the benchmark report")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--queries-file", default=os.path.join(HERE, "queries.json"),
                        help="path to queries JSON file (for meta + expected answers)")
    parser.add_argument("--judge", action="store_true", help="run the LLM judge (uses GROQ_API_KEY)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        records = json.load(f)
    cfg = load_config()
    with open(args.queries_file, "r", encoding="utf-8") as f:
        qdata = json.load(f)
    cfg["meta"] = {"generated": qdata["meta"].get("created", "unknown"), "queries": len(qdata["queries"])}

    scores = None
    if args.judge:
        if not cfg["groq_api_key"]:
            print("GROQ_API_KEY not set; skipping judge.")
        else:
            print(f"Running judge with {cfg['judge_model']} on {sum(1 for r in records if r.get('mode')=='answer')} answers...")
            scores = run_judge(records, cfg)

    stats = compute_engine_stats(records, scores)
    print_console(stats)
    report = render(records, cfg, scores, args.output)
    print(f"\nFull report written to {args.output}")
    if scores:
        uncounted = [k for k, v in scores.items() if v is None]
        if uncounted:
            print(f"Judge could not score {len(uncounted)} answers.")


if __name__ == "__main__":
    main()
