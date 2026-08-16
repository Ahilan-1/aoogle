import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from config import load_config
from engine_clients import build_clients

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
RAW_DIR = os.path.join(RESULTS_DIR, "raw")
OUTPUT_JSON = os.path.join(RESULTS_DIR, "bench_output.json")

def run_task(client, mode, q, limit_queries=None):
    fn = client.answer if mode == "answer" else client.search
    try:
        result = fn(q["query"])
    except Exception as e:
        result = {"results": [], "answer": "", "citations": [],
                  "latency": -1, "cost": 0.0, "raw": {"error": str(e)}}
    return {
        "query_id": q["id"],
        "query": q["query"],
        "category": q.get("category", ""),
        "expected": q.get("expected", []),
        "engine": client.name,
        "mode": mode,
        "results": result.get("results", []),
        "answer": result.get("answer", ""),
        "citations": result.get("citations", []),
        "latency": round(result.get("latency", 0.0), 3),
        "cost": round(result.get("cost", 0.0), 6),
        "raw": result.get("raw", {}),
        "raw_file": os.path.join(RAW_DIR, f"{q['id']}_{client.name}_{mode}.json"),
    }


def raw_path(q_id, engine, mode):
    return os.path.join(RAW_DIR, f"{q_id}_{engine}_{mode}.json")


def main():
    parser = argparse.ArgumentParser(description="Run the Arlong search benchmark across engines")
    parser.add_argument("--queries", type=int, default=None, help="limit to first N queries")
    parser.add_argument("--queries-file", default=os.path.join(HERE, "queries.json"),
                        help="path to queries JSON file")
    parser.add_argument("--engines", default=None, help="comma-separated engines to run")
    parser.add_argument("--modes", default="search,answer", help="comma-separated modes (search,answer)")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--resume", action="store_true", help="skip tasks with existing raw files")
    parser.add_argument("--json-out", default=OUTPUT_JSON)
    parser.add_argument("--run-id", default=None, help="subdirectory suffix for results (default: queries file stem)")
    args = parser.parse_args()

    if args.run_id:
        run_id = args.run_id
    else:
        run_id = os.path.splitext(os.path.basename(args.queries_file))[0]
    global RAW_DIR
    RAW_DIR = os.path.join(RESULTS_DIR, "raw_" + run_id)
    if args.json_out == OUTPUT_JSON:
        args.json_out = os.path.join(RESULTS_DIR, "bench_output_" + run_id + ".json")

    os.makedirs(RAW_DIR, exist_ok=True)
    cfg = load_config()
    with open(args.queries_file, "r", encoding="utf-8") as f:
        queries = json.load(f)["queries"]
    if args.queries:
        queries = queries[: args.queries]

    clients = [c for c in build_clients(cfg) if c.ready()]
    if args.engines:
        wanted = set(args.engines.split(","))
        clients = [c for c in clients if c.name in wanted]

    modes = args.modes.split(",")
    tasks = []
    for client in clients:
        for q in queries:
            for mode in modes:
                tasks.append((client, mode, q))

    pending = []
    for client, mode, q in tasks:
        if args.resume and os.path.exists(raw_path(q["id"], client.name, mode)):
            continue
        pending.append((client, mode, q))

    if not pending:
        print("Nothing to run (all tasks cached or none ready).")
        return

    print(f"Engines ready: {', '.join(c.name for c in clients)}")
    print(f"Tasks to run: {len(pending)} ({len(clients)} engines x {len(queries)} queries x {len(modes)} modes)")

    records = []
    errors = 0

    def work(item):
        client, mode, q = item
        rec = run_task(client, mode, q)
        with open(raw_path(q["id"], client.name, mode), "w", encoding="utf-8") as f:
            json.dump(rec.get("raw", {}), f, ensure_ascii=False, indent=2)
        return rec

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, rec in enumerate(pool.map(work, pending), 1):
            status = "ok" if rec["latency"] >= 0 else "FAILED"
            if status == "FAILED":
                errors += 1
            print(f"[{i}/{len(pending)}] {rec['engine']:10s} {rec['mode']:6s} "
                  f"{rec['query_id']}  {status}  {rec['latency']:.1f}s  ${rec['cost']:.4f}")
            records.append(rec)

    existing = []
    if args.resume and os.path.exists(args.json_out):
        with open(args.json_out, "r", encoding="utf-8") as f:
            existing = json.load(f)
    all_records = existing + records
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(all_records, f, ensure_ascii=False, indent=2)

    total_cost = sum(r["cost"] for r in all_records)
    print(f"\nDone. {len(all_records)} records written to {args.json_out}")
    print(f"Estimated total cost: ${total_cost:.4f}" + ("  (errors: %d)" % errors if errors else ""))


if __name__ == "__main__":
    main()
