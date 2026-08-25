# Arlong benchmark suite

Benchmarks Arlong against agentic AI search engines (Exa, Perplexity, Parallel, Linkup)
on 20 queries across factoid, current-events, product, comparison, how-to, local, and deep categories.

## Cost plan (~$0 total)

| Engine | What it costs | 20-query run |
|---|---|---|
| Arlong | local server, free | $0 |
| Exa | $20 free signup credits (~2,800 searches) | ~$0.15 |
| Perplexity | no free tier, ~$5/1K requests + tokens | ~$0.10 |
| Parallel | free tier (up to ~16K requests) | ~$0.10 |
| Linkup | $20/mo free credit, no card | ~$0.12 |

Optional LLM judge uses your existing `GROQ_API_KEY` (llama-3.3-70b) — ~$0.01 for 100 answers.

## Setup

1. Create `benchmarks/.env.bench` (copy from `.env.example` below) and fill in only the keys you have.
   Every missing key just skips that engine.
2. Start Arlong locally: `python main.py` (default `http://127.0.0.1:5000`).

## Run

```bash
python benchmarks/bench.py            # run search + answer for all ready engines
python benchmarks/report.py           # print summary + write results/report.md
python benchmarks/report.py --judge   # also LLM-judge answer quality via Groq
```

Useful flags:

```bash
python benchmarks/bench.py --engines arlong,exa,linkup   # only some engines
python benchmarks/bench.py --modes search                # skip answers
python benchmarks/bench.py --queries 5                   # first 5 queries
python benchmarks/bench.py --resume                      # skip tasks already cached
```

## Output

- `results/raw/<query>_<engine>_<mode>.json` — raw API responses (resumable cache)
- `results/bench_output.json` — normalized records with latency + estimated cost
- `results/report.md` — per-engine summary table + per-query top-3 results & answers

## Refresh only Arlong

The latest runner preserves captured competitor responses and refreshes only
Arlong through current production endpoints. It defaults to one question,
sequential calls, a delay, resume, and atomic checkpoints.

```bash
python benchmarks/arlong_latest.py run --queries-file benchmarks/queries2.json
python benchmarks/arlong_latest.py run --queries-file benchmarks/queries2.json --start 2 --limit 5
python benchmarks/arlong_latest.py report
```

Keep `ARLONG_API_KEY` in ignored `benchmarks/.env.bench`; it is never written to results.
