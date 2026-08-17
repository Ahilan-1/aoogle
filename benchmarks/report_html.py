import argparse
import json
import os
import re
import sys
import time
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_config
from report import dom, expected_match, is_authoritative, normalize

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

ENGINE_LABELS = {
    "arlong": "Arlong",
    "exa": "Exa",
    "perplexity": "Perplexity",
    "parallel": "Parallel",
    "linkup": "Linkup",
}

ENGINE_COLORS = {
    "arlong": "#8b5cf6",
    "exa": "#38bdf8",
    "perplexity": "#fb923c",
    "parallel": "#34d399",
    "linkup": "#f87171",
}

ENGINE_NOTE = {
    "arlong": "Local, self-hosted. Runs search + answer in-process on this machine; no API cost.",
    "exa": "Exa semantic search + Groq-generated summary over its top results.",
    "perplexity": "Perplexity Sonar (agentic, returns citations instead of raw results).",
    "parallel": "Parallel AI search + answer (x-api-key header).",
    "linkup": "Linkup search API (excluded: account returned 402 Payment Required).",
}


def load_bench(out_file, queries_file):
    with open(os.path.join(RESULTS, out_file), "r", encoding="utf-8") as f:
        records = json.load(f)
    with open(queries_file, "r", encoding="utf-8") as f:
        qdata = json.load(f)
    return records, qdata["queries"]


def compute_stats(records):
    stats = {}
    for rec in records:
        eng = rec["engine"]
        s = stats.setdefault(eng, {
            "lat": [], "cost": 0.0, "fact_hits": 0, "fact_n": 0,
            "answers": 0, "cites": 0, "auth": 0, "search_n": 0, "answer_n": 0,
            "grounded": 0, "res_ok": 0,
        })
        s["cost"] += rec.get("cost", 0.0)
        if rec.get("latency", -1) >= 0:
            s["lat"].append(rec["latency"])
        if rec["mode"] == "search":
            s["search_n"] += 1
            results = rec.get("results") or []
            if results:
                s["res_ok"] += 1
                if any(is_authoritative(r.get("url")) for r in results[:3]):
                    s["auth"] += 1
        else:
            s["answer_n"] += 1
            answer = rec.get("answer") or ""
            if answer.strip():
                s["answers"] += 1
            if rec.get("expected"):
                s["fact_n"] += 1
                if expected_match(rec.get("expected"), answer):
                    s["fact_hits"] += 1
            cites = rec.get("citations") or []
            if cites:
                s["cites"] += 1
                res_doms = {dom(r.get("url")) for r in (rec.get("results") or [])}
                if any(dom(c) in res_doms for c in cites):
                    s["grounded"] += 1
    return stats


def avg_lat(stats, s):
    n = s["search_n"] + s["answer_n"]
    if not s["lat"] or not n:
        return "-"
    avg = sum(s["lat"]) / n
    return f"{avg:.1f}s" if avg >= 1 else f"{avg * 1000:.0f}ms"


def run_judge(records, cfg):
    from groq import Groq
    client = Groq(api_key=cfg["groq_api_key"])
    system = (
        "You are an impartial judge evaluating answers from different AI search engines. "
        'For each question and candidate answer, score factual correctness and completeness from 1 (wrong/unhelpful) '
        'to 5 (correct, complete, well-cited). Respond ONLY with a JSON object like {"score": 4, "reason": "short"}'
    )
    scores = {}
    answers = [r for r in records if r["mode"] == "answer"]
    for i, rec in enumerate(answers, 1):
        ans = (rec.get("answer") or "").strip()
        key = (rec["engine"], rec["query_id"])
        if not ans:
            scores[key] = None
            continue
        try:
            resp = client.chat.completions.create(
                model=cfg["judge_model"],
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": f'Question: {rec["query"]}\n\nCandidate answer:\n{ans}\n\nScore:'},
                ],
                temperature=0,
                max_tokens=140,
            )
            content = resp.choices[0].message.content or ""
            m = re.search(r"\{.*\}", content, re.DOTALL)
            obj = json.loads(m.group(0)) if m else {}
            scores[key] = {"score": obj.get("score"), "reason": obj.get("reason", "")}
            print(f"  [{i}/{len(answers)}] {rec['engine']:10s} {rec['query_id']}  {obj.get('score')}")
        except Exception:
            scores[key] = None
        time.sleep(0.05)
    return scores


def esc(text):
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build(records, queries, scores, title, subtitle, index, accent):
    stats = compute_stats(records)
    by_query = {}
    for rec in records:
        by_query.setdefault(rec["query_id"], []).append(rec)
    order = [q["id"] for q in queries]
    cat_of = {q["id"]: q.get("category", "") for q in queries}
    expected_of = {q["id"]: q.get("expected", []) for q in queries}
    query_text = {q["id"]: q["query"] for q in queries}

    jn_by_eng = {eng: 0 for eng in ENGINE_LABELS}
    js_by_eng = {eng: 0 for eng in ENGINE_LABELS}
    for eng in ENGINE_LABELS:
        for qid in order:
            v = (scores or {}).get((eng, qid))
            if isinstance(v, dict) and isinstance(v.get("score"), (int, float)):
                js_by_eng[eng] += v["score"]
                jn_by_eng[eng] += 1

    rows = ""
    for eng in ENGINE_LABELS:
        if eng not in stats:
            continue
        s = stats[eng]
        fact = f"{s['fact_hits']}/{s['fact_n']}" if s["fact_n"] else "-"
        jn = jn_by_eng.get(eng, 0)
        js = js_by_eng.get(eng, 0)
        judge = f"{js / jn:.2f}" if jn else "-"
        pct = js / jn / 5 * 100 if jn else 0
        rows += (
            f"<tr>"
            f"<td><div class='eng'><span class='dot' style='background:{ENGINE_COLORS[eng]}'></span>"
            f"<span class='eng-name'>{ENGINE_LABELS[eng]}</span></div></td>"
            f"<td class='mono'>{avg_lat(stats, s)}</td>"
            f"<td class='mono num'>${s['cost']:.4f}</td>"
            f"<td class='mono num'>{fact}</td>"
            f"<td class='mono num'>{s['cites']}/{s['answer_n']}</td>"
            f"<td class='mono num'>{s['auth']}/{s['search_n']}</td>"
            f"<td class='num'><div class='score-wrap'><div class='score-fill' style='width:{pct}%'></div>"
            f"<span class='score-label mono'>{judge}</span></div></td>"
            f"</tr>"
        )

    bars = ""
    for eng in ENGINE_LABELS:
        if eng not in stats:
            continue
        jn = jn_by_eng.get(eng, 0)
        js = js_by_eng.get(eng, 0)
        avg = (js / jn) if jn else 0
        pct = avg / 5 * 100
        bars += (
            f"<div class='bar-row'>"
            f"<div class='bar-eng'><b>{ENGINE_LABELS[eng]}</b></div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%'></div></div>"
            f"<div class='bar-val mono'>{avg:.2f}<span class='dim'>/5</span></div>"
            f"</div>"
        )

    qblocks = ""
    for qid in order:
        recs = by_query.get(qid, [])
        q = query_text.get(qid, "")
        cat = cat_of.get(qid, "")
        exp = expected_of.get(qid, [])
        exp_tag = f'<span class="tag exp">expected · {esc(", ".join(exp))}</span>' if exp else ""
        cat_tag = f'<span class="tag">{esc(cat)}</span>' if cat else ""
        rows2 = ""
        for eng in ENGINE_LABELS:
            r = next((x for x in recs if x["engine"] == eng), None)
            if not r:
                continue
            top = ", ".join(dom(x.get("url")) for x in (r.get("results") or [])[:3]) or "-"
            ans = (r.get("answer") or "").strip()
            v = (scores or {}).get((eng, qid))
            sc = "—"
            sc_class = ""
            if isinstance(v, dict) and isinstance(v.get("score"), (int, float)):
                sc = f"{v['score']}"
                sc_class = "p" + str(int(round(v["score"])))
            cite_count = len(r.get("citations") or [])
            cites_html = ""
            for c in (r.get("citations") or [])[:5]:
                cites_html += f'<a class="cite" href="{esc(c)}" target="_blank" rel="noopener">{esc(dom(c))}</a>'
            cite_link = cites_html or '<span class="dim">none</span>'
            if len(ans) > 320:
                ans_short, ans_more = ans[:320], ans[320:]
                ans_html = (
                    f"<span class='ans-text'>{esc(ans_short)}</span>"
                    f"<span class='ans-more' style='display:none'>{esc(ans_more)}</span>"
                    f"<button class='toggle' onclick='toggle(this)'>expand</button>"
                )
            else:
                ans_html = f"<span class='ans-text'>{esc(ans)}</span>"
            rows2 += (
                f"<tr>"
                f"<td><div class='eng'><span class='dot' style='background:{ENGINE_COLORS[eng]}'></span>"
                f"<span class='eng-name'>{ENGINE_LABELS[eng]}</span></div></td>"
                f"<td class='small links'>{esc(top)}</td>"
                f"<td class='small ans'>{ans_html}</td>"
                f"<td class='small cites'>{cite_link}</td>"
                f"<td class='num'><span class='score-pill {sc_class}'>{sc}</span></td>"
                f"</tr>"
            )
        qblocks += (
            f"<details class='qblock' open>"
            f"<summary><span class='qid mono'>{qid}</span>"
            f"<span class='qtext'>{esc(q)}</span>{cat_tag}{exp_tag}</summary>"
            f"<div class='qwrap'><table>"
            f"<thead><tr><th>Engine</th><th>Top links</th><th>Answer</th><th>Citations</th><th>Score</th></tr></thead>"
            f"<tbody>{rows2}</tbody></table></div>"
            f"</details>"
        )

    return f"""
<section class='bench' id='bench-{index}'>
  <div class='bench-head'>
    <span class='kicker mono'>BENCHMARK {index}</span>
    <h2>{title}</h2>
    <p class='sub'>{subtitle}</p>
  </div>
  <div class='panel'>
    <table class='sum'>
      <thead><tr><th>Engine</th><th>Latency</th><th>Est. cost</th><th>Factoid</th>
      <th>Citations</th><th>Auth links</th><th>Judge score</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <div class='bars'><div class='bars-title mono'>AVG JUDGE SCORE</div>{bars}</div>
  </div>
  <div class='perq'>
    <div class='perq-head'><h3>Per-query breakdown</h3><span class='dim mono'>{len(order)} QUERIES</span></div>
    {qblocks}
  </div>
</section>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate public-facing benchmark.html")
    parser.add_argument("--judge", action="store_true", help="run the LLM judge (saves scores)")
    parser.add_argument("--output", default=os.path.join(RESULTS, "benchmark.html"))
    args = parser.parse_args()

    cfg = load_config()
    b1 = load_bench("bench_output.json", os.path.join(HERE, "queries.json"))
    b2 = load_bench("bench_output_queries2.json", os.path.join(HERE, "queries2.json"))

    scores1, scores2 = None, None
    cache1 = os.path.join(RESULTS, "judge_scores_1.json")
    cache2 = os.path.join(RESULTS, "judge_scores_2.json")
    if os.path.exists(cache1) and os.path.exists(cache2):
        with open(cache1, encoding="utf-8") as f:
            s1 = json.load(f)
        with open(cache2, encoding="utf-8") as f:
            s2 = json.load(f)
        scores1 = {(k.split("|")[0], k.split("|")[1]): v for k, v in s1.items()}
        scores2 = {(k.split("|")[0], k.split("|")[1]): v for k, v in s2.items()}
        print("Loaded cached judge scores.")
    if args.judge or (not scores1 and not scores2):
        if not cfg["groq_api_key"]:
            print("GROQ_API_KEY not set; skipping judge.")
        else:
            if not scores1:
                print("Judging benchmark 1...")
                scores1 = run_judge(b1[0], cfg)
                with open(cache1, "w", encoding="utf-8") as f:
                    json.dump({f"{k[0]}|{k[1]}": v for k, v in scores1.items() if v}, f, ensure_ascii=False, indent=1)
            if not scores2:
                print("Judging benchmark 2...")
                scores2 = run_judge(b2[0], cfg)
                with open(cache2, "w", encoding="utf-8") as f:
                    json.dump({f"{k[0]}|{k[1]}": v for k, v in scores2.items() if v}, f, ensure_ascii=False, indent=1)

    total_cost = sum(r["cost"] for r in b1[0]) + sum(r["cost"] for r in b2[0])
    sec1 = build(b1[0], b1[1], scores1, "General Queries",
                 "20 everyday, current, and how-to questions spanning factoids, comparisons, local, product, and deep-dive topics.",
                 1, "#38bdf8")
    sec2 = build(b2[0], b2[1], scores2, "Advanced Queries",
                 "20 harder, multi-hop questions: speculative decoding, GPU scheduling, EU AI Act, the 1997 Asian crisis, and more.",
                 2, "#818cf8")

    engine_cards = ""
    for eng in ENGINE_LABELS:
        engine_cards += (
            f"<div class='card'>"
            f"<div class='card-head'><span class='dot' style='background:{ENGINE_COLORS[eng]}'></span>"
            f"<b>{ENGINE_LABELS[eng]}</b></div>"
            f"<div class='card-body'>{ENGINE_NOTE[eng]}</div>"
            f"</div>"
        )

    css = """
:root{
  --bg:#060709; --panel:#0b0d12; --panel2:#0e1117; --line:rgba(255,255,255,.07);
  --txt:#eef1f6; --mut:#8b93a1; --dim:#565e6d; --blue:#3b82f6; --blue-soft:#60a5fa;
  --mono:'JetBrains Mono','SF Mono','Cascadia Code',Consolas,monospace;
  --sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px 100px}
::selection{background:rgba(59,130,246,.35)}
.mono{font-family:var(--mono)}
.dim{color:var(--dim)}
a{color:var(--blue-soft);text-decoration:none}
a:hover{text-decoration:underline}

/* ---------- HERO ---------- */
.hero{position:relative;overflow:hidden;border-bottom:1px solid var(--line);
  background:radial-gradient(900px 480px at 50% -20%,#12203a 0%,rgba(10,14,22,.2) 55%,transparent 75%);}
.hero .grid-overlay{position:absolute;inset:0;pointer-events:none;opacity:.35;
  background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),
  linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);
  background-size:42px 42px;
  mask-image:radial-gradient(700px 380px at 50% 0%,#000 40%,transparent 90%);
  -webkit-mask-image:radial-gradient(700px 380px at 50% 0%,#000 40%,transparent 90%);}
.hero-inner{position:relative;max-width:1120px;margin:0 auto;padding:84px 24px 60px;text-align:center}
.badge{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);
  background:rgba(255,255,255,.04);border-radius:999px;padding:6px 14px;font-size:.72rem;
  letter-spacing:.14em;color:var(--mut);text-transform:uppercase;margin-bottom:26px}
.badge .pulse{width:7px;height:7px;border-radius:50%;background:var(--blue);
  box-shadow:0 0 0 0 rgba(59,130,246,.7);animation:pulse 2.2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(59,130,246,.5)}70%{box-shadow:0 0 0 9px rgba(59,130,246,0)}100%{box-shadow:0 0 0 0 rgba(59,130,246,0)}}
.hero h1{margin:0;font-size:clamp(2rem,5vw,3.4rem);font-weight:800;letter-spacing:-.02em;line-height:1.12}
.hero h1 .grad{background:linear-gradient(100deg,#fff 10%,#bfdbfe 45%,#3b82f6 90%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.hero .sub{color:var(--mut);max-width:620px;margin:18px auto 0;font-size:1.02rem}
.stats-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:38px}
.stat{flex:1;min-width:150px;max-width:190px;background:rgba(255,255,255,.03);
  border:1px solid var(--line);border-radius:14px;padding:18px 16px;backdrop-filter:blur(6px)}
.stat .n{font-family:var(--mono);font-size:1.7rem;font-weight:700;color:#fff;line-height:1.2}
.stat .n em{font-style:normal;color:var(--blue-soft)}
.stat .l{font-size:.72rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-top:6px}

/* ---------- SECTION HEADERS ---------- */
.sect{position:relative;margin-top:72px}
.sect-head{display:flex;align-items:center;gap:18px;margin-bottom:26px}
.sect-num{font-family:var(--mono);font-size:.8rem;color:var(--blue);letter-spacing:.12em;
  border:1px solid rgba(59,130,246,.35);border-radius:8px;padding:6px 10px;background:rgba(59,130,246,.08)}
.sect-head h2{font-size:1.6rem;font-weight:700;letter-spacing:-.01em}
.sect-head .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
.sect-sub{color:var(--mut);max-width:760px;margin:-10px 0 24px 54px}

/* ---------- CARDS ---------- */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:20px 0 8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;
  transition:border-color .2s,transform .2s}
.card:hover{border-color:rgba(59,130,246,.45);transform:translateY(-2px)}
.card-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:.95rem}
.card-body{color:var(--mut);font-size:.82rem;line-height:1.55}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;flex-shrink:0}

/* ---------- METHOD ---------- */
.method{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px 28px;
  color:var(--mut);font-size:.92rem;line-height:1.75}
.method b{color:var(--txt)}
.method-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:18px;margin-top:16px}
.method-grid .m-item{border-left:2px solid rgba(59,130,246,.4);padding-left:14px}
.method-grid .m-item .m-title{font-family:var(--mono);font-size:.74rem;color:var(--blue-soft);
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}

/* ---------- BENCH PANELS ---------- */
.bench{margin-top:64px}
.bench-head{margin-bottom:22px}
.kicker{font-size:.74rem;letter-spacing:.22em;color:var(--blue);display:inline-block;margin-bottom:10px}
.bench-head h2{font-size:1.7rem;font-weight:700;letter-spacing:-.01em}
.bench-head .sub{color:var(--mut);margin-top:8px;max-width:720px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{font-family:var(--mono);font-size:.68rem;letter-spacing:.14em;color:var(--dim);text-transform:uppercase;
  text-align:left;padding:14px 18px;border-bottom:1px solid var(--line);background:var(--panel2)}
td{padding:14px 18px;border-bottom:1px solid var(--line);font-size:.9rem;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(59,130,246,.05)}
.num{text-align:center}
.eng{display:flex;align-items:center;gap:10px}
.eng-name{font-weight:600}
.eng small{color:var(--dim);font-weight:400}
.mono{font-family:var(--mono)}
.score-wrap{position:relative;min-width:64px;height:22px;border-radius:6px;overflow:hidden;
  background:var(--panel2);border:1px solid var(--line);display:inline-flex;align-items:center;justify-content:center}
.score-fill{position:absolute;inset:0;background:linear-gradient(90deg,rgba(59,130,246,.25),rgba(59,130,246,.55));
  z-index:0}
.score-label{position:relative;z-index:1;font-size:.85rem;font-weight:700}

/* ---------- BARS ---------- */
.bars{padding:22px 28px;border-top:1px solid var(--line);background:var(--panel2)}
.bars-title{font-size:.68rem;letter-spacing:.2em;color:var(--dim);margin-bottom:14px}
.bar-row{display:flex;align-items:center;gap:16px;margin:10px 0}
.bar-eng{width:110px;font-size:.9rem}
.bar-track{flex:1;height:16px;background:#0a0c11;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:8px;
  background:linear-gradient(90deg,rgba(59,130,246,.45),var(--blue-soft));
  box-shadow:0 0 14px rgba(59,130,246,.4)}
.bar-val{width:64px;text-align:right;font-size:.9rem;font-weight:700}
.bar-val .dim{font-weight:400;font-size:.75rem}

/* ---------- PER QUERY ---------- */
.perq{margin-top:44px}
.perq-head{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:16px}
.perq-head h3{font-size:1.1rem}
.qblock{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:10px 0;overflow:hidden;
  transition:border-color .2s}
.qblock[open]{border-color:rgba(59,130,246,.35)}
.qblock summary{list-style:none;cursor:pointer;padding:15px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.qblock summary::-webkit-details-marker{display:none}
.qid{font-size:.78rem;color:var(--blue);background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);
  border-radius:6px;padding:2px 8px;flex-shrink:0}
.qtext{flex:1;min-width:200px;font-size:.92rem;font-weight:500}
.qblock summary .tag{font-family:var(--mono);font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;
  color:var(--mut);border:1px solid var(--line);border-radius:20px;padding:2px 10px;background:var(--panel2)}
.qblock summary .tag.exp{color:#86efac;border-color:rgba(134,239,172,.3)}
.qblock summary .chev{transition:transform .2s;color:var(--dim);font-family:var(--mono)}
.qblock[open] summary .chev{transform:rotate(90deg)}
.qwrap{padding:0 20px 18px}
.qwrap table{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.qwrap td.small{font-size:.8rem;color:var(--mut);vertical-align:top}
.qwrap td.ans{color:var(--txt);line-height:1.6}
.qwrap td.links{max-width:200px;word-break:break-word}
.cite{display:inline-block;margin:0 6px 4px 0;font-size:.74rem;font-family:var(--mono);
  border:1px solid var(--line);border-radius:6px;padding:1px 7px;color:var(--blue-soft);background:var(--panel2)}
.cite:hover{border-color:rgba(59,130,246,.5);text-decoration:none}
.score-pill{font-family:var(--mono);font-weight:700;border-radius:6px;padding:2px 10px;font-size:.85rem;
  border:1px solid var(--line);background:var(--panel2);color:var(--mut)}
.score-pill.p5{color:#86efac;border-color:rgba(134,239,172,.35)}
.score-pill.p4{color:#a7f3d0;border-color:rgba(134,239,172,.2)}
.score-pill.p3{color:#fde68a;border-color:rgba(253,230,138,.3)}
.score-pill.p2,.score-pill.p1{color:#fca5a5;border-color:rgba(252,165,165,.3)}
.toggle{background:transparent;border:1px solid var(--line);color:var(--blue-soft);font-size:.72rem;
  font-family:var(--mono);border-radius:6px;padding:2px 9px;margin-left:8px;cursor:pointer;transition:border-color .2s}
.toggle:hover{border-color:rgba(59,130,246,.5)}

/* ---------- FOOTER ---------- */
footer{border-top:1px solid var(--line);margin-top:90px;padding:34px 0 10px;text-align:center;
  color:var(--dim);font-size:.8rem}
footer .f-top{font-family:var(--mono);letter-spacing:.24em;font-size:.72rem;color:var(--mut);text-transform:uppercase;margin-bottom:12px}
footer .f-top span{color:var(--blue)}

@media (max-width:720px){
  .hero-inner{padding:56px 20px 44px}
  .wrap{padding:0 14px 80px}
  .sect-head .rule{display:none}
  .sect-sub{margin-left:0}
  .qwrap{overflow-x:auto}
  .qwrap table{min-width:680px}
}
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Search Engine Benchmark 2026 — Labs</title>
<style>{css}</style>
</head>
<body>

<div class="hero">
  <div class="grid-overlay"></div>
  <div class="hero-inner">
    <div class="badge"><span class="pulse"></span>AI LABS · RESEARCH REPORT</div>
    <h1>AI Search Engine <span class="grad">Benchmark 2026</span></h1>
    <p class="sub">A fair, low-cost comparison of agentic AI search engines on 40 queries &mdash;
    measuring link quality, citation grounding, answer correctness, latency, and cost.</p>
    <div class="stats-row">
      <div class="stat"><div class="n"><em>40</em></div><div class="l">Total queries</div></div>
      <div class="stat"><div class="n"><em>4</em></div><div class="l">Engines</div></div>
      <div class="stat"><div class="n"><em>2</em></div><div class="l">Benchmark sets</div></div>
      <div class="stat"><div class="n"><em>$1.21</em></div><div class="l">Total API cost</div></div>
      <div class="stat"><div class="n"><em>160</em></div><div class="l">Judged answers</div></div>
    </div>
  </div>
</div>

<div class="wrap">

  <section class="sect" id="engines">
    <div class="sect-head"><span class="sect-num">01</span><h2>Engines Tested</h2><div class="rule"></div></div>
    <p class="sect-sub">Four engines, one identical workload. Each engine received the exact same 20 questions per benchmark, in both <i>search</i> and <i>answer</i> modes.</p>
    <div class="cards">{engine_cards}</div>
  </section>

  <section class="sect" id="method">
    <div class="sect-head"><span class="sect-num">02</span><h2>Methodology</h2><div class="rule"></div></div>
    <div class="method">
      Every engine was asked the same questions under identical conditions. Each question ran twice: once to
      <b>return top results</b> (search mode) and once to <b>synthesize an answer with citations</b> (answer mode).
      Latency and cost were captured per request. Costs use published list prices; Arlong runs locally and costs
      nothing in infrastructure. All 160 answers were then scored 1&ndash;5 by an independent LLM judge
      (Groq <span class="mono">openai/gpt-oss-20b</span>), temperature 0, blind to which engine produced them.
      <div class="method-grid">
        <div class="m-item"><div class="m-title">Factoid accuracy</div>Answer must contain the expected fact (case / ascii-insensitive).</div>
        <div class="m-item"><div class="m-title">Auth links</div>Top-3 results contain an authoritative source (.gov/.edu/.mil, wikipedia.org, arxiv.org, reuters.com, &hellip;).</div>
        <div class="m-item"><div class="m-title">Citations</div>Answers returned with at least one cited source URL.</div>
        <div class="m-item"><div class="m-title">Judge score</div>1&ndash;5 for correctness, completeness, and citation quality.</div>
      </div>
    </div>
  </section>

  {sec1}
  {sec2}

  <footer>
    <div class="f-top">ARLONG <span>·</span> LABS — 2026</div>
    Generated 2026-08-15 · Independent judge: Groq openai/gpt-oss-20b · Raw data: benchmarks/results/bench_output*.json
  </footer>
</div>

<script>
function toggle(btn){{
  var tr = btn.closest('tr');
  var more = tr.querySelector('.ans-more');
  if (more.style.display === 'none') {{
    more.style.display = 'inline';
    btn.textContent = 'collapse';
  }} else {{
    more.style.display = 'none';
    btn.textContent = 'expand';
  }}
}}
</script>
</body>
</html>"""
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {args.output} ({os.path.getsize(args.output):,} bytes)")


if __name__ == "__main__":
    main()
