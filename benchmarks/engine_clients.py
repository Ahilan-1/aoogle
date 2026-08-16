import json
import time

import requests

TIMEOUT = 90


class EngineClient:
    name = None

    def ready(self):
        return True

    def search(self, q):
        raise NotImplementedError

    def answer(self, q):
        raise NotImplementedError


class ArlongClient(EngineClient):
    name = "arlong"

    def __init__(self, base_url, api_key, use_internal=True):
        self.base_url = base_url
        self.use_internal = use_internal
        self.headers = {"User-Agent": "arlong-benchmark/1.0"}
        if api_key:
            self.headers["Authorization"] = "Bearer " + api_key
        self._main = None

    def ready(self):
        return True

    def _load_main(self):
        if self._main is None:
            import os
            import sys
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if root not in sys.path:
                sys.path.insert(0, root)
            import main
            self._main = main
        return self._main

    @staticmethod
    def _map_results(page_results):
        return [{
            "title": r.get("title") or "",
            "url": r.get("url") or "",
            "snippet": r.get("snippet") or "",
            "published": r.get("date") or r.get("published") or "",
        } for r in (page_results or [])]

    def search(self, q):
        if not self.use_internal:
            return self._search_http(q)
        main = self._load_main()
        t0 = time.time()
        try:
            page_results, total = main.search_engine.search(q, 1)
            elapsed = time.time() - t0
            return {"results": self._map_results(page_results[:10]), "latency": elapsed,
                    "cost": 0.0, "raw": {"total": total, "results": page_results[:10]}}
        except Exception as e:
            return {"results": [], "latency": time.time() - t0, "cost": 0.0,
                    "raw": {"error": str(e)}}

    def answer(self, q):
        if not self.use_internal:
            return self._answer_http(q)
        main = self._load_main()
        t0 = time.time()
        try:
            page_results, _ = main.search_engine.search(q, 1)
            answer, sources = main.arlong_ai_answer(q, page_results[:5] if page_results else None)
            elapsed = time.time() - t0
            citations = [s.get("url") for s in (sources or []) if s.get("url")]
            # raw MUST include the answer text so the per-query JSON files are
            # self-contained (previously only sources were persisted).
            return {"results": self._map_results(page_results[:10]), "answer": answer,
                    "citations": citations, "latency": elapsed, "cost": 0.0,
                    "raw": {"sources": sources, "answer": answer}}
        except Exception as e:
            return {"results": [], "answer": "", "citations": [], "latency": time.time() - t0,
                    "cost": 0.0, "raw": {"error": str(e)}}

    def _get(self, path, params):
        t0 = time.time()
        try:
            r = requests.get(self.base_url + path, params=params, headers=self.headers, timeout=TIMEOUT)
            data = r.json() if r.ok else {"error": r.text, "status": r.status_code}
        except Exception as e:
            return {"error": str(e)}, time.time() - t0
        return data, time.time() - t0

    def _search_http(self, q):
        data, elapsed = self._get("/api/search", {"q": q})
        results = []
        for item in data.get("results") or []:
            results.append({
                "title": item.get("title") or "",
                "url": item.get("url") or "",
                "snippet": item.get("snippet") or item.get("text") or "",
                "published": item.get("published_date") or item.get("published") or "",
            })
        return {"results": results, "latency": elapsed, "cost": 0.0, "raw": data}

    def _answer_http(self, q):
        data, elapsed = self._get("/api/ai-summary", {"q": q})
        answer = data.get("summary") or ""
        citations = [s.get("url") for s in (data.get("sources") or []) if s.get("url")]
        # always include a results key so consumers can rely on rec["results"]
        return {"results": [], "answer": answer, "citations": citations, "latency": elapsed,
                "cost": 0.0, "raw": data}


class ExaClient(EngineClient):
    name = "exa"

    def __init__(self, api_key):
        self.api_key = api_key

    def ready(self):
        return bool(self.api_key)

    def _post(self, path, body):
        t0 = time.time()
        try:
            r = requests.post("https://api.exa.ai" + path, json=body,
                              headers={"x-api-key": self.api_key}, timeout=TIMEOUT)
            data = r.json() if r.ok else {"error": r.text, "status": r.status_code}
        except Exception as e:
            return {"error": str(e)}, time.time() - t0
        return data, time.time() - t0

    @staticmethod
    def _cost(data):
        cd = data.get("costDollars") or {}
        if isinstance(cd, dict):
            return cd.get("total") or 0.0
        return 0.0

    @staticmethod
    def _results(data):
        out = []
        for item in data.get("results") or []:
            highlights = item.get("highlights") or []
            snippet = " ".join(highlights) if highlights else (item.get("text") or "")[:300]
            out.append({
                "title": item.get("title") or "",
                "url": item.get("url") or "",
                "snippet": snippet,
                "published": item.get("publishedDate") or "",
            })
        return out

    def search(self, q):
        body = {"query": q, "numResults": 10, "type": "auto",
                "contents": {"highlights": {"query": q}}}
        data, elapsed = self._post("/search", body)
        return {"results": self._results(data), "latency": elapsed, "cost": self._cost(data), "raw": data}

    def answer(self, q):
        body = {"query": q, "numResults": 5, "type": "auto",
                "outputSchema": {"type": "text",
                                 "description": "Direct, concise answer to the question with the key facts."}}
        data, elapsed = self._post("/search", body)
        out = data.get("output")
        answer = ""
        if isinstance(out, str):
            answer = out
        elif isinstance(out, dict):
            answer = out.get("content") or out.get("text") or json.dumps(out)
        elif isinstance(out, list):
            answer = json.dumps(out)
        citations = [item.get("url") for item in (data.get("results") or []) if item.get("url")]
        return {"answer": answer, "citations": citations, "latency": elapsed, "cost": self._cost(data), "raw": data}


class PerplexityClient(EngineClient):
    name = "perplexity"
    PRICES = {"sonar": (1.0, 1.0), "sonar-small": (0.2, 0.2),
              "sonar-pro": (3.0, 15.0), "sonar-reasoning-pro": (2.0, 8.0)}

    def __init__(self, api_key, model="sonar"):
        self.api_key = api_key
        self.model = model

    def ready(self):
        return bool(self.api_key)

    def answer(self, q):
        t0 = time.time()
        body = {"model": self.model,
                "messages": [{"role": "user", "content": q}],
                "max_tokens": 400}
        headers = {"Authorization": "Bearer " + self.api_key}
        data = {}
        for attempt in range(4):
            try:
                r = requests.post("https://api.perplexity.ai/chat/completions",
                                  json=body, headers=headers, timeout=TIMEOUT)
                if r.status_code == 429:
                    time.sleep(5 * (attempt + 1))
                    continue
                data = r.json() if r.ok else {"error": r.text, "status": r.status_code}
                break
            except Exception as e:
                if attempt == 3:
                    return {"answer": "", "citations": [], "latency": time.time() - t0, "cost": 0.0,
                            "raw": {"error": str(e)}}
                time.sleep(2)
        elapsed = time.time() - t0
        choices = data.get("choices") or []
        answer = choices[0].get("message", {}).get("content", "") if choices else ""
        citations = data.get("citations") or []
        usage = data.get("usage") or {}
        pin, pout = self.PRICES.get(self.model, (1.0, 1.0))
        cost = (usage.get("prompt_tokens", 0) / 1e6 * pin) + \
               (usage.get("completion_tokens", 0) / 1e6 * pout) + 0.005
        return {"answer": answer, "citations": citations, "latency": elapsed, "cost": cost, "raw": data}

    def search(self, q):
        res = self.answer(q)
        results = [{"title": "", "url": u, "snippet": "", "published": ""} for u in res["citations"]]
        return {**res, "results": results}


class ParallelClient(EngineClient):
    name = "parallel"

    def __init__(self, api_key):
        self.api_key = api_key

    def ready(self):
        return bool(self.api_key)

    def _post(self, path, body):
        t0 = time.time()
        try:
            r = requests.post("https://api.parallel.ai" + path, json=body,
                              headers={"x-api-key": self.api_key, "Content-Type": "application/json"},
                              timeout=TIMEOUT)
            data = r.json() if r.ok else {"error": r.text, "status": r.status_code}
        except Exception as e:
            return {"error": str(e)}, time.time() - t0
        return data, time.time() - t0

    def search(self, q):
        body = {"objective": q, "search_queries": [q], "mode": "basic"}
        data, elapsed = self._post("/v1/search", body)
        results = []
        for item in data.get("results") or []:
            excerpts = item.get("excerpts") or []
            results.append({
                "title": item.get("title") or "",
                "url": item.get("url") or "",
                "snippet": " ".join(excerpts)[:600],
                "published": item.get("publish_date") or "",
            })
        return {"results": results, "latency": elapsed, "cost": 0.005, "raw": data}

    def answer(self, q):
        body = {"model": "parallel", "input": q, "reasoning": {"effort": "low"}}
        data, elapsed = self._post("/v1/responses", body)
        answer, citations = _extract_openai_responses(data)
        return {"answer": answer, "citations": citations, "latency": elapsed, "cost": 0.02, "raw": data}


class LinkupClient(EngineClient):
    name = "linkup"

    def __init__(self, api_key):
        self.api_key = api_key

    def ready(self):
        return bool(self.api_key)

    def _post(self, body):
        t0 = time.time()
        try:
            r = requests.post("https://api.linkup.so/v1/search", json=body,
                              headers={"x-api-key": self.api_key}, timeout=TIMEOUT)
            data = r.json() if r.ok else {"error": r.text, "status": r.status_code}
        except Exception as e:
            return {"error": str(e)}, time.time() - t0
        return data, time.time() - t0

    def search(self, q):
        body = {"q": q, "depth": "standard", "outputType": "searchResults", "maxResults": 10}
        data, elapsed = self._post(body)
        results = []
        for item in data.get("results") or []:
            results.append({
                "title": item.get("name") or "",
                "url": item.get("url") or "",
                "snippet": item.get("content") or "",
                "published": "",
            })
        return {"results": results, "latency": elapsed, "cost": 0.005, "raw": data}

    def answer(self, q):
        body = {"q": q, "depth": "standard", "outputType": "sourcedAnswer",
                "includeInlineCitations": True, "maxResults": 8}
        data, elapsed = self._post(body)
        answer = data.get("answer") or ""
        citations = [s.get("url") for s in (data.get("sources") or []) if s.get("url")]
        return {"answer": answer, "citations": citations, "latency": elapsed, "cost": 0.006, "raw": data}


def _extract_openai_responses(data):
    if isinstance(data, dict) and data.get("type") == "error":
        return "", []
    text_parts = []
    urls = []
    if isinstance(data, dict):
        if data.get("output_text"):
            text_parts.append(data["output_text"])
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "message":
                for part in item.get("content") or []:
                    if isinstance(part, dict):
                        if part.get("text"):
                            text_parts.append(part["text"])
                        for ann in part.get("annotations") or []:
                            if isinstance(ann, dict) and ann.get("url"):
                                urls.append(ann["url"])
                for ann in item.get("annotations") or []:
                    if isinstance(ann, dict) and ann.get("url"):
                        urls.append(ann["url"])
    return "\n".join(p for p in text_parts if p), list(dict.fromkeys(urls))


def build_clients(cfg):
    return [
        ArlongClient(cfg["arlong_base_url"], cfg["arlong_api_key"], cfg["arlong_use_internal"]),
        ExaClient(cfg["exa_api_key"]),
        PerplexityClient(cfg["perplexity_api_key"], cfg["perplexity_model"]),
        ParallelClient(cfg["parallel_api_key"]),
        LinkupClient(cfg["linkup_api_key"]),
    ]
