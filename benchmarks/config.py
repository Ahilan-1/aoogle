import os


def _parse_env_file(path):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val:
                values[key] = val
    return values


def load_config():
    bench_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(bench_dir)
    env = _parse_env_file(os.path.join(root_dir, ".env"))
    env.update(_parse_env_file(os.path.join(bench_dir, ".env.bench")))
    for key, val in list(env.items()):
        os.environ.setdefault(key, val)

    def get(name, default=""):
        return os.environ.get(name, default)

    return {
        "arlong_base_url": get("ARLONG_BASE_URL", "https://arlong.org").rstrip("/"),
        "arlong_api_key": get("ARLONG_API_KEY"),
        "arlong_use_internal": get("ARLONG_USE_INTERNAL", "1") in ("1", "true", "yes", "on"),
        "exa_api_key": get("EXA_API_KEY"),
        "perplexity_api_key": get("PERPLEXITY_API_KEY"),
        "perplexity_model": get("PERPLEXITY_MODEL", "sonar"),
        "parallel_api_key": get("PARALLEL_API_KEY"),
        "linkup_api_key": get("LINKUP_API_KEY"),
        "groq_api_key": get("GROQ_API_KEY"),
        "judge_model": get("JUDGE_MODEL", "llama-3.3-70b-versatile"),
    }
