"""
arlong Web Crawler — production-grade, single-machine, 24/7.

Architecture:
  - crawldata.jsonl : JSON Lines index (append-only, easy dedup at read time)
  - crawl-status.json : queue + visited set + stats + robots cache
  - proxies.txt     : one proxy per line for rotation
  - Reads top-1m.csv for seed domains

Design:
  - Respects robots.txt with Crawl-Delay
  - Per-domain rate limiting with jitter
  - Proxy rotation with failure tracking
  - BFS with unlimited depth (configurable cap)
  - Ctrl+C / SIGTERM saves state instantly
  - JSONL avoids rewriting entire index on every save
  - Periodic compaction deduplicates crawldata.jsonl
"""

import json, os, time, signal, sys, re, random, logging, threading
from collections import deque
from urllib.parse import urlparse, urljoin, urldefrag
from urllib.robotparser import RobotFileParser
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# ── Config ──

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOP_1M_CSV        = os.path.join(BASE_DIR, 'top-1m.csv')
CRAWL_DATA_FILE   = os.path.join(BASE_DIR, 'crawldata.jsonl')
CRAWL_STATUS_FILE = os.path.join(BASE_DIR, 'crawl-status.json')
PROXY_FILE        = os.path.join(BASE_DIR, 'proxies.txt')

MAX_SEEDS           = 10000       # how many from top-1m.csv to queue
MAX_CRAWL           = 0           # 0 = unlimited per session
MAX_DEPTH           = 999999      # effectively unlimited
DEFAULT_DELAY       = 0.5         # base seconds between requests to same domain
TIMEOUT             = 20
MAX_RETRIES         = 3
SAVE_INTERVAL       = 15          # seconds between status saves
COMPACT_INTERVAL    = 1000        # compact crawldata.jsonl every N new entries
MAX_CRAWL_DATA      = 5000000     # max entries in crawldata.jsonl (5M)
MAX_VISITED         = 20000000    # max visited URLs tracked in memory
BATCH_LOG           = 100         # log a summary line every N pages

LOGGING_FORMAT = '[%(asctime)s] %(message)s'
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT, datefmt='%H:%M:%S')
log = logging.getLogger('crawl')

IMPORTANT_DOMAINS = [
    'en.wikipedia.org', 'wikipedia.org',
    'imdb.com', 'stackoverflow.com', 'github.com',
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com',
    'reddit.com', 'youtube.com', 'medium.com',
    'nih.gov', 'who.int', 'w3.org',
    'python.org', 'mozilla.org',
    'nature.com', 'plos.org', 'springer.com',
    'britannica.com', 'merriam-webster.com',
    'quora.com', 'investopedia.com', 'reuters.com',
    'npr.org', 'theguardian.com', 'wired.com',
    'forbes.com', 'bloomberg.com',
    'news.ycombinator.com', 'arxiv.org',
    'stackexchange.com', 'gitlab.com', 'bitbucket.org',
    'npmjs.com', 'pypi.org', 'crates.io',
    'docker.com', 'kubernetes.io', 'aws.amazon.com',
    'developer.mozilla.org', 'docs.python.org',
    'scholar.google.com', 'pubmed.ncbi.nlm.nih.gov',
    'un.org', 'europa.eu', 'state.gov',
    'whitehouse.gov', 'gov.uk', 'canada.ca',
    'worldbank.org', 'oecd.org', 'imf.org',
    'nasa.gov', 'noaa.gov', 'usgs.gov',
    'pewresearch.org', 'gutenberg.org',
    'tandfonline.com', 'wiley.com', 'elsevier.com',
    'cambridge.org', 'oxford.com',
]

HIGH_VALUE_PREFIXES = (
    '/wiki/', '/article/', '/blog/', '/news/', '/posts/',
    '/questions/', '/answers/', '/page/', '/content/',
    '/documentation/', '/docs/', '/guide/', '/tutorial/',
    '/publication/', '/paper/', '/research/', '/study/',
    '/about/', '/faq/', '/help/', '/support/',
    '/how-to/', '/what-is/', '/why-',
    '/topic/', '/category/', '/section/',
)

LOW_VALUE_PATTERNS = re.compile(
    r'(login|signup|register|logout|cart|checkout|shopping_cart|'
    r'wp-admin|wp-login|admin|dashboard|settings|profile|'
    r'edit|delete|remove|upload|download|share\?|'
    r'print|mailto|tel:|javascript:|ftp:|'
    r'calendar|event\?|tag/[^/]+/$|'
    r'category/[^/]+/$|page/\d+/\d+|\?page=\d+$|'
    r'#comment|replytocom|like=)',
    re.I
)

DELAY_JITTER = (0.75, 1.5)


# ── Helpers ──

def _normalise_url(url):
    url, _ = urldefrag(url)
    url = url.rstrip('/')
    return url


def _domain_of(url):
    return urlparse(url).netloc


def _is_html(url, ct):
    if not ct:
        return url.endswith(('.html', '.htm', '/')) or '.' not in url.split('/')[-1]
    return 'text/html' in ct or 'application/xhtml' in ct


def _is_near_duplicate(a, b):
    if not a or not b:
        return False
    return abs(len(a) - len(b)) / max(len(a), len(b), 1) < 0.15


# ── Crawler ──

class Crawler:
    def __init__(self):
        self.ua = UserAgent()
        self.sesh = requests.Session()
        self.sesh.headers.update({'Accept-Language': 'en-US,en;q=0.9'})
        self.proxies = self._load_proxies()
        self.proxy_index = 0
        self.proxy_blacklist = {}
        self.running = True
        self.status = self._load_status()
        self._save_timer = 0
        self._last_log_count = 0
        self._compact_counter = 0
        self._new_entry_count = 0
        self._write_lock = threading.Lock()
        self._crawldata_fp = None
        self._recent_titles = deque(maxlen=20)

    # ── Persistence ──

    def _load_status(self):
        if os.path.exists(CRAWL_STATUS_FILE) and os.path.getsize(CRAWL_STATUS_FILE) > 2:
            try:
                with open(CRAWL_STATUS_FILE, 'r') as f:
                    data = json.load(f)
                v = len(data.get('visited', []))
                q = len(data.get('pending_queue', []))
                log.info(f"Resumed: {v} visited, {q} queued, "
                         f"{data.get('stats', {}).get('crawled', 0)} crawled")
                return data
            except Exception as e:
                log.warning(f"Status load failed: {e}")
        return self._fresh_status()

    def _fresh_status(self):
        return {
            'pending_queue': [],
            'visited': [],
            'crawled_urls': [],
            'domain_delays': {},
            'robots_cache': {},
            'proxy_errors': {},
            'stats': {
                'crawled': 0,
                'errors': 0,
                'skipped': 0,
                'bytes_received': 0,
                'total_queued': 0,
                'started_at': datetime.now(timezone.utc).isoformat(),
                'last_saved': '',
            },
        }

    def save_status(self):
        self.status['stats']['last_saved'] = datetime.now(timezone.utc).isoformat()
        data = {
            'pending_queue': self.status['pending_queue'][:100000],
            'visited': list(self.status['visited']),
            'crawled_urls': list(self.status['crawled_urls']),
            'domain_delays': self.status['domain_delays'],
            'robots_cache': self.status['robots_cache'],
            'proxy_errors': self.status['proxy_errors'],
            'stats': self.status['stats'],
        }
        tmp = CRAWL_STATUS_FILE + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, CRAWL_STATUS_FILE)
        except Exception as e:
            log.error(f"Save status failed: {e}")

    # ── JSONL Index ──

    def _open_crawldata(self):
        if self._crawldata_fp is None:
            try:
                self._crawldata_fp = open(CRAWL_DATA_FILE, 'a', encoding='utf-8')
            except Exception as e:
                log.error(f"Failed to open crawldata: {e}")

    def _close_crawldata(self):
        if self._crawldata_fp:
            try:
                self._crawldata_fp.close()
            except:
                pass
            self._crawldata_fp = None

    def _append_crawldata(self, entry):
        self._open_crawldata()
        line = json.dumps(entry, ensure_ascii=False)
        with self._write_lock:
            try:
                self._crawldata_fp.write(line + '\n')
                self._crawldata_fp.flush()
            except Exception as e:
                log.error(f"Append to crawldata failed: {e}")
        self._new_entry_count += 1
        if self._new_entry_count >= COMPACT_INTERVAL:
            self._compact_crawldata()

    def _compact_crawldata(self):
        self._new_entry_count = 0
        log.info("Compacting crawldata.jsonl…")
        try:
            seen = {}
            if os.path.exists(CRAWL_DATA_FILE):
                with open(CRAWL_DATA_FILE, 'r', encoding='utf-8') as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            url = entry.get('url', '')
                            if url:
                                seen[url] = (line_no, entry)
                        except json.JSONDecodeError:
                            continue
            tmp = CRAWL_DATA_FILE + '.tmp'
            count = 0
            with open(tmp, 'w', encoding='utf-8') as f:
                for line_no, entry in sorted(seen.values(), key=lambda x: x[0]):
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                    count += 1
            os.replace(tmp, CRAWL_DATA_FILE)
            log.info(f"Compacted: {count} unique entries")
        except Exception as e:
            log.error(f"Compaction failed: {e}")

    def count_crawldata(self):
        if not os.path.exists(CRAWL_DATA_FILE):
            return 0
        try:
            with open(CRAWL_DATA_FILE, 'r') as f:
                return sum(1 for line in f if line.strip())
        except:
            return 0

    # ── Proxies ──

    def _load_proxies(self):
        proxies = []
        if os.path.exists(PROXY_FILE):
            try:
                with open(PROXY_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            proxies.append(line)
            except:
                pass
        if proxies:
            log.info(f"Loaded {len(proxies)} proxies")
        else:
            log.info("No proxies configured — using direct connection")
        return proxies

    def _next_proxy(self):
        if not self.proxies:
            return None
        now = time.time()
        for _ in range(len(self.proxies)):
            idx = self.proxy_index % len(self.proxies)
            self.proxy_index += 1
            proxy_url = self.proxies[idx]
            blacklisted_until = self.proxy_blacklist.get(proxy_url, 0)
            if now >= blacklisted_until:
                return proxy_url
            if blacklisted_until > now + 600:
                self.proxy_blacklist[proxy_url] = now + 600
        return self.proxies[self.proxy_index % len(self.proxies)]

    def _mark_proxy_bad(self, proxy_url):
        if proxy_url:
            penalty = min(self.proxy_blacklist.get(proxy_url, 0) + 30, 600)
            self.proxy_blacklist[proxy_url] = time.time() + penalty

    # ── Seeds ──

    def load_seeds(self):
        seeds = OrderedDict()
        if os.path.exists(TOP_1M_CSV):
            try:
                with open(TOP_1M_CSV, 'r') as f:
                    for i, line in enumerate(f):
                        if i >= MAX_SEEDS:
                            break
                        line = line.strip()
                        if not line or ',' not in line:
                            continue
                        domain = line.split(',', 1)[1].strip().lower()
                        if domain and len(domain) < 100:
                            seeds['https://' + domain] = None
            except Exception as e:
                log.error(f"Failed to read top-1m.csv: {e}")
        for d in IMPORTANT_DOMAINS:
            seeds['https://' + d] = None
        log.info(f"Seeds: {len(seeds)} ({MAX_SEEDS} from top-1m + {len(IMPORTANT_DOMAINS)} important)")
        return list(seeds.keys())

    # ── Robots.txt ──

    def _robots_key(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _robots_for(self, url):
        key = self._robots_key(url)
        if key in self.status['robots_cache']:
            return self.status['robots_cache'][key]
        rp = RobotFileParser()
        robots_url = urljoin(key + '/', 'robots.txt')
        rp.set_url(robots_url)
        delay = DEFAULT_DELAY
        try:
            with self.sesh.get(robots_url, timeout=10, headers={'User-Agent': 'arlong-crawler/1.0'}) as resp:
                if resp.status_code == 200:
                    rp.parse(resp.text.splitlines())
                    cd = rp.crawl_delay('*')
                    if cd:
                        delay = float(cd)
                    log.info(f"  robots: {robots_url} delay={delay}s")
                else:
                    rp = None
        except Exception:
            rp = None
        cache = {'rp': rp, 'delay': max(delay, DEFAULT_DELAY), 'fetched': time.time()}
        self.status['robots_cache'][key] = cache
        return cache

    def can_fetch(self, url):
        rc = self._robots_for(url)
        if rc['rp'] is None:
            return True
        return rc['rp'].can_fetch('*', url)

    def get_delay(self, url):
        rc = self._robots_for(url)
        jitter = random.uniform(*DELAY_JITTER)
        return max(rc['delay'] * jitter, DEFAULT_DELAY)

    # ── Rate Limit ──

    def _throttle(self, url):
        domain = _domain_of(url)
        last = self.status['domain_delays'].get(domain, 0)
        delay = self.get_delay(url)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)

    def _touch_domain(self, url):
        self.status['domain_delays'][_domain_of(url)] = time.time()

    # ── Crawl One URL ──

    def crawl_url(self, url, depth):
        self._throttle(url)
        url_norm = _normalise_url(url)
        proxy = self._next_proxy()
        proxies = {'http': proxy, 'https': proxy} if proxy else None

        for attempt in range(MAX_RETRIES):
            try:
                resp = self.sesh.get(
                    url_norm, timeout=TIMEOUT,
                    headers={'User-Agent': self.ua.random,
                             'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                             'Accept-Encoding': 'gzip, deflate'},
                    proxies=proxies,
                )
                self._touch_domain(url_norm)
                if resp.status_code != 200:
                    if resp.status_code in (429, 503):
                        delay = float(resp.headers.get('Retry-After', 5))
                        log.info(f"  rate-limited ({resp.status_code}), waiting {delay}s")
                        time.sleep(min(delay, 30))
                        continue
                    return None
                ct = resp.headers.get('Content-Type', '')
                if not _is_html(url_norm, ct):
                    return None
                html = resp.text
                if not html or len(html) < 100:
                    return None
                self.status['stats']['bytes_received'] += len(resp.content)
                soup = BeautifulSoup(html, 'html.parser')
                title = soup.title.get_text(strip=True)[:300] if soup.title and soup.title.string else ''
                meta_desc = ''
                meta_keywords = ''
                og_title = ''
                og_desc = ''
                og_image = ''
                og_site = ''
                canonical = ''
                author = ''
                published = ''
                for tag in soup.find_all('meta'):
                    n = (tag.get('name') or '').lower().strip()
                    p = (tag.get('property') or '').lower().strip()
                    c = tag.get('content', '').strip()
                    if n == 'description':
                        meta_desc = c[:500]
                    elif n == 'keywords':
                        meta_keywords = c[:500]
                    elif n == 'author':
                        author = c[:200]
                    elif p == 'og:title':
                        og_title = c[:300]
                    elif p == 'og:description':
                        og_desc = c[:500]
                    elif p == 'og:image':
                        og_image = c[:1000]
                    elif p == 'og:site_name':
                        og_site = c[:200]
                    elif p == 'article:published_time':
                        published = c[:30]
                canon = soup.find('link', rel='canonical')
                if canon and canon.get('href'):
                    canonical = canon['href'].strip()
                time_tag = soup.find('time')
                if time_tag and time_tag.get('datetime') and not published:
                    published = time_tag['datetime'][:30]
                h1_tag = soup.find('h1')
                h1 = h1_tag.get_text(strip=True)[:300] if h1_tag else ''
                for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside',
                                 'iframe', 'noscript', 'svg', 'form', 'button',
                                 'select', 'input', 'textarea']):
                    tag.decompose()
                body = soup.find('body')
                text = body.get_text(separator=' ', strip=True) if body else html
                text = re.sub(r'\s{2,}', ' ', text).strip()
                word_count = len(text.split())
                text_snippet = text[:800]
                internal_links = []
                external_links = []
                seen_links = set()
                domain = _domain_of(url_norm)
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    if not href or href.startswith(('javascript:', 'mailto:', 'tel:', 'ftp:')):
                        continue
                    full = _normalise_url(urljoin(url_norm, href))
                    if not full.startswith(('http://', 'https://')):
                        continue
                    if full in seen_links:
                        continue
                    seen_links.add(full)
                    if _domain_of(full) == domain:
                        internal_links.append(full)
                    else:
                        external_links.append(full)
                entry = {
                    'url': url_norm,
                    'domain': domain,
                    'title': title,
                    'meta_description': meta_desc,
                    'meta_keywords': meta_keywords,
                    'h1': h1,
                    'text_snippet': text_snippet,
                    'word_count': word_count,
                    'canonical_url': canonical or url_norm,
                    'og_title': og_title,
                    'og_description': og_desc,
                    'og_image': og_image,
                    'og_site_name': og_site,
                    'author': author,
                    'published': published,
                    'status_code': resp.status_code,
                    'content_type': ct.split(';')[0].strip(),
                    'crawled_at': datetime.now(timezone.utc).isoformat(),
                    'depth': depth,
                }
                next_urls = []
                if depth < MAX_DEPTH:
                    for link in internal_links:
                        if link not in self.status['visited']:
                            if not LOW_VALUE_PATTERNS.search(link):
                                depth_bonus = 1 if any(link.startswith(p) for p in HIGH_VALUE_PREFIXES) else 0
                                next_urls.append((link, depth + 1 - depth_bonus))
                for link in external_links:
                    if (link not in self.status['visited'] and
                        link not in [e['url'] for e in self.status['pending_queue'][:100]]):
                        if not LOW_VALUE_PATTERNS.search(link):
                            ext_domain = _domain_of(link)
                            if ext_domain in IMPORTANT_DOMAINS:
                                next_urls.append((link, depth + 1))
                log.info(f"  OK {word_count}w, {len(internal_links)}i/{len(external_links)}e links")
                return {'data': entry, 'next_links': next_urls}
            except requests.exceptions.Timeout:
                log.warning(f"  timeout (a{attempt+1}/{MAX_RETRIES})")
                continue
            except requests.exceptions.ConnectionError:
                if proxy:
                    self._mark_proxy_bad(proxy)
                log.warning(f"  connection err (a{attempt+1}/{MAX_RETRIES})")
                time.sleep(2 ** attempt)
                continue
            except requests.exceptions.ProxyError:
                if proxy:
                    self._mark_proxy_bad(proxy)
                log.warning(f"  proxy err (a{attempt+1}/{MAX_RETRIES})")
                time.sleep(2)
                continue
            except Exception as e:
                log.warning(f"  error: {e}")
                return None
        return None

    # ── Enqueue ──

    def _enqueue(self, url, depth):
        url_norm = _normalise_url(url)
        if url_norm in self.status['visited']:
            return
        for qe in self.status['pending_queue']:
            if qe['url'] == url_norm:
                return
        if len(self.status['visited']) >= MAX_VISITED:
            return
        self.status['pending_queue'].append({
            'url': url_norm,
            'depth': min(depth, MAX_DEPTH),
            'added': datetime.now(timezone.utc).isoformat(),
        })

    # ── Dedup ──

    def _dedup_and_append(self, entry):
        url = entry['url']
        self.status['crawled_urls'].append(url)
        self._append_crawldata(entry)

    # ── Main Loop ──

    def run(self):
        log.info("=" * 56)
        log.info("  arlong Web Crawler  v2")
        log.info("=" * 56)
        if self.status['stats']['crawled'] == 0:
            seeds = self.load_seeds()
            for url in seeds:
                self._enqueue(url, 0)
            self.status['stats']['total_queued'] = len(self.status['pending_queue'])
            log.info(f"Queued {len(seeds)} seeds")
            self.save_status()
        else:
            log.info(f"Resume: {self.status['stats']['crawled']} done, "
                     f"{len(self.status['pending_queue'])} queued, "
                     f"{self.count_crawldata()} in index")
        crawldata_count = self.count_crawldata()
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        n_this_session = 0
        try:
            while self.running and self.status['pending_queue']:
                if MAX_CRAWL and n_this_session >= MAX_CRAWL:
                    log.info(f"Reached session limit ({MAX_CRAWL})")
                    break
                entry = self.status['pending_queue'].pop(0)
                url = entry['url']
                depth = entry.get('depth', 0)
                if url in self.status['visited'] or len(self.status['visited']) >= MAX_VISITED:
                    continue
                self.status['visited'].append(url)
                n_this_session += 1
                log.info(f"[{self.status['stats']['crawled']+1}/{self.status['stats']['total_queued']}] {url} d={depth}")
                if not self.can_fetch(url):
                    log.info(f"  robots disallowed, skip")
                    self.status['stats']['skipped'] += 1
                    self._maybe_save()
                    continue
                result = self.crawl_url(url, depth)
                if result:
                    self._dedup_and_append(result['data'])
                    self.status['stats']['crawled'] += 1
                    for nu, nd in result['next_links']:
                        self._enqueue(nu, nd)
                else:
                    self.status['stats']['errors'] += 1
                if n_this_session % BATCH_LOG == 0:
                    q = len(self.status['pending_queue'])
                    v = len(self.status['visited'])
                    ix = self.count_crawldata()
                    log.info(f"  ── [{n_this_session}] q={q} v={v} idx={ix} "
                             f"err={self.status['stats']['errors']} ──")
                self._maybe_save()
        except Exception as e:
            log.error(f"Fatal: {e}")
        finally:
            self._shutdown()

    def shutdown(self):
        self.running = False

    def _shutdown(self):
        self._close_crawldata()
        self._compact_crawldata()
        self._close_crawldata()
        self.save_status()
        ct = self.count_crawldata()
        log.info(f"── SHUTDOWN ──")
        log.info(f"  Session     : {self.status['stats']['crawled']} crawled, "
                 f"{self.status['stats']['errors']} errors, "
                 f"{self.status['stats']['skipped']} skipped")
        log.info(f"  Total index : {ct} entries in crawldata.jsonl")
        log.info(f"  Queue       : {len(self.status['pending_queue'])} pending URLs")
        log.info(f"  To resume   : python crawl.py")

    def _maybe_save(self):
        now = time.time()
        if now - self._save_timer > SAVE_INTERVAL:
            self.save_status()
            self._save_timer = now

    def _handle_signal(self, sig, frame):
        log.info(f"\n{'='*56}")
        log.info("  INTERRUPT — saving state...")
        self.running = False


# ── Entry Point ──

if __name__ == '__main__':
    c = Crawler()
    c.run()
