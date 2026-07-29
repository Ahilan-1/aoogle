"""
Intelligent web crawler for arlong search engine.
Respects robots.txt, obeys rate limits, saves progress on Ctrl+C, deduplicates.
"""

import json, os, time, signal, sys, re, logging
from collections import OrderedDict
from urllib.parse import urlparse, urljoin, urldefrag
from urllib.robotparser import RobotFileParser
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('crawl')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOP_1M_CSV = os.path.join(BASE_DIR, 'top-1m.csv')
CRAWL_DATA_FILE = os.path.join(BASE_DIR, 'crawldata.json')
CRAWL_STATUS_FILE = os.path.join(BASE_DIR, 'crawl-status.json')

MAX_SEEDS = 1000
MAX_DEPTH = 2
DEFAULT_DELAY = 1.0
MAX_RETRIES = 2
REQUEST_TIMEOUT = 15
MAX_TEXT_SNIPPET_LEN = 500
MAX_CRAWL_DATA_SIZE = 50000

IMPORTANT_DOMAINS = [
    'en.wikipedia.org', 'wikipedia.org',
    'imdb.com', 'stackoverflow.com', 'github.com',
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com',
    'reddit.com', 'youtube.com', 'medium.com',
    'nih.gov', 'who.int', 'w3.org',
    'python.org', 'mozilla.org', 'googleblog.com',
    'nature.com', 'sciencedirect.com', 'plos.org',
    'britannica.com', 'merriam-webster.com',
    'quora.com', 'investopedia.com', 'reuters.com',
    'npr.org', 'theguardian.com', 'wired.com',
    'forbes.com', 'bloomberg.com', 'news.ycombinator.com',
]

class Crawler:
    def __init__(self):
        self.ua = UserAgent()
        self.session = requests.Session()
        self.session.headers.update({'Accept-Language': 'en-US,en;q=0.9'})
        self.running = True
        self.status = self._load_status()
        self._save_timer = 0

    # ── Persistence ──

    def _load_status(self):
        if os.path.exists(CRAWL_STATUS_FILE):
            try:
                with open(CRAWL_STATUS_FILE, 'r') as f:
                    data = json.load(f)
                log.info(f"Loaded saved progress: {data['stats']['crawled']} crawled, "
                         f"{len(data['pending_queue'])} pending, "
                         f"{len(data['visited'])} visited")
                return data
            except Exception as e:
                log.warning(f"Failed to load status file: {e}")
        return self._fresh_status()

    def _fresh_status(self):
        return {
            'pending_queue': [],
            'visited': [],
            'crawled_urls': [],
            'domain_delays': {},
            'robots_cache': {},
            'stats': {
                'crawled': 0,
                'errors': 0,
                'skipped': 0,
                'total_queued': 0,
                'started_at': datetime.now(timezone.utc).isoformat(),
                'last_saved': '',
            },
            'seed_index': 0,
        }

    def save_status(self):
        self.status['stats']['last_saved'] = datetime.now(timezone.utc).isoformat()
        tmp = CRAWL_STATUS_FILE + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(self.status, f, indent=2)
            os.replace(tmp, CRAWL_STATUS_FILE)
            log.info(f"Saved progress: {self.status['stats']['crawled']} crawled, "
                     f"{len(self.status['pending_queue'])} pending")
        except Exception as e:
            log.error(f"Failed to save status: {e}")

    def load_crawldata(self):
        if os.path.exists(CRAWL_DATA_FILE):
            try:
                with open(CRAWL_DATA_FILE, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_crawldata(self, data):
        tmp = CRAWL_DATA_FILE + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, CRAWL_DATA_FILE)
        except Exception as e:
            log.error(f"Failed to save crawldata: {e}")

    # ── Seed Loading ──

    def load_seeds(self):
        seeds = []
        if os.path.exists(TOP_1M_CSV):
            try:
                with open(TOP_1M_CSV, 'r') as f:
                    for i, line in enumerate(f):
                        if i >= MAX_SEEDS:
                            break
                        line = line.strip()
                        if not line or ',' not in line:
                            continue
                        parts = line.split(',', 1)
                        domain = parts[1].strip().lower()
                        if domain:
                            seeds.append('https://' + domain)
            except Exception as e:
                log.error(f"Error reading top-1m.csv: {e}")
        for d in IMPORTANT_DOMAINS:
            url = 'https://' + d
            if url not in seeds:
                seeds.append(url)
        log.info(f"Loaded {len(seeds)} seed URLs ({MAX_SEEDS} from top-1m + {len(IMPORTANT_DOMAINS)} important)")
        return seeds

    # ── Robots.txt ──

    def _get_robots_key(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _fetch_robots(self, url):
        key = self._get_robots_key(url)
        if key in self.status['robots_cache']:
            return self.status['robots_cache'][key]
        rp = RobotFileParser()
        robots_url = urljoin(key + '/', '/robots.txt')
        rp.set_url(robots_url)
        delay = DEFAULT_DELAY
        try:
            rp.read()
            delay = rp.crawl_delay('*') or DEFAULT_DELAY
            log.info(f"  robots.txt: {robots_url} delay={delay}s")
        except Exception as e:
            log.warning(f"  robots.txt failed for {key}: {e}")
            rp = None
        cache = {'rp': rp, 'crawl_delay': delay, 'fetched_at': time.time()}
        self.status['robots_cache'][key] = cache
        return cache

    def can_fetch(self, url):
        key = self._get_robots_key(url)
        cache = self._fetch_robots(url)
        if cache['rp'] is None:
            return True
        return cache['rp'].can_fetch('*', url)

    def get_delay(self, url):
        key = self._get_robots_key(url)
        cache = self._fetch_robots(url)
        return max(cache['crawl_delay'], DEFAULT_DELAY)

    # ── Rate Limiting ──

    def _respect_rate_limit(self, url):
        domain = urlparse(url).netloc
        last = self.status['domain_delays'].get(domain, 0)
        delay = self.get_delay(url)
        elapsed = time.time() - last
        if elapsed < delay:
            sleep_time = delay - elapsed
            time.sleep(sleep_time)

    def _mark_crawled_domain(self, url):
        domain = urlparse(url).netloc
        self.status['domain_delays'][domain] = time.time()

    # ── Crawl a Single URL ──

    def crawl_url(self, url, depth):
        self._respect_rate_limit(url)
        parsed = urlparse(url)
        domain = parsed.netloc
        result = None
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT,
                                        headers={'User-Agent': self.ua.random,
                                                 'Accept': 'text/html,application/xhtml+xml'})
                self._mark_crawled_domain(url)
                if resp.status_code != 200:
                    log.warning(f"  [{resp.status_code}] skipped")
                    return None
                ct = resp.headers.get('Content-Type', '')
                if 'text/html' not in ct and 'application/xhtml' not in ct:
                    log.info(f"  non-HTML ({ct.split(';')[0]}), skipped")
                    return None
                html = resp.text
                if not html or len(html) < 50:
                    return None
                soup = BeautifulSoup(html, 'html.parser')
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()[:200]
                else:
                    title = ''
                meta_desc = ''
                meta_keywords = ''
                og_title = ''
                og_description = ''
                og_image = ''
                canonical = ''
                for tag in soup.find_all('meta'):
                    name = (tag.get('name') or '').lower()
                    prop = (tag.get('property') or '').lower()
                    content = tag.get('content', '').strip()
                    if name == 'description':
                        meta_desc = content[:300]
                    elif name == 'keywords':
                        meta_keywords = content[:300]
                    elif prop == 'og:title':
                        og_title = content[:200]
                    elif prop == 'og:description':
                        og_description = content[:300]
                    elif prop == 'og:image':
                        og_image = content[:500]
                canon_tag = soup.find('link', rel='canonical')
                if canon_tag and canon_tag.get('href'):
                    canonical = canon_tag['href'].strip()
                h1_tag = soup.find('h1')
                h1 = h1_tag.get_text(strip=True)[:200] if h1_tag else ''
                for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside',
                                 'iframe', 'noscript', 'svg', 'form', 'button']):
                    tag.decompose()
                body = soup.find('body')
                text = body.get_text(separator=' ', strip=True) if body else ''
                text = re.sub(r'\s+', ' ', text).strip()
                word_count = len(text.split())
                text_snippet = text[:MAX_TEXT_SNIPPET_LEN]
                links = []
                internal_links = []
                external_links = []
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    full_url = urljoin(url, href)
                    full_url, _ = urldefrag(full_url)
                    if not full_url.startswith(('http://', 'https://')):
                        continue
                    if any(full_url.startswith(p) for p in
                           ['javascript:', 'mailto:', 'tel:', 'ftp:']):
                        continue
                    links.append(full_url)
                    if urlparse(full_url).netloc == domain:
                        internal_links.append(full_url)
                    else:
                        external_links.append(full_url)
                canonical_url = canonical or url
                crawled_data = {
                    'url': url,
                    'domain': domain,
                    'title': title,
                    'meta_description': meta_desc,
                    'meta_keywords': meta_keywords,
                    'h1': h1,
                    'text_snippet': text_snippet,
                    'word_count': word_count,
                    'canonical_url': canonical_url,
                    'og_title': og_title,
                    'og_description': og_description,
                    'og_image': og_image,
                    'status_code': resp.status_code,
                    'content_type': ct.split(';')[0].strip(),
                    'crawled_at': datetime.now(timezone.utc).isoformat(),
                    'depth': depth,
                }
                result = crawled_data
                next_links = []
                if depth < MAX_DEPTH:
                    for link in internal_links:
                        if link not in self.status['visited']:
                            next_links.append((link, depth + 1))
                log.info(f"  OK {len(text)} chars, {len(links)} links, "
                         f"{len(internal_links)} internal")
                return {'data': crawled_data, 'next_links': next_links}
            except requests.exceptions.Timeout:
                log.warning(f"  timeout (attempt {attempt+1}/{MAX_RETRIES})")
                continue
            except requests.exceptions.ConnectionError:
                log.warning(f"  connection error (attempt {attempt+1}/{MAX_RETRIES})")
                time.sleep(2)
                continue
            except Exception as e:
                log.warning(f"  error: {e}")
                return None
        return None

    # ── Main Loop ──

    def run(self):
        log.info("=" * 50)
        log.info("arlong Web Crawler starting")
        log.info("=" * 50)
        if not self.status['pending_queue'] and self.status['stats']['crawled'] == 0:
            seeds = self.load_seeds()
            for url in seeds:
                self._enqueue(url, depth=0)
            self.status['stats']['total_queued'] = len(seeds)
            self.save_status()
        elif not self.status['pending_queue'] and self.status['stats']['crawled'] > 0:
            log.info("Pending queue empty — crawl appears complete.")
            log.info(f"Total crawled: {self.status['stats']['crawled']}")
            return
        else:
            log.info(f"Resuming with {len(self.status['pending_queue'])} pending URLs")
        crawldata = self.load_crawldata()
        log.info(f"Loaded {len(crawldata)} existing crawl data entries")
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        try:
            while self.running and self.status['pending_queue']:
                entry = self.status['pending_queue'].pop(0)
                url = entry['url']
                depth = entry.get('depth', 0)
                if url in self.status['visited']:
                    continue
                domain = urlparse(url).netloc
                log.info(f"[{self.status['stats']['crawled']+1}] {url} (depth={depth})")
                if not self.can_fetch(url):
                    log.info(f"  disallowed by robots.txt, skipped")
                    self.status['visited'].append(url)
                    self.status['stats']['skipped'] += 1
                    self._maybe_save(crawldata)
                    continue
                result = self.crawl_url(url, depth)
                if result:
                    self.status['visited'].append(url)
                    self.status['crawled_urls'].append(url)
                    self._dedup_and_add(crawldata, result['data'])
                    self.status['stats']['crawled'] += 1
                    for next_url, next_depth in result['next_links']:
                        self._enqueue(next_url, next_depth)
                else:
                    self.status['visited'].append(url)
                    self.status['stats']['errors'] += 1
                self._maybe_save(crawldata)
            log.info(f"Crawl finished. Total crawled: {self.status['stats']['crawled']}")
        except Exception as e:
            log.error(f"Crawl loop error: {e}")
        finally:
            self.save_crawldata(crawldata)
            self.save_status()
            log.info(f"Final: {self.status['stats']['crawled']} crawled, "
                     f"{self.status['stats']['errors']} errors, "
                     f"{len(crawldata)} entries in crawldata.json")

    def _enqueue(self, url, depth):
        if url not in self.status['visited']:
            exists = any(e['url'] == url for e in self.status['pending_queue'])
            if not exists:
                self.status['pending_queue'].append({
                    'url': url,
                    'depth': depth,
                    'added_at': datetime.now(timezone.utc).isoformat(),
                })

    def _dedup_and_add(self, crawldata, entry):
        url = entry['url']
        crawldata[:] = [e for e in crawldata if e.get('url') != url]
        crawldata.append(entry)
        if len(crawldata) > MAX_CRAWL_DATA_SIZE:
            crawldata.sort(key=lambda x: _entry_score(x), reverse=True)
            crawldata[:] = crawldata[:MAX_CRAWL_DATA_SIZE]

    def _maybe_save(self, crawldata):
        now = time.time()
        if now - self._save_timer > 60:
            self.save_crawldata(crawldata)
            self.save_status()
            self._save_timer = now

    def _handle_signal(self, sig, frame):
        log.info(f"\n{'='*50}")
        log.info("Received interrupt — saving progress and shutting down...")
        self.running = False


def _entry_score(entry):
    priority = 0
    url = entry.get('url', '')
    title = entry.get('title', '')
    domain = entry.get('domain', '')
    word_count = entry.get('word_count', 0)
    depth = entry.get('depth', 99)
    if domain in IMPORTANT_DOMAINS:
        priority += 100
    if domain in ('google.com',):
        priority += 50
    if '.gov' in domain or '.edu' in domain:
        priority += 30
    if word_count >= 50:
        priority += 20
    if title:
        priority += 10
    if depth <= 1:
        priority += 10
    return priority


if __name__ == '__main__':
    c = Crawler()
    c.run()
