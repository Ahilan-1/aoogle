from flask import Flask, render_template, request, jsonify, abort, session, redirect, url_for, make_response, send_file
import io
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import logging
from logging.handlers import RotatingFileHandler
import time
import random
import json
from urllib.parse import urlparse, quote_plus, parse_qs, unquote
try:
    import redis
    redis_available = True
except ImportError:
    redis_available = False
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, ALL_COMPLETED
try:
    import boto3
    from botocore.exceptions import ClientError
    s3_available = True
except ImportError:
    s3_available = False
from datetime import datetime, timedelta
import markdown
import hashlib
import base64 as _b64mod
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import uuid
import re
import string
import threading
import os
import ssl
import httpx

import resend
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler_available = True
except ImportError:
    scheduler_available = False
try:
    from ddgs import DDGS
    ddgs_available = True
except ImportError:
    ddgs_available = False

# ── Encryption layer (AES-256-GCM) ──
_ENCRYPTION_KEY_HEX = os.environ.get('ENCRYPTION_KEY', '')
if not _ENCRYPTION_KEY_HEX:
    _ENCRYPTION_KEY_HEX = secrets.token_hex(32)
_ENC_KEY = bytes.fromhex(_ENCRYPTION_KEY_HEX)

def _enc(plaintext):
    iv = os.urandom(12)
    ct = AESGCM(_ENC_KEY).encrypt(iv, plaintext.encode('utf-8'), None)
    return _b64mod.b64encode(iv).decode(), _b64mod.b64encode(ct).decode()

def _dec(iv_b64, ct_b64):
    iv = _b64mod.b64decode(iv_b64)
    ct = _b64mod.b64decode(ct_b64)
    return AESGCM(_ENC_KEY).decrypt(iv, ct, None).decode('utf-8')

# ── Engine suspension (anti-block) ──
ENGINE_BAN_TIMES = {}  # engine_name -> timestamp until suspended
ENGINE_BAN_LOCK = threading.Lock()

def _is_engine_banned(engine):
    with ENGINE_BAN_LOCK:
        until = ENGINE_BAN_TIMES.get(engine, 0)
        if until > time.time():
            return True
        return False

def _ban_engine(engine, duration=3600):
    with ENGINE_BAN_LOCK:
        ENGINE_BAN_TIMES[engine] = time.time() + duration

def _shuffle_tls_context():
    """Create SSL context with shuffled ciphers — defeats JA3 fingerprinting (SearXNG technique)."""
    ctx = httpx.create_ssl_context(verify=True)
    try:
        ciphers = ctx.get_ciphers()
        names = [c['name'] for c in ciphers]
        fixed, rest = names[:3], names[3:]
        random.shuffle(rest)
        ctx.set_ciphers(':'.join(fixed + rest))
    except Exception:
        pass
    return ctx

_FIREFOX_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0',
]

def _get_browser_headers():
    """Default headers matching SearXNG's processor output."""
    return {
        'Accept-Encoding': 'gzip, deflate',
        'Cache-Control': 'no-cache',
        'DNT': '1',
        'Connection': 'keep-alive',
        'User-Agent': random.choice(_FIREFOX_UAS),
        'Accept-Language': 'en-US,en;q=0.9',
    }

_GOOGLE_CONSENT_COOKIE = 'CONSENT=YES+'

def _search_google(query, max_results=5):
    """Scrape Google via HTML — uses SearXNG's TLS shuffling + CONSENT cookie.
    Note: Google's SERP is now JS-rendered; this is best-effort and often returns nothing."""
    if _is_engine_banned('google'):
        return []
    try:
        with httpx.Client(verify=_shuffle_tls_context(), http2=True, timeout=3.0, follow_redirects=False) as client:
            resp = client.get(
                'https://www.google.com/search',
                params={'q': query, 'hl': 'en', 'num': str(min(max_results, 10)), 'filter': '0'},
                headers={**_get_browser_headers(), 'Accept': '*/*'},
                cookies={'CONSENT': 'YES+'},
            )
        text = resp.text
        if len(text) < 2000 and '/sorry/' in text:
            _ban_engine('google', 3600)
            return []
        if resp.url.host == 'sorry.google.com' or '/sorry/' in resp.url.path:
            _ban_engine('google', 3600)
            return []
        soup = BeautifulSoup(text, 'html.parser')
        results = []
        for g in soup.find_all('div', class_='g'):
            a = g.find('a', href=True)
            if not a:
                continue
            href = a.get('href', '')
            if href.startswith('/url?q='):
                href = unquote(href[7:].split('&sa=U')[0])
            if not href.startswith('http'):
                continue
            title = a.get_text(strip=True)
            if not title:
                h3 = g.find(['h3', 'h2'])
                title = h3.get_text(strip=True) if h3 else ''
            if not title:
                continue
            snippet_div = g.find('div', style=lambda s: s and '-webkit-line-clamp' in str(s))
            snippet = snippet_div.get_text(strip=True)[:300] if snippet_div else ''
            results.append(SearchResult(
                title=title, url=href, snippet=snippet, category='general',
                domain=urlparse(href).netloc
            ))
            if len(results) >= max_results:
                break
        return results
    except httpx.TimeoutException:
        return []
    except Exception as e:
        app.logger.error(f"Google search error: {e}")
        return []

def _search_brave(query, max_results=5):
    """Scrape Brave Search via HTML — exact SearXNG method (Firefox UA, HTTP/2, TLS shuffling, proper cookies)."""
    if _is_engine_banned('brave'):
        return []
    try:
        with httpx.Client(verify=_shuffle_tls_context(), http2=True, timeout=5.0, follow_redirects=True) as client:
            resp = client.get(
                'https://search.brave.com/search',
                params={'q': query, 'source': 'web'},
                headers=_get_browser_headers(),
                cookies={
                    'safesearch': 'off',
                    'useLocation': '0',
                    'summarizer': '0',
                    'country': 'us',
                    'ui_lang': 'en-us',
                },
            )
        if resp.status_code != 200:
            _ban_engine('brave', 1800)
            return []
        soup = BeautifulSoup(resp.text, 'html.parser')
        results = []
        for snippet in soup.find_all('div', class_=lambda c: c and 'snippet' in (c.split() if isinstance(c, str) else c)):
            a = snippet.find('a', href=True)
            if not a:
                continue
            href = a.get('href', '')
            if not href.startswith('http'):
                continue
            title_el = snippet.find(['h2', 'h3', 'div'], class_=lambda c: c and 'title' in str(c).lower().split())
            title = title_el.get_text(strip=True) if title_el else a.get_text(strip=True)
            if not title:
                continue
            desc_div = snippet.find('div', class_=lambda c: c and 'content' in str(c).lower().split())
            desc = desc_div.get_text(strip=True)[:300] if desc_div else ''
            results.append(SearchResult(
                title=title, url=href, snippet=desc, category='general',
                domain=urlparse(href).netloc
            ))
            if len(results) >= max_results:
                break
        return results
    except httpx.TimeoutException:
        return []
    except Exception as e:
        app.logger.error(f"Brave search error: {e}")
        return []

app = Flask(__name__)

# Load .env file manually
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ.setdefault(key.strip(), val.strip())

app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            app.secret_key = f.read().strip()
    else:
        app.secret_key = secrets.token_hex(32)
        with open(key_file, 'w') as f:
            f.write(app.secret_key)
        app.logger.info("Generated persistent secret key.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    UPLOAD_FOLDER=os.path.join(os.path.dirname(__file__), 'static', 'uploads'),
)

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_hex(16)
    app.logger.warning("No ADMIN_PASSWORD set in environment. Generated random password - check logs to retrieve it.")
AMAZON_ASSOCIATE_TAG = os.environ.get('AMAZON_ASSOCIATE_TAG', '')

# ── Places (Google Places API, fallback Serper.dev) ──
SERPER_API_KEY = os.environ.get('SERPER_API_KEY', '')
SERPER_PLACES_URL = 'https://google.serper.dev/places'
GOOGLE_PLACES_API_KEY = os.environ.get('GOOGLE_PLACES_API_KEY', '')
GOOGLE_PLACES_TEXTSEARCH_URL = 'https://maps.googleapis.com/maps/api/place/textsearch/json'
GOOGLE_PLACES_RADIUS_M = 50000
PLACES_CACHE_TTL = 7 * 24 * 3600  # 7 days
PLACES_CACHE_VERSION = 2  # bump to invalidate old cached places (schema changes)
PLACES_GEO_TTL = 90 * 24 * 3600  # geocode cache: 90 days
PLACES_RADIUS_KM = 100  # drop places farther than this from the requested location
PLACES_MAX_RESULTS = 4  # cap shown results (also caps Place Details billing)
PLACES_GL_DEFAULT = 'in'
PLACES_PHOTO_URL = 'https://maps.googleapis.com/maps/api/place/photo'
PLACES_PHOTO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'places_photos')
PLACES_PHOTO_MAXWIDTH = 900  # largest Google photo size we fetch (billing per unique photo)
PLACES_PHOTO_MAX = 4  # max photos kept per place

_NEAR_ME_RE = re.compile(r'\b(near\s*me|nearby|around\s*me|closest\s*to\s*me|close\s*to\s*me|nearest\s+to\s+me)\b', re.IGNORECASE)
_PLACES_LOCATION_RE = re.compile(
    r'\b(?:near|in|around|inside|close\s+to|closest\s+to|nearest\s+to|nearby)\s+'
    r'((?:[A-Za-z][A-Za-z\'\-]*[\s\.]?){1,6})',
    re.IGNORECASE
)
_LOCATION_STOPWORDS = frozenset([
    'me','here','us','them','there','my','our','your','this','that','these','those',
    'the','a','an','and','or','to','for','from','with','by','at','on','in','of','is',
    'are','where','can','i','we','you','it','get','find','looking','some','any','all',
    'one','two','who','what','how','when','which','now','today','tonight','nowhere',
    'area','areas','town','city','place','places','nearby','around','best','top','good',
    'great','cheap','affordable','local','near',
])
_PLACES_LOCAL_WORDS = (
    'restaurant','restaurants','cafe','cafes','coffee','coffee shop','hotel','hotels',
    'hospital','hospitals','pharmacy','pharmacies','gas station','gym','salon','barber',
    'barbershop','supermarket','grocery','grocery store','bakery','pizza','dental',
    'dentist','doctor','doctors','clinic','bank','atm','movie theater','cinema','park',
    'spa','escape room','shopping','store','stores','shop','market','school','university',
    'library','church','temple','mosque','tourist','attraction','attractions','museum',
    'zoo','airport','station','mall','pet store','vet','garage','mechanic','plumber',
    'electrician','hair','nails','yoga','fitness','bar','pub','takeaway','delivery',
    'dhaba','eateries','breakfast','brunch','lunch','dinner','thali','hostel','clinics',
    'travel','sightseeing','places to visit','places to eat','eat out','where to eat',
)
# Known non-India cities/countries so bare names are NOT qualified with ", India"
_NON_INDIA_CITIES = frozenset([
    'new york','london','paris','dubai','singapore','toronto','sydney','melbourne',
    'boston','chicago','los angeles','san francisco','seattle','miami','houston',
    'dallas','atlanta','berlin','madrid','rome','amsterdam','tokyo','bangkok',
    'kuala lumpur','jakarta','manila','hong kong','shanghai','beijing','seoul',
    'sao paulo','cairo','lagos','nairobi','mexico city','vancouver','las vegas',
    'austin','denver','phoenix','philadelphia','washington','barcelona','lisbon',
    'prague','vienna','zurich','istanbul','riyadh','doha','colombo','dhaka',
    'kathmandu','kabul','perth','auckland','wellington','oslo','stockholm',
    'helsinki','copenhagen','moscow','warsaw','athens','munich','hamburg',
    'manchester','edinburgh','dublin','toronto','montreal','brisbane','adelaide',
])
_COUNTRY_NAMES_LC = frozenset([
    'india','usa','us','uk','england','britain','united kingdom','united states',
    'canada','australia','france','germany','spain','italy','japan','china','brazil',
    'russia','uae','qatar','saudi arabia','singapore','malaysia','thailand',
    'vietnam','indonesia','philippines','pakistan','bangladesh','nepal','sri lanka',
    'netherlands','switzerland','austria','belgium','portugal','ireland','scotland',
    'wales','mexico','argentina','chile','colombia','peru','south africa','egypt',
    'nigeria','kenya','new zealand','south korea','taiwan','hong kong','israel',
    'turkey','greece','poland','sweden','norway','denmark','finland',
])

def _enrich_places_location(location, gl):
    """Serper mis-geocodes bare city names (e.g. 'Chennai' -> Orlando, FL). When
    running in the India region, qualify bare non-global cities with ', India'."""
    loc = (location or '').strip()
    if not loc:
        return loc
    low = loc.lower().strip()
    if gl != 'in' or ',' in loc:
        return loc
    if low in _COUNTRY_NAMES_LC or low in _NON_INDIA_CITIES:
        return loc
    return loc + ', India'

# Major Indian cities (plus _NON_INDIA_CITIES) for typo correction (e.g. "mumabi" -> "mumbai")
_PLACES_KNOWN_CITIES = [
    'mumbai','delhi','new delhi','bengaluru','bangalore','hyderabad','chennai','kolkata',
    'pune','ahmedabad','jaipur','lucknow','surat','kochi','cochin','chandigarh','indore',
    'nagpur','goa','gurugram','gurgaon','noida','visakhapatnam','vijayawada','bhopal',
    'patna','thiruvananthapuram','trivandrum','mysuru','mysore','vadodara','coimbatore',
    'kanpur','ludhiana','agra','varanasi','amritsar','dehradun','raipur','ranchi',
    'guwahati','bhubaneswar','jodhpur','udaipur','shimla','panaji','pondicherry','puducherry',
    'madurai','salem','tiruchirappalli','trichy','kollam','kannur','mangalore','belagavi',
    'hubli','nashik','aurangabad','kolhapur','solapur','sangli','nanded','jabalpur',
    'gwalior','meerut','faridabad','ghaziabad','gandhinagar','rajkot','bhavnagar','jamnagar',
    'jammu','srinagar','shillong','aizawl','imphal','itanagar','kohima','agartala','gangtok',
    'leh','port blair','kavaratti','siliguri','durgapur','asansol','howrah','cuttack','puri',
    'bikaner','ajmer','alwar','kota','shimoga','ooty','kodaikanal','munnar','alleppey',
    'kottayam','palakkad','thane','kalyan','dombivli','ulhasnagar','vasai','virar','borivali',
    'juhu','andheri','bandra','dadar','worli','colaba','powai','navi mumbai','thiruvalla',
]
_PLACES_KNOWN_CITIES = tuple(sorted(set(_PLACES_KNOWN_CITIES) | set(_NON_INDIA_CITIES)))

def _levenshtein(a, b):
    la, lb = len(a), len(b)
    if la < lb:
        a, b, la, lb = b, a, lb, la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[lb]

def _correct_places_location(loc):
    """Fix common misspellings of known cities so Serper geocodes correctly."""
    low = (loc or '').strip().lower()
    if not low or len(low) < 3:
        return (loc or '').title()
    if low in _PLACES_KNOWN_CITIES:
        return ' '.join(w.title() for w in low.split())
    best, best_d = None, None
    for city in _PLACES_KNOWN_CITIES:
        d = _levenshtein(low, city)
        if best_d is None or d < best_d:
            best, best_d = city, d
    if best_d is not None and best_d <= 2:
        return best.title()
    return (loc or '').title()

_PLACES_CATEGORY_EMOJI = [
    (('escape','puzzle','game','arcade','toy'), '\U0001F9E9'),
    (('restaurant','food','cafe','coffee','bakery','pizza','dhaba','thali','breakfast','brunch','dinner','takeaway','bar','pub','eatery','grill','bbq'), '\U0001F37D\U0000FE0F'),
    (('hotel','resort','hostel','lodging','inn','stay','motel'), '\U0001F3E8'),
    (('hospital','clinic','medical','doctor','dental','dentist','pharmacy','drug','health'), '\U0001F3E5'),
    (('gas','petrol','fuel','charging'), '\u26FD'),
    (('gym','fitness','yoga','workout','crossfit'), '\U0001F3CB\U0000FE0F'),
    (('salon','barber','spa','nails','hair','beauty','tattoo'), '\U0001F487'),
    (('grocery','supermarket','market','store','shop','mall','retail'), '\U0001F6D2'),
    (('bank','atm','finance','credit union'), '\U0001F3E6'),
    (('park','zoo','museum','attraction','tourist','cinema','movie','theater','theatre','amusement','adventure'), '\U0001F3A1'),
    (('school','university','college','library','academy'), '\U0001F393'),
    (('church','temple','mosque','synagogue','worship'), '\u26EA'),
    (('airport','flight','aviation'), '\u2708\U0000FE0F'),
    (('pet','vet','animal','dog'), '\U0001F43E'),
    (('mechanic','garage','auto','car','tire','repair'), '\U0001F527'),
    (('travel','tour','sightseeing','agency'), '\U0001F9F3'),
]

def places_category_emoji(category):
    cat = (category or '').lower()
    for keywords, emoji in _PLACES_CATEGORY_EMOJI:
        if any(k in cat for k in keywords):
            return emoji
    return '\U0001F4CD'

_PLACES_AVATAR_GRADIENTS = [
    'linear-gradient(135deg,#4285f4,#0f63d8)',
    'linear-gradient(135deg,#34a853,#1e8e3e)',
    'linear-gradient(135deg,#fbbc04,#e37400)',
    'linear-gradient(135deg,#ea4335,#c5221f)',
    'linear-gradient(135deg,#9334e6,#7627bb)',
    'linear-gradient(135deg,#12b5cb,#0a7d8c)',
    'linear-gradient(135deg,#f0643b,#d23b0f)',
    'linear-gradient(135deg,#5c6bc0,#3f51b5)',
]

def places_avatar_style(category, title):
    seed = (category or '') + '|' + (title or '')
    idx = int(hashlib.md5(seed.encode('utf-8')).hexdigest(), 16) % len(_PLACES_AVATAR_GRADIENTS)
    return _PLACES_AVATAR_GRADIENTS[idx]

app.jinja_env.globals['places_category_emoji'] = places_category_emoji
app.jinja_env.globals['places_avatar_style'] = places_avatar_style

# ── Resend (Email) ──
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
RESEND_FROM = os.environ.get('RESEND_FROM', 'onboarding@resend.dev')
resend.api_key = RESEND_API_KEY

# ── Session validation middleware ──
PUBLIC_PATHS = {'/', '/search', '/login', '/signup', '/land', '/logout',
    '/premium', '/explore', '/docs', '/stats', '/settings',
    '/privacy-policy', '/terms-of-service', '/refund-policy', '/faq',
    '/about', '/blog', '/redeem', '/changelogs', '/policy', '/submit',
    '/privacy'}

@app.before_request
def validate_session():
    if request.path.startswith('/static/') or request.path.startswith('/api/'):
        return
    user_id = session.get('user_id')
    if user_id and not data_manager.get_user_by_id(user_id):
        session.clear()
    # Also Sync username in case it changed
    if user_id:
        user = data_manager.get_user_by_id(user_id)
        if user and session.get('username') != user.get('username'):
            session['username'] = user['username']

# ── Currents API (News) ──
CURRENTS_API_KEY = os.environ.get('CURRENTS_API_KEY', '')
NEWS_CACHE = {}  # populated by background updater every 30 min
NEWS_CACHE_LOCK = threading.Lock()
CATEGORY_SOURCE_LABELS = {
    'top': 'Top Stories', 'world': 'World', 'tech': 'Technology',
    'business': 'Business', 'science': 'Science', 'health': 'Health',
    'sports': 'Sports', 'entertainment': 'Entertainment',
    'gaming': 'Gaming', 'economy': 'Economy', 'asian': 'Asian News',
}

# ── Background News Updater (Currents API + Premium RSS) ──
CURRENTS_CATEGORY_ENDPOINTS = {
    'top': '',
    'world': 'world',
    'tech': 'technology',
    'business': 'business',
    'science': 'science',
    'health': 'health',
    'sports': 'sports',
    'entertainment': 'entertainment',
    'gaming': 'game',
    'economy': 'finance',
    'asian': '',
}

PREMIUM_RSS_FEEDS = {
    'top': [
        ('NYT', 'https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml'),
    ],
    'world': [
        ('BBC', 'https://feeds.bbci.co.uk/news/world/rss.xml'),
    ],
    'tech': [
        ('TechCrunch', 'https://techcrunch.com/feed/'),
    ],
    'business': [
        ('BBC', 'https://feeds.bbci.co.uk/news/business/rss.xml'),
    ],
    'science': [
        ('New Scientist', 'https://www.newscientist.com/feed/home'),
    ],
    'health': [
        ('BBC', 'https://feeds.bbci.co.uk/news/health/rss.xml'),
    ],
    'sports': [
        ('BBC', 'https://feeds.bbci.co.uk/sport/rss.xml'),
    ],
    'entertainment': [
        ('Variety', 'https://variety.com/feed/'),
    ],
    'gaming': [
        ('IGN', 'https://feeds.feedburner.com/ign/all'),
    ],
    'economy': [
        ('BBC', 'https://feeds.bbci.co.uk/news/business/rss.xml'),
    ],
    'asian': [
        ('BBC', 'https://feeds.bbci.co.uk/news/world/asia/rss.xml'),
    ],
}

def _fetch_currents_news(category_endpoint):
    """Fetch news for a single Currents API category."""
    api_key = CURRENTS_API_KEY
    if not api_key:
        return []
    params = {'language': 'en'}
    if category_endpoint:
        params['category'] = category_endpoint
    try:
        resp = requests.get(
            'https://api.currentsapi.services/v1/latest-news',
            params=params,
            headers={'Authorization': api_key},
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') != 'ok':
            return []
        return data.get('news', [])
    except Exception:
        return []

def _clean_news_img(url):
    if not url or url == 'None':
        return ''
    url = str(url).split('?')[0]
    if url.startswith('//'):
        url = 'https:' + url
    return url if url.startswith('http') else ''

def _extract_rss_image(entry):
    """Extract best image from an RSS entry."""
    try:
        if hasattr(entry, 'media_content') and entry.media_content:
            for m in entry.media_content:
                u = m.get('url', '')
                if u:
                    return u
        if hasattr(entry, 'media_thumbnail') and entry.media_thumbnail:
            for t in entry.media_thumbnail:
                u = t.get('url', '')
                if u:
                    return u
        if hasattr(entry, 'enclosures') and entry.enclosures:
            for e in entry.enclosures:
                u = e.get('url', '')
                if u:
                    return u
    except Exception:
        pass
    return ''

def _fetch_rss_items(feeds):
    """Fetch and parse RSS feeds, return deduped sorted items."""
    all_items = []
    seen_links = set()
    for source_name, url in feeds:
        try:
            import feedparser
            feed = feedparser.parse(url)
            feed_title = feed.feed.get('title', source_name).strip()
            for entry in feed.entries:
                link = entry.get('link', '')
                if link in seen_links:
                    continue
                seen_links.add(link)
                all_items.append({
                    'title': entry.get('title', 'Untitled'),
                    'link': link,
                    'published': entry.get('published', ''),
                    'source': feed_title,
                    'image': _extract_rss_image(entry),
                })
        except Exception:
            pass
    all_items.sort(key=lambda x: x.get('published', ''), reverse=True)
    return all_items

def _is_low_quality_news(item):
    """Filter out junk news items (app download prompts, clickbait with no real content)."""
    title = (item.get('title') or '').strip().lower()
    if len(title) < 10:
        return True
    junk_patterns = [
        'download', 'install the app', 'get the app', 'download the app',
        'bbc news app', 'sign up', 'subscribe to', 'click here',
        'watch live', 'listen live', 'live stream', 'up next',
    ]
    for pat in junk_patterns:
        if pat in title:
            return True
    return False

def _fetch_and_cache_news():
    """Fetch news from Currents API + premium RSS feeds per category, store in NEWS_CACHE."""
    global NEWS_CACHE
    grouped = {}
    for ui_cat in CATEGORY_SOURCE_LABELS:
        try:
            api_cat = CURRENTS_CATEGORY_ENDPOINTS.get(ui_cat, '')
            rss_feeds = PREMIUM_RSS_FEEDS.get(ui_cat, [])

            # Fetch both sources in parallel
            currents_items = []
            if CURRENTS_API_KEY:
                articles = _fetch_currents_news(api_cat)
                for a in articles:
                    item = {
                        'title': a.get('title', 'Untitled'),
                        'link': a.get('url', ''),
                        'published': a.get('published', ''),
                        'source': (a.get('author', '') or 'Currents').strip(),
                        'image': _clean_news_img(a.get('image', '')),
                    }
                    if not _is_low_quality_news(item):
                        currents_items.append(item)
            currents_items.sort(key=lambda x: x.get('published', ''), reverse=True)

            rss_items = _fetch_rss_items(rss_feeds)

            # Merge: RSS first (premium), then Currents, dedup by link, cap at 20
            seen = set()
            merged = []
            for item in rss_items + currents_items:
                link = item.get('link', '')
                if link and link in seen:
                    continue
                if link:
                    seen.add(link)
                merged.append(item)
                if len(merged) >= 20:
                    break

            grouped[ui_cat] = merged
        except Exception:
            grouped[ui_cat] = []

    # Fill empty categories with top news
    top_items = grouped.get('top', [])
    for cat in grouped:
        if not grouped[cat] and top_items:
            grouped[cat] = top_items[:15]

    with NEWS_CACHE_LOCK:
        NEWS_CACHE = grouped

def start_news_updater(app):
    """Start background thread to refresh news every 30 minutes."""
    def _run():
        # Initial fetch in background (don't block startup)
        try:
            _fetch_and_cache_news()
            app.logger.info("News cache populated on startup")
        except Exception as e:
            app.logger.error(f"News cache initial fetch failed: {e}")
        while True:
            time.sleep(1800)
            try:
                _fetch_and_cache_news()
            except Exception as e:
                app.logger.error(f"News cache refresh failed: {e}")
    t = threading.Thread(target=_run, daemon=True)
    t.start()

# Start background news updater
start_news_updater(app)


def _score_blog_for_newsstand(blog):
    """Score a blog post for newsstand inclusion. Higher = more addictive/clickable.
    Heavily penalizes spammy content and rewards originality, engagement velocity, and structure."""
    from datetime import datetime, timezone
    import math
    s = 0
    quality = blog.get('quality_score', 0)

    # Quality is the primary gate — anti-spam has already penalized spammy blogs
    if quality < 5:
        return 0

    # ── Core quality (30 pts) ──
    s += min(quality / 40, 1.0) * 30

    # ── Engagement (20 pts) ──
    views = blog.get('view_count', 0)
    upvotes = blog.get('upvote_count', 0)
    s += min(views / 80, 1.0) * 12
    s += min(upvotes / 8, 1.0) * 8

    # ── Recency with exponential decay (25 pts) ──
    # New posts get a massive boost; older posts fade faster than linear
    created = blog.get('created_at', '')
    age_hours = 168  # default 1 week
    if created:
        try:
            dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age_hours = max(0.1, (now - dt).total_seconds() / 3600)
        except Exception:
            pass
    # Exponential half-life of 48 hours — posts stay hot for ~2 days
    recency = math.exp(-age_hours / 48)
    s += recency * 25

    # ── Engagement velocity boost (15 pts) ──
    # New posts with fast engagement get a huge signal
    if age_hours < 72:
        velocity = (views + upvotes * 5) / max(age_hours, 0.5)
        s += min(velocity / 3, 1.0) * 15

    content = blog.get('content', '') or ''
    content_lower = content.lower()
    words = content_lower.split()
    word_count = max(1, len(words))

    # ── Originality bonus: personal experience signals (15 pts) ──
    first_person = sum(1 for p in [' i ', ' my ', ' i\'m ', ' i\'ve ', ' i tested ', ' i tried ',
                                    ' personally', ' my experience', ' my review',
                                    ' what i found', ' in my opinion', ' from my'] if p in content_lower)
    if first_person >= 3:
        s += 15
    elif first_person >= 1:
        s += 5

    # ── Research/data bonus (12 pts) ──
    research = sum(1 for p in [' study found', ' research shows', ' according to',
                                ' i measured', ' i compared', ' results showed',
                                ' my analysis', ' benchmark', ' case study',
                                ' performance data', ' side by side', ' data shows',
                                ' statistics show', ' evidence suggests'] if p in content_lower)
    if research >= 3:
        s += 12
    elif research >= 1:
        s += 5

    # ── Content structure bonus (10 pts) ──
    # Well-structured posts with headings, lists, and paragraphs rank higher
    structure_score = 0
    if content.count('\n#') >= 2 or content.count('\n##') >= 2:
        structure_score += 3  # has headings
    if content.count('\n- ') >= 3 or content.count('\n* ') >= 3 or re.search(r'\n\d+\.\s', content):
        structure_score += 3  # has lists
    paragraphs = [p.strip() for p in content.split('\n\n') if len(p.strip()) > 50]
    if len(paragraphs) >= 3:
        structure_score += 2  # has multiple substantial paragraphs
    if word_count >= 300:
        structure_score += 2  # decent length
    s += min(structure_score, 10)

    # ── Quick spam sniff — penalize hard ──
    promo_hits = sum(1 for kw in ['buy now', 'limited time', 'discount code',
                                   'coupon', 'promo code', 'special offer',
                                   'free trial', 'click here', 'save big',
                                   'affiliate', 'lowest price', 'order today',
                                   'act now', 'dont miss', 'hurry'] if kw in content_lower)
    if promo_hits >= 2:
        s -= 30
    elif promo_hits >= 1:
        s -= 10

    # ── Affiliate link density ──
    affiliate_pats = ['amazon.com/', 'amzn.to', 'shareasale', 'bit.ly/', 'tinyurl.com', 'cutt.ly']
    aff_count = sum(1 for p in affiliate_pats if p in content_lower)
    if aff_count >= 2:
        s -= 20
    elif aff_count >= 1:
        s -= 5

    # ── Presentation bonuses ──
    desc = blog.get('description', '') or ''
    if len(desc) > 80:
        s += 5
    elif len(desc) > 30:
        s += 2
    if blog.get('thumbnail'):
        s += 8
    if len(content) > 800:
        s += 5
    elif len(content) > 300:
        s += 2

    if quality >= 40:
        s += 5
    elif quality >= 25:
        s += 2

    return round(max(s, 0), 2)


def _get_blog_news_items(max_items=3):
    """Get top-scoring blogs formatted as news items for newsstand injection."""
    if not data_manager:
        return []
    try:
        blogs = [data_manager._normalize_collection(c) for c in data_manager.data.get('collections', [])
                 if c.get('post_type') == 'blog'
                 and c.get('is_public', True)
                 and c.get('quality_score', 0) >= data_manager.QUALITY_THRESHOLD
                 and c.get('flags', 0) < 3]
        if not blogs:
            return []
        for b in blogs:
            b['_ns_score'] = _score_blog_for_newsstand(b)
        blogs.sort(key=lambda x: x['_ns_score'], reverse=True)
        items = []
        for b in blogs[:max_items]:
            title = b.get('name', 'Blog Post')
            desc = b.get('description', '') or (b.get('content', '') or '')[:150]
            item = {
                'title': title,
                'link': f"/explore/{b['id']}",
                'image': b.get('thumbnail', ''),
                'source': 'arlong Blog',
                'description': desc[:200],
                '_is_blog': True,
                '_blog_id': b['id'],
            }
            items.append(item)
        return items
    except Exception:
        return []


BLOG_NEWSTAND_POSITIONS = [1, 3, 5]

# ── Search Quota (unlimited) ──
UNLIMITED = 999999

# ── CSRF Protection ──
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf():
    token = request.form.get('_csrf_token', '')
    expected = session.get('_csrf_token', '')
    if not token or not secrets.compare_digest(expected, token):
        return False
    return True

app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['enc_key'] = _ENCRYPTION_KEY_HEX

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'interest-cohort=()'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
    response.headers['Access-Control-Max-Age'] = '86400'
    return response

# Initialize S3 for persistent storage (Railway Storage Buckets)
s3_client = None
S3_BUCKET = None
S3_DATA_KEY = 'data.json'
S3_ENABLED = False

if s3_available:
    bucket_name = os.environ.get('BUCKET')
    access_key = os.environ.get('ACCESS_KEY_ID')
    secret_key = os.environ.get('SECRET_ACCESS_KEY')
    endpoint = os.environ.get('ENDPOINT')
    if bucket_name and access_key and secret_key and endpoint:
        try:
            s3_client = boto3.client(
                's3',
                endpoint_url=endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=os.environ.get('REGION', 'auto')
            )
            S3_BUCKET = bucket_name
            S3_ENABLED = True
            app.logger.info("S3 storage bucket configured")
        except Exception as e:
            app.logger.warning(f"S3 init failed, falling back to local file: {e}")

# Persist/load secret key via S3 for session continuity across deploys
if S3_ENABLED and s3_client:
    try:
        resp = s3_client.get_object(Bucket=S3_BUCKET, Key='.secret_key')
        s3_key = resp['Body'].read().decode('utf-8').strip()
        if s3_key:
            app.secret_key = s3_key
            app.logger.info("Loaded persistent secret key from S3")
    except ClientError:
        try:
            s3_client.put_object(Bucket=S3_BUCKET, Key='.secret_key', Body=app.secret_key.encode('utf-8'), ContentType='text/plain')
            app.logger.info("Persisted new secret key to S3")
        except Exception as e:
            app.logger.error(f"Failed to persist secret key to S3: {e}")
    except Exception as e:
        app.logger.error(f"Failed to load secret key from S3: {e}")

# Enhanced logging configuration
handler = RotatingFileHandler(
    'search_engine.log',
    maxBytes=10000000,  # 10MB
    backupCount=5
)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)



# Initialize Redis for caching
redis_client = None
if redis_available:
    try:
        redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        redis_client.ping()
    except:
        redis_client = None
        app.logger.warning("Redis not available, falling back to in-memory cache")

DISCUSSION_DOMAINS = {
    'reddit.com', 'redd.it', 'old.reddit.com', 'new.reddit.com',
    'quora.com', 'stackexchange.com', 'stackoverflow.com',
    'serverfault.com', 'superuser.com', 'askubuntu.com',
    'mathoverflow.net', 'forum.xda-developers.com',
    'discourse.org', 'discourse.', 'forum.', 'forums.',
    'answers.yahoo.com', 'answers.com', 'ask.com',
    'hubpages.com', 'medium.com', 'dev.to', 'hashnode.com',
    'producthunt.com', 'news.ycombinator.com', 'lobste.rs',
    'twitter.com', 'x.com', 'facebook.com', 'facebook.com/groups',
    'linkedin.com', 'reddit.com/r/',
}


class SearchResult:
    def __init__(self, title, url, snippet, category='general', date=None, favicon=None, domain=None, source=None):
        self.title = title
        self.url = url
        self.snippet = snippet
        self.category = category
        self.date = date
        self.favicon = favicon or f"https://www.google.com/s2/favicons?domain={url}"
        self.score = 0
        self.domain = domain or urlparse(url).netloc if url else ''
        self.source = source

    def to_dict(self):
        return {
            'title': self.title,
            'url': self.url,
            'display_url': self.url[:60] + '...' if len(self.url) > 60 else self.url,
            'snippet': self.snippet,
            'category': self.category,
            'date': self.date,
            'favicon': self.favicon,
            'score': self.score,
            'type': 'regular',
            'domain': self.domain,
            'source': self.source
        }


BLOCKED_DOMAINS = {
    'zooporn.show', 'porn', 'xxx', 'xvideos', 'xnxx', 'redtube', 'youporn',
    'pornhub', 'tube8', 'xhamster', 'adult', 'sex', 'escort', 'dating',
    'whistleblowersoftware.com', 'healthplix.com', 'mashalearning.com',
    'elearningindustry.com',
}


QUERY_INTENTS = {
    'discussion': {
        'keywords': ['reddit', 'vs', 'versus', 'or', 'best', 'review', 'recommend', 'recommendation',
                     'should', 'help', 'advice', 'opinion', 'thoughts', 'experience', 'tips', 'trick',
                     'guide', 'how to', 'tutorial', 'fix', 'problem', 'issue', 'solution', 'alternative',
                     'compare', 'comparison', 'pros', 'cons', 'worth', 'anyone', 'idea', 'suggestion',
                     'difference', 'better', 'worst', 'top', 'rating', 'rank', 'feedback'],
    },
    'navigational': {
        'keywords': ['login', 'sign in', 'signin', 'sign up', 'signup', 'download', 'official',
                     'website', 'homepage', 'home page', 'site', 'portal', 'dashboard'],
    },
    'transactional': {
        'keywords': ['buy', 'purchase', 'price', 'cost', 'deal', 'discount', 'coupon', 'offer',
                     'cheap', 'affordable', 'order', 'shop', 'store', 'delivery', 'shipping',
                     'free', 'trial', 'subscription', 'rent', 'hire'],
    },
    'local': {
        'keywords': ['near me', 'nearby', 'near', 'in ', 'at ', 'open now', 'hours',
                     'direction', 'map', 'place', 'restaurant', 'cafe', 'hotel', 'hospital',
                     'pharmacy', 'gas station', 'bank', 'store near'],
    },
    'academic': {
        'keywords': ['paper', 'peer reviewed', 'peer-reviewed', 'study', 'doi', 'arxiv',
                     'publication', 'research', 'journal', 'scholar', 'scholarly',
                     'citation', 'cited', 'literature review', 'systematic review',
                     'meta-analysis', 'conference paper', 'proceedings', 'preprint',
                     'thesis', 'dissertation', 'academic', 'science direct',
                     'springer', 'ieee', 'acm', 'nature', 'science magazine',
                     'pubmed', 'pmc', 'medline', 'google scholar',
                     'original research', 'primary literature', 'scientific paper'],
    },
}


DOMAIN_AUTHORITY = {
    'wikipedia.org': 95, 'stackoverflow.com': 90, 'github.com': 88, 'reddit.com': 75,
    'youtube.com': 85, 'medium.com': 70, 'dev.to': 72, 'aws.amazon.com': 85,
    'docs.python.org': 92, 'developer.mozilla.org': 92, 'npmjs.com': 80, 'pypi.org': 82,
    'docker.com': 80, 'kubernetes.io': 82, 'mysql.com': 78, 'postgresql.org': 80,
    'nginx.com': 75, 'apache.org': 78, 'microsoft.com': 82, 'apple.com': 85,
    'google.com': 88, 'meta.com': 75, 'arxiv.org': 85, 'scholar.google.com': 90,
    'ieee.org': 85, 'acm.org': 85, 'springer.com': 80, 'nature.com': 85,
    'sciencedirect.com': 82, 'news.ycombinator.com': 80, 'quora.com': 65,
    'forbes.com': 75, 'nytimes.com': 80, 'reuters.com': 82, 'bbc.com': 82,
    'cnn.com': 78, 'wsj.com': 82, 'bloomberg.com': 80, 'economist.com': 82,
    'wired.com': 75, 'techcrunch.com': 72, 'arstechnica.com': 78,
    'stackexchange.com': 75, 'superuser.com': 70, 'askubuntu.com': 72,
    'serverfault.com': 72, 'coursera.org': 78, 'udemy.com': 70, 'edx.org': 78,
    'khanacademy.org': 80, 'tutorialspoint.com': 60, 'geeksforgeeks.org': 65,
    'w3schools.com': 65,     'realpython.com': 88, 'digitalocean.com': 72,
    'atlassian.com': 72, 'jetbrains.com': 72,     'oracle.com': 70, 'ibm.com': 72,
    'adobe.com': 72, 'salesforce.com': 70, 'wordpress.org': 68, 'getbootstrap.com': 70,
    'python.org': 95, 'pypi.org': 90, 'opensource.org': 80, 'gnu.org': 82,
    'eff.org': 75, 'jetbrains.com': 78, 'git-scm.com': 80, 'nginx.org': 78,
    'sqlite.org': 80, 'readthedocs.io': 75, 'freecodecamp.org': 78,
    'codecademy.com': 70, 'datacamp.com': 70, 'educative.io': 65,
    'ray.so': 50, 'carbon.now.sh': 50, 'roadmap.sh': 65,
    'redditmedia.com': 40, 'redditstatic.com': 40,
    'netflix.com': 92, 'imdb.com': 90, 'rottentomatoes.com': 85,
    'hulu.com': 85, 'disneyplus.com': 88, 'hotstar.com': 85,
    'amazon.com': 88, 'primevideo.com': 85, 'sonyliv.com': 80,
    'zee5.com': 78, 'voot.com': 78, 'jiocinema.com': 80,
    'mxplayer.in': 75, 'crunchyroll.com': 82, 'hbo.com': 88,
    'paramountplus.com': 82, 'peacocktv.com': 80, 'appletv.com': 85,
    'discoveryplus.com': 78, 'espn.com': 85, 'spotify.com': 85,
    'tvtropes.org': 75, 'metacritic.com': 80, 'letterboxd.com': 72,
    'themoviedb.org': 78, 'filmAffinity.com': 70,
    'instagram.com': 72, 'facebook.com': 70, 'x.com': 70, 'twitter.com': 70,
    'linkedin.com': 75, 'pinterest.com': 65, 'tiktok.com': 60,
    'usa.gov': 92, 'whitehouse.gov': 92, 'state.gov': 90, 'defense.gov': 90,
    'nih.gov': 95, 'cdc.gov': 93, 'fda.gov': 92, 'nasa.gov': 94,
    'nsa.gov': 85, 'fbi.gov': 88, 'irs.gov': 85, 'ssa.gov': 85,
    'justice.gov': 88, 'commerce.gov': 85, 'energy.gov': 85, 'interior.gov': 80,
    'education.gov': 85, 'treasury.gov': 85, 'transportation.gov': 80,
    'dhs.gov': 88, 'va.gov': 85, 'usda.gov': 80, 'epa.gov': 85,
    'fema.gov': 88, 'ready.gov': 85, 'noaa.gov': 85, 'usgs.gov': 85,
    'uk.gov': 92, 'gov.uk': 92, 'parliament.uk': 90, 'nhs.uk': 92,
    'canada.ca': 90, 'gc.ca': 90, 'ontario.ca': 82,
    'india.gov.in': 90, 'nic.in': 85, 'mygov.in': 85, 'pmindia.gov.in': 88,
    'gov.in': 85, 'aus.gov.au': 90, 'gov.au': 90, 'health.gov.au': 85,
    'govt.nz': 85, 'europa.eu': 90, 'ec.europa.eu': 88,
    'un.org': 90, 'who.int': 92, 'unesco.org': 85, 'oecd.org': 85,
    'worldbank.org': 85, 'imf.org': 85, 'nato.int': 85, 'redcross.org': 85,
    'bbc.co.uk': 82, 'guardian.co.uk': 80, 'theguardian.com': 80,
    'washingtonpost.com': 82, 'latimes.com': 78, 'wsj.com': 82,
    'ft.com': 80, 'economist.com': 82, 'time.com': 75, 'newyorker.com': 80,
    'nationalgeographic.com': 80, 'scientificamerican.com': 82,
    'theverge.com': 72, 'polygon.com': 70, 'ign.com': 72, 'gamespot.com': 70,
    'eurogamer.net': 70, 'kotaku.com': 68, 'rockpapershotgun.com': 70,
    'pcgamer.com': 70, 'variety.com': 75, 'hollywoodreporter.com': 75,
    'deadline.com': 72, 'thewrap.com': 70, 'empireonline.com': 72,
    'collider.com': 68, 'screenrant.com': 60, 'cbr.com': 60,
    'animenewsnetwork.com': 78, 'myanimelist.net': 75,
}

DISCUSSION_DOMAINS = {'reddit.com', 'quora.com', 'stackexchange.com', 'news.ycombinator.com',
                      'stackoverflow.com', 'medium.com', 'dev.to', 'hu.elnino'}

PLATFORM_DOMAINS = {
    'netflix': 'netflix.com',
    'prime video': 'amazon.com',
    'primevideo': 'primevideo.com',
    'amazon prime': 'amazon.com',
    'hotstar': 'hotstar.com',
    'disney+': 'hotstar.com',
    'disneyplus': 'disneyplus.com',
    'hulu': 'hulu.com',
    'sonyliv': 'sonyliv.com',
    'zee5': 'zee5.com',
    'voot': 'voot.com',
    'jiocinema': 'jiocinema.com',
    'mxplayer': 'mxplayer.in',
    'crunchyroll': 'crunchyroll.com',
    'hbo': 'hbo.com',
    'hbo max': 'hbomax.com',
    'paramount+': 'paramountplus.com',
    'peacock': 'peacocktv.com',
    'appletv': 'appletv.com',
    'youtube': 'youtube.com',
    'spotify': 'spotify.com',
    'imdb': 'imdb.com',
    'rottentomatoes': 'rottentomatoes.com',
}

ACADEMIC_PRIMARY_DOMAINS = {
    'nature.com', 'science.org', 'sciencedirect.com', 'sciencedirect.',
    'springer.com', 'springerlink.com', 'acs.org', 'pubs.acs.org',
    'wiley.com', 'onlinelibrary.wiley.com', 'tandfonline.com',
    'oxfordjournals.org', 'academic.oup.com', 'cambridge.org',
    'sagepub.com', 'annualreviews.org', 'cell.com', 'thelancet.com',
    'nejm.org', 'bmj.com', 'plos.org', 'journals.plos.org',
    'pubmed.ncbi.nlm.nih.gov', 'ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov',
    'arxiv.org', 'ieee.org', 'ieeexplore.ieee.org', 'acm.org',
    'dl.acm.org', 'researchgate.net', 'semanticscholar.org',
    'scholar.google.com', 'core.ac.uk',     'citeseerx.ist.psu.edu',
    'pubmedcentral.org', 'medrxiv.org', 'biorxiv.org', 'ssrn.com',
    'frontiersin.org', 'mdpi.com', 'hindawi.com', 'peerj.com',
    'jstor.org', 'sciencemag.org',
    'pnas.org', 'royalsocietypublishing.org',
    'iop.org', 'iopscience.iop.org', 'aps.org', 'journals.aps.org',
    'aip.org', 'scitation.aip.org', 'spiedigitallibrary.org',
    'liebertpub.com', 'karger.com', 'karger.ch',
    'degruyter.com', 'brill.com', 'emerald.com', 'inderscience.com',
}

ACADEMIC_NEWS_BLOG_PENALTY_DOMAINS = {
    'medium.com', 'blogger.com', 'blogspot.com', 'wordpress.com',
    'substack.com', 'wixsite.com', 'weebly.com', 'hubpages.com',
    'ezinearticles.com', 'articlesfactory.com',
    'theverge.com', 'techcrunch.com', 'wired.com', 'arstechnica.com',
    'cnet.com', 'engadget.com', 'gizmodo.com', 'mashable.com',
    'zdnet.com', 'venturebeat.com', 'forbes.com', 'bloomberg.com',
    'reuters.com', 'bbc.com', 'cnn.com', 'nytimes.com',
    'washingtonpost.com', 'theguardian.com', 'theconversation.com',
    'businessinsider.com', 'theatlantic.com', 'newscientist.com',
    'sciencealert.com', 'livescience.com', 'iflscience.com',
    'popularmechanics.com', 'popsci.com', 'sciencenews.org',
    'cosmosmagazine.com', 'eurekalert.org', 'phys.org',
    'science20.com', 'scitechdaily.com',
}

BANG_REDIRECTS = {
    'g': 'https://www.google.com/search?q={}',
    'ch': 'https://chatgpt.com/?q={}',
    'ge': 'https://gemini.google.com/search?q={}',
    'wiki': 'https://en.wikipedia.org/wiki/{}',
    'w': 'https://en.wikipedia.org/w/index.php?search={}',
    're': 'https://www.reddit.com/search/?q={}',
    'red': 'https://www.reddit.com/r/{}',
    'you': 'https://www.youtube.com/results?search_query={}',
    'yt': 'https://www.youtube.com/results?search_query={}',
    'b': 'https://www.youtube.com/results?search_query={}',
    'gi': 'https://www.google.com/search?tbm=isch&q={}',
    'map': 'https://www.google.com/maps/search/{}',
    'maps': 'https://www.google.com/maps/search/{}',
    'news': 'https://news.google.com/search?q={}',
    'a': 'https://www.amazon.com/s?k={}',
    'so': 'https://stackoverflow.com/search?q={}',
    'gh': 'https://github.com/search?q={}&type=repositories',
    'npm': 'https://www.npmjs.com/search?q={}',
    'pypi': 'https://pypi.org/search/?q={}',
    'ddg': 'https://duckduckgo.com/?q={}',
    'bing': 'https://www.bing.com/search?q={}',
    'yhoo': 'https://search.yahoo.com/search?p={}',
    'imdb': 'https://www.imdb.com/find?q={}',
    'rt': 'https://www.rottentomatoes.com/search?search={}',
    'twit': 'https://twitter.com/search?q={}',
    'fb': 'https://www.facebook.com/search/top?q={}',
    'ig': 'https://www.instagram.com/explore/tags/{}/',
    'li': 'https://www.linkedin.com/search/results/all/?keywords={}',
    'pin': 'https://www.pinterest.com/search/pins/?q={}',
    'qu': 'https://www.quora.com/search?q={}',
    'md': 'https://medium.com/search?q={}',
    'dev': 'https://dev.to/search?q={}',
    'hn': 'https://news.ycombinator.com/submitted?id={}',
    'ph': 'https://www.producthunt.com/search?q={}',
    'tf': 'https://www.tensorflow.org/search?q={}',
    'py': 'https://docs.python.org/3/search.html?q={}',
    'mdn': 'https://developer.mozilla.org/en-US/search?q={}',
    'js': 'https://developer.mozilla.org/en-US/search?q={}',
    'react': 'https://react.dev/search?q={}',
    'vue': 'https://vuejs.org/search?q={}',
    'ang': 'https://angular.io/search?q={}',
    'tw': 'https://tailwindcss.com/search?q={}',
    'verge': 'https://www.theverge.com/search?q={}',
    'wi': 'https://www.wired.com/search?q={}',
    'tc': 'https://techcrunch.com/search/{}',
    'ars': 'https://arstechnica.com/search?q={}',
    'sch': 'https://scholar.google.com/scholar?q={}',
    'arx': 'https://arxiv.org/search/?query={}&searchtype=all',
    'pm': 'https://pubmed.ncbi.nlm.nih.gov/?term={}',
    'doi': 'https://doi.org/{}',
    'dr': 'https://drive.google.com/drive/search?q={}',
    'keep': 'https://keep.google.com/u/0/#search/text={}',
    'fl': 'https://www.flightaware.com/live/findflight?q={}',
    'wb': 'https://www.wolframalpha.com/input/?i={}',
    'urb': 'https://www.urbandictionary.com/define.php?term={}',
    'et': 'https://www.etymonline.com/search?q={}',
    'dict': 'https://www.merriam-webster.com/dictionary/{}',
    'th': 'https://www.thesaurus.com/browse/{}',
    'gl': 'https://www.google.com/search?tbm=shop&q={}',
    'eb': 'https://www.ebay.com/sch/i.html?_nkw={}',
    'wa': 'https://www.walmart.com/search?q={}',
    'bb': 'https://www.bestbuy.com/site/searchpage.jsp?st={}',
    'ct': 'https://www.coursera.org/search?query={}',
    'ud': 'https://www.udemy.com/courses/search/?q={}',
    'edx': 'https://www.edx.org/search?q={}',
    'khan': 'https://www.khanacademy.org/search?page_search_query={}',
    'se': 'https://stackexchange.com/search?q={}',
    'su': 'https://superuser.com/search?q={}',
    'au': 'https://askubuntu.com/search?q={}',
    'sp': 'https://open.spotify.com/search/{}',
    'nf': 'https://www.netflix.com/search?q={}',
    'tr': 'https://www.tripadvisor.com/Search?q={}',
    'tik': 'https://www.tiktok.com/search?q={}',
    'hulu': 'https://www.hulu.com/search?q={}',
}

BANG_PATTERN = re.compile(r'^\s*!(\w{1,20})(?:\s+(.+))?\s*$', re.IGNORECASE)


def parse_bang(query):
    if not query:
        return None, query
    stripped = query.strip()
    if not stripped.startswith('!'):
        return None, query
    m = BANG_PATTERN.match(stripped)
    if not m:
        return None, query
    bang_key = m.group(1).lower()
    search_term = (m.group(2) or '').strip()
    if bang_key in BANG_REDIRECTS:
        return bang_key, search_term
    return None, query


def get_bang_redirect(query):
    bang_key, search_term = parse_bang(query)
    if not bang_key:
        return None
    template = BANG_REDIRECTS[bang_key]
    return template.format(quote_plus(search_term) if search_term else '')


AD_DOMAINS = {
    'oneclearwinner.com', 'taboola.com', 'outbrain.com', 'revcontent.com',
    'mgid.com', 'exoclick.com', 'popads.net', 'propellerads.com',
    'adsterra.com', 'adcash.com', 'adf.ly', 'adfly.com',
    'bit.ly', 'tinyurl.com', 'shorte.st', 'bc.vc',
    'sponsored', 'adservice', 'doubleclick.net', 'googlesyndication.com',
    'googleadservices.com', 'googleads.g.doubleclick.net',
    'amazon-adsystem.com', 'amazon.com/gp/product', 'ebay.com/sch',
    'alibaba.com', 'aliexpress.com', 'wish.com',
    'temu.com', 'shein.com', 'tradedoubler.com',
}
AD_KEYWORDS = ['ad', 'sponsored', 'promoted', 'advertisement', 'paid',
               'partner', 'disclosure', 'affiliate', 'sponsor']

# Load Blocklist Project blocklists (gambling, ads, crypto, drugs, fraud)
BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocklist_domains.json')
BLOCKLIST_DOMAINS = set()
BLOCKLIST_COUNT = 0
if os.path.exists(BLOCKLIST_FILE):
    try:
        with open(BLOCKLIST_FILE) as f:
            bl_data = json.load(f)
        BLOCKLIST_DOMAINS = set(bl_data.get('blocklist_domains', []))
        BLOCKLIST_COUNT = len(BLOCKLIST_DOMAINS)
        app.logger.info(f"Loaded {BLOCKLIST_COUNT} blocklisted domains")
    except Exception as e:
        app.logger.error(f"Failed to load blocklist: {e}")

# Load Tranco top-1M domain authority
TRANCO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tranco_authority.json')
TRANCO_AUTHORITY = {}
if os.path.exists(TRANCO_FILE):
    try:
        with open(TRANCO_FILE) as f:
            TRANCO_AUTHORITY = json.load(f)
        app.logger.info(f"Loaded {len(TRANCO_AUTHORITY)} Tranco-ranked domains")
    except Exception as e:
        app.logger.error(f"Failed to load Tranco authority: {e}")


class SearchBlocker:
    @staticmethod
    def is_ad(url, title, snippet):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        if any(ad_domain in domain for ad_domain in AD_DOMAINS):
            return True
        combined = (title + ' ' + snippet).lower()
        ad_score = 0
        for kw in AD_KEYWORDS:
            if kw in combined:
                ad_score += 1
        if ad_score >= 3:
            return True
        if any(ad_domain in url.lower() for ad_domain in AD_DOMAINS):
            return True
        return False

    @staticmethod
    def is_blocklisted(url):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        if domain in BLOCKLIST_DOMAINS:
            return True
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in BLOCKLIST_DOMAINS:
                return True
        return False


class SearchIntent:
    def __init__(self, query):
        self.query = query
        self.lower = query.lower().strip()
        self.terms = self.lower.split()
        self.detected_intents = self._detect()

    def _detect(self):
        intents = set()
        for intent_name, intent_data in QUERY_INTENTS.items():
            for kw in intent_data['keywords']:
                if kw in self.lower:
                    intents.add(intent_name)
                    break
        if not intents:
            intents.add('informational')
        return intents

    def wants_discussion(self):
        return 'discussion' in self.detected_intents

    def is_navigational(self):
        return 'navigational' in self.detected_intents

    def is_transactional(self):
        return 'transactional' in self.detected_intents

    def wants_academic(self):
        return 'academic' in self.detected_intents

CRISIS_PREFIXES = [
    "i am in crisis", "i need help", "i want to die", "i want to kms",
    "suicide", "suicidal", "self harm", "selfharm", "end my life",
    "i can't do this anymore", "i give up", "no one cares", "help me",
    "abuse at home", "scared at home", "unsafe at home", "being abused",
    "hurting myself", "hurt myself", "want to hurt",
]

HARMFUL_CONTENT_PREFIXES = [
    "how to self harm", "self harm methods", "suicide methods",
    "how to kill myself", "how to commit suicide",
]

DISASTER_KEYWORDS = {
    "tornado": {
        "title": "Tornado Safety",
        "steps": [
            "Go to the basement or lowest floor, away from windows.",
            "Cover your head and neck with your arms or a blanket.",
            "Do NOT stay in a mobile home or vehicle.",
            "Listen to local weather alerts or check NOAA Weather Radio.",
            "After the tornado, watch for downed power lines and sharp debris."
        ]
    },
    "earthquake": {
        "title": "Earthquake Safety",
        "steps": [
            "Drop, Cover, and Hold On — get under a sturdy table or desk.",
            "Stay indoors and away from windows, heavy furniture, and exterior walls.",
            "If outside, stay in the open away from buildings, trees, and power lines.",
            "If driving, pull over to a clear area and stay in the vehicle.",
            "After shaking stops, check for injuries and hazards (gas leaks, fires)."
        ]
    },
    "flood": {
        "title": "Flood Safety",
        "steps": [
            "Move to higher ground immediately — do NOT walk or drive through floodwater.",
            "Just 6 inches of moving water can knock you down; 12 inches can sweep a car away.",
            "Avoid power lines and electrical wires — water conducts electricity.",
            "Heed evacuation orders from local authorities promptly.",
            "After the flood, avoid contact with floodwater (it may be contaminated)."
        ]
    },
    "hurricane": {
        "title": "Hurricane Safety",
        "steps": [
            "Stay indoors in an interior room away from windows and glass doors.",
            "If evacuation is ordered, leave immediately with your emergency kit.",
            "Charge phones and devices before the storm hits.",
            "Fill bathtubs and containers with clean water in case of supply disruption.",
            "After the storm, avoid floodwater, downed power lines, and damaged buildings."
        ]
    },
    "wildfire": {
        "title": "Wildfire Safety",
        "steps": [
            "Evacuate immediately if authorities advise it — take your emergency kit.",
            "Close all windows and doors before leaving.",
            "Wear protective clothing: long sleeves, pants, cotton or wool fabrics.",
            "If trapped, call emergency services and find a body of water or cleared area.",
            "After the fire, check for hot spots, smoldering stumps, and embers."
        ]
    },
    "tsunami": {
        "title": "Tsunami Safety",
        "steps": [
            "If you feel a strong earthquake near the coast, move inland immediately.",
            "If you see the ocean receding rapidly, run to high ground — a tsunami is coming.",
            "Do NOT wait for an official warning — natural signs are your first alert.",
            "Go at least 100 feet above sea level or 2 miles inland.",
            "Stay on high ground until authorities say it is safe to return."
        ]
    }
}

CRISIS_RESOURCES = {
    "global": {
        "hotline": "International Association for Suicide Prevention — https://www.iasp.info/resources/Crisis_Centres/",
        "text": "Crisis Text Line — Text HOME to 741741 (US) or visit crisistextline.org",
        "note": "You are not alone. Help is available, and you matter."
    },
    "us": {
        "hotline": "988 Suicide & Crisis Lifeline — Call or text 988",
        "text": "Crisis Text Line — Text HOME to 741741",
        "child": "Childhelp National Child Abuse Hotline — Call 1-800-422-4453",
        "note": "Trained counselors are available 24/7. Free and confidential."
    },
    "uk": {
        "hotline": "Samaritans — Call 116 123 (free, 24/7)",
        "text": "SHOUT — Text SHOUT to 85258",
        "child": "Childline — Call 0800 1111",
        "note": "Whatever you're going through, you don't have to face it alone."
    },
    "india": {
        "hotline": "iCall — Call 022 2552 1111 (Mon-Sat, 8am-10pm)",
        "text": "Snehi — Call 044 2464 0050",
        "child": "Childline India — Call 1098 (24/7)",
        "note": "Free, confidential support. You deserve to be heard."
    },
    "canada": {
        "hotline": "Talk Suicide Canada — Call 1-833-456-4566",
        "text": "Crisis Text Line — Text HOME to 686868",
        "child": "Kids Help Phone — Call 1-800-668-6868",
        "note": "Reach out. There are people who care and want to help."
    },
    "australia": {
        "hotline": "Lifeline Australia — Call 13 11 14 (24/7)",
        "text": "Kids Helpline — Call 1800 55 1800",
        "child": "1800RESPECT — Call 1800 737 732 (domestic violence)",
        "note": "You don't have to go through this alone. Help is a call away."
    }
}

LIFE_RESOURCES = [
    {"title": "Building a Life You Don't Need to Escape From", "url": "https://www.psychologytoday.com/us/basics/happiness", "snippet": "Research-backed guidance on cultivating meaning, connection, and daily practices that support emotional well-being.", "category": "wellness"},
    {"title": "The Science of Happiness", "url": "https://greatergood.berkeley.edu/", "snippet": "Explore evidence-based strategies for living a more fulfilling life, from gratitude practices to strengthening relationships.", "category": "wellness"},
    {"title": "You Are Not Your Thoughts", "url": "https://www.mindful.org/", "snippet": "Mindfulness and meditation resources to help you find peace, gain perspective, and build resilience through difficult times.", "category": "wellness"},
    {"title": "Finding Purpose After Loss", "url": "https://www.whatsyourgrief.com/", "snippet": "A compassionate guide to navigating grief, rediscovering meaning, and rebuilding a life that feels worth living.", "category": "support"},
    {"title": "Self-Compassion: A Better Way to Be Kind to Yourself", "url": "https://self-compassion.org/", "snippet": "Research and exercises from Dr. Kristin Neff on treating yourself with the same kindness you would offer a friend.", "category": "guide"},
    {"title": "How to Get Through the Worst Days", "url": "https://www.npr.org/sections/health-shots/2020/03/20/814758032/managing-your-mental-health-during-the-coronavirus-outbreak", "snippet": "Practical strategies for surviving difficult moments, one hour at a time, with professional guidance and peer support.", "category": "guide"},
    {"title": "988 Suicide & Crisis Lifeline", "url": "https://988lifeline.org/", "snippet": "Call or text 988. Free, confidential, 24/7. Trained crisis counselors are ready to listen and help you find hope.", "category": "support"},
    {"title": "Crisis Text Line", "url": "https://www.crisistextline.org/", "snippet": "Text HOME to 741741 to connect with a trained crisis counselor. Free, 24/7, confidential.", "category": "support"},
]

def detect_crisis(query):
    q = query.lower().strip()
    if not q:
        return None
    for prefix in HARMFUL_CONTENT_PREFIXES:
        if q.startswith(prefix) or q == prefix:
            return {"type": "harmful", "severity": "high"}
    for prefix in CRISIS_PREFIXES:
        if prefix in q:
            return {"type": "crisis", "severity": "high"}
    words = set(q.split())
    for disaster, info in DISASTER_KEYWORDS.items():
        if disaster in words or disaster in q:
            return {"type": "disaster", "disaster": disaster, "info": info}
    return None

BODY_NEGATIVE_PATTERNS = [
    "ugly women", "ugly girl", "ugly woman", "ugly girls",
    "fat women", "fat girl", "ugly people",
    "women are ugly", "girls are ugly",
    "why are women so ugly", "why are girls so ugly",
    "hate women", "hate girls",
    "women are useless", "girls are useless",
]

NSFW_CONTENT_PATTERNS = [
    "nsfw", "porn", "pornography", "xxx", "adult content",
    "sex videos", "sex images", "naked", "nude",
    "explicit content", "adult video", "adult images",
    "onlyfans", "strip", "stripclub",
    "hentai", "rule34",
]

MEDICAL_HELP_PATTERNS = [
    "chest pain", "heart attack symptoms", "stroke symptoms",
    "i think i'm dying", "medical emergency",
    "poison", "overdose", "bleeding heavily",
    "difficulty breathing", "can't breathe",
    "severe allergic reaction", "anaphylaxis",
    "head injury", "concussion symptoms",
]

BODY_POSITIVE_RESOURCES = [
    {"title": "You Are Enough — Body Positivity & Self-Worth", "url": "https://www.nationaleatingdisorders.org/body-image", "snippet": "Everyone deserves to feel comfortable in their own skin. Learn about body image, self-acceptance, and how to build a healthier relationship with yourself.", "category": "support"},
    {"title": "The Body Is Not an Apology", "url": "https://thebodyisnotanapology.com/", "snippet": "Radical self-love and body positivity resources. A global movement dedicated to ending body shame and discrimination.", "category": "community"},
    {"title": "Self-Compassion Guide", "url": "https://self-compassion.org/", "snippet": "Learn how to be kinder to yourself. Research-backed exercises and meditations to build self-compassion.", "category": "wellness"},
    {"title": "Love Your Body — A Guide to Self-Acceptance", "url": "https://www.verywellmind.com/how-to-love-your-body-5097489", "snippet": "Practical steps to challenge negative self-talk, stop comparing yourself to others, and appreciate your body for what it does.", "category": "guide"},
    {"title": "Crisis Text Line — Free 24/7 Support", "url": "https://www.crisistextline.org/", "snippet": "Text HOME to 741741 to connect with a trained crisis counselor. Free, confidential, available 24/7.", "category": "support"},
]

def detect_notice(query):
    q = query.lower().strip()
    if not q:
        return None
    for pattern in BODY_NEGATIVE_PATTERNS:
        if pattern in q:
            return {
                "type": "redirect",
                "title": "No results found",
                "message": "Try searching something else. Here are some resources that might help:",
            }
    for pattern in NSFW_CONTENT_PATTERNS:
        if pattern in q:
            return {
                "type": "warning",
                "icon": "&#x26A0;&#xFE0F;",
                "message": "We don't serve adult content. If you or someone you know needs support, you're not alone. <a href='/crisis' style='color:#1a73e8;'>Find help here</a>.",
            }
    for pattern in MEDICAL_HELP_PATTERNS:
        if pattern in q:
            return {
                "type": "warning",
                "icon": "&#x1F3E5;",
                "message": "If this is a medical emergency, call your local emergency services immediately (911 in the US). These search results are not a substitute for professional medical help.",
            }
    return None

COUNTRY_NAMES = {
    'us': 'United States', 'uk': 'United Kingdom', 'ca': 'Canada',
    'de': 'Germany', 'fr': 'France', 'jp': 'Japan', 'in': 'India',
    'au': 'Australia', 'br': 'Brazil', 'es': 'Spain', 'it': 'Italy',
}

def fetch_trending_news(country_code):
    """Fetch trending news: regional from Google News RSS, global from Reddit hot."""
    import feedparser
    regional = []
    global_top = []

    # 1. Google News RSS for regional
    try:
        rss_url = f'https://news.google.com/rss?gl={country_code}&hl=en&ceid={country_code}:en'
        feed = feedparser.parse(rss_url)
        seen = set()
        for entry in feed.entries:
            title = entry.get('title', '').strip()
            link = entry.get('link', '')
            if not title or len(title) < 10 or link in seen:
                continue
            seen.add(link)
            source = ''
            if hasattr(entry, 'source') and entry.source:
                source = entry.source.get('title', '')
            if not source:
                src_tag = entry.get('published', '').split()[-1] if entry.get('published') else ''
                source = src_tag or 'News'
            regional.append({
                'title': title,
                'url': link,
                'source': source,
                'articles': random.randint(150, 1200),
            })
            if len(regional) >= 6:
                break
    except Exception:
        pass

    # 2. Reddit r/all hot for global
    try:
        reddit_url = 'https://www.reddit.com/r/all/hot.json?limit=10'
        headers = {'User-Agent': 'arlong-search/1.0 (trending)', 'Accept': 'application/json'}
        resp = requests.get(reddit_url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            for post in data.get('data', {}).get('children', []):
                p = post.get('data', {})
                title = p.get('title', '').strip()
                url = p.get('url', '')
                domain = p.get('domain', 'reddit.com')
                ups = p.get('ups', 0)
                if not title or len(title) < 10:
                    continue
                global_top.append({
                    'title': title,
                    'url': url,
                    'source': domain,
                    'articles': max(ups, random.randint(200, 1500)),
                })
                if len(global_top) >= 6:
                    break
    except Exception:
        pass

    # 3. Fallback: if regional empty, use global news via Google News RSS US
    if not regional:
        try:
            fallback_url = 'https://news.google.com/rss?gl=US&hl=en&ceid=US:en'
            feed = feedparser.parse(fallback_url)
            seen = set()
            for entry in feed.entries:
                title = entry.get('title', '').strip()
                link = entry.get('link', '')
                if not title or len(title) < 10 or link in seen:
                    continue
                seen.add(link)
                source = ''
                if hasattr(entry, 'source') and entry.source:
                    source = entry.source.get('title', '')
                regional.append({
                    'title': title,
                    'url': link,
                    'source': source or 'News',
                    'articles': random.randint(150, 1200),
                })
                if len(regional) >= 6:
                    break
        except Exception:
            pass

    # If still empty, try a simple scraping approach
    if not regional:
        try:
            resp = requests.get('https://www.theguardian.com/world/rss', timeout=8)
            feed = feedparser.parse(resp.content)
            for entry in feed.entries:
                title = entry.get('title', '').strip()
                link = entry.get('link', '')
                if title and len(title) >= 10:
                    regional.append({
                        'title': title,
                        'url': link,
                        'source': 'The Guardian',
                        'articles': random.randint(150, 1200),
                    })
                    if len(regional) >= 6:
                        break
        except Exception:
            pass

    return {
        'regional': regional[:3],
        'global': global_top[:3],
        'all_regional': regional,
        'all_global': global_top,
    }

def detect_user_country():
    # Check Cloudflare header first
    cf = request.headers.get('cf-ipcountry', '')
    if cf and cf.upper() in [c.upper() for c in COUNTRY_NAMES]:
        return cf.lower(), cf.lower()
    # Then ip-api.com
    try:
        r = requests.get('https://ip-api.com/json/?fields=countryCode,country',
                          headers={'User-Agent': 'arlong-search/1.0'}, timeout=4)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                cc = data.get('countryCode', '').lower()
                country = data.get('country', '')
                for code, name in COUNTRY_NAMES.items():
                    if cc == code or country.lower() == name.lower():
                        return code, cc
                return None, cc
    except:
        pass
    return None, None

DATA_FILE = os.environ.get('DATA_FILE') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.json')
BACKUP_DIR = os.environ.get('BACKUP_DIR') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')

_json_cache = {'data': None, 'ts': 0}
_JSON_CACHE_TTL = 2

def _load_json():
    now = time.time()
    if _json_cache['data'] is not None and (now - _json_cache['ts']) < _JSON_CACHE_TTL:
        return _json_cache['data']
    result = None
    if S3_ENABLED and s3_client:
        try:
            resp = s3_client.get_object(Bucket=S3_BUCKET, Key=S3_DATA_KEY)
            result = json.loads(resp['Body'].read().decode('utf-8'))
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                pass
            else:
                app.logger.error(f"S3 load error: {e}")
        except Exception as e:
            app.logger.error(f"S3 load error: {e}")
    else:
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, 'r') as f:
                    result = json.load(f)
            except:
                pass
    if result is not None:
        _json_cache['data'] = result
        _json_cache['ts'] = now
    return result

def _invalidate_json_cache():
    _json_cache['data'] = None
    _json_cache['ts'] = 0

def _save_json(data):
    _invalidate_json_cache()
    if S3_ENABLED and s3_client:
        try:
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=S3_DATA_KEY,
                Body=json.dumps(data, indent=2).encode('utf-8'),
                ContentType='application/json'
            )
        except Exception as e:
            app.logger.error(f"S3 save error: {e}")
    else:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)

def _create_backup():
    try:
        data = _load_json()
        if not data:
            app.logger.warning("Backup skipped: no data loaded")
            return
        ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_name = f"data_{ts}.json"
        backup_payload = json.dumps(data, indent=2).encode('utf-8')
        if S3_ENABLED and s3_client:
            try:
                s3_client.put_object(
                    Bucket=S3_BUCKET,
                    Key=f"backups/{backup_name}",
                    Body=backup_payload,
                    ContentType='application/json'
                )
                app.logger.info(f"Backup saved to S3: backups/{backup_name}")
            except Exception as e:
                app.logger.error(f"S3 backup error: {e}")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        local_path = os.path.join(BACKUP_DIR, backup_name)
        with open(local_path, 'wb') as f:
            f.write(backup_payload)
        app.logger.info(f"Backup saved locally: {local_path}")
        _prune_old_backups()
    except Exception as e:
        app.logger.error(f"Backup failed: {e}")

def _prune_old_backups(keep=48):
    try:
        if S3_ENABLED and s3_client:
            try:
                resp = s3_client.list_objects_v2(Bucket=S3_BUCKET, Prefix='backups/')
                objs = resp.get('Contents', [])
                if len(objs) > keep:
                    objs.sort(key=lambda o: o['Key'])
                    to_delete = objs[:len(objs) - keep]
                    for obj in to_delete:
                        s3_client.delete_object(Bucket=S3_BUCKET, Key=obj['Key'])
                    app.logger.info(f"Pruned {len(to_delete)} old S3 backups")
            except Exception as e:
                app.logger.error(f"S3 backup prune error: {e}")
        if os.path.isdir(BACKUP_DIR):
            files = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('data_') and f.endswith('.json')])
            if len(files) > keep:
                for f in files[:len(files) - keep]:
                    os.remove(os.path.join(BACKUP_DIR, f))
                    app.logger.info(f"Pruned old local backup: {f}")
    except Exception as e:
        app.logger.error(f"Backup prune failed: {e}")

class DataManager:
    def __init__(self):
        self._lock = threading.Lock()
        # Auto-migrate from old path when volume is configured
        if os.environ.get('DATA_FILE'):
            old_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.json')
            if not os.path.exists(DATA_FILE) and os.path.exists(old_path):
                import shutil
                shutil.copy2(old_path, DATA_FILE)
                app.logger.info(f"Migrated data.json from {old_path} to {DATA_FILE}")
        loaded = _load_json()
        if loaded:
            self.data = loaded
        else:
            self.data = {"reports": [], "blacklist": {}, "total_searches": 0, "celebration": "", "announcement": ""}
            _save_json(self.data)

    def add_report(self, url, title, query, domain):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            ids = [r['id'] for r in self.data['reports']]
            next_id = max(ids) + 1 if ids else 1
            report = {
                "id": next_id,
                "url": url,
                "domain": domain,
                "title": title,
                "query": query,
                "reported_at": datetime.now().isoformat(),
                "status": "pending"
            }
            self.data['reports'].append(report)
            _save_json(self.data)
            return report

    def get_pending_reports(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return [r for r in self.data['reports'] if r['status'] == 'pending']

    def get_all_reports(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return list(self.data['reports'])

    def approve_report(self, report_id, penalty=-30):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for report in self.data['reports']:
                if report['id'] == report_id and report['status'] == 'pending':
                    report['status'] = 'approved'
                    domain = report['domain']
                    self.data['blacklist'][domain] = penalty
                    _save_json(self.data)
                    return True
            return False

    def deny_report(self, report_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for report in self.data['reports']:
                if report['id'] == report_id and report['status'] == 'pending':
                    report['status'] = 'denied'
                    _save_json(self.data)
                    return True
            return False

    def get_blacklist(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return dict(self.data.get('blacklist', {}))

    def remove_from_blacklist(self, domain):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            if domain in self.data['blacklist']:
                del self.data['blacklist'][domain]
                _save_json(self.data)
                return True
            return False

    def get_stats(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            reports = self.data['reports']
            pending = sum(1 for r in reports if r['status'] == 'pending')
            approved = sum(1 for r in reports if r['status'] == 'approved')
            denied = sum(1 for r in reports if r['status'] == 'denied')
            return {
                'total_reports': len(reports),
                'pending': pending,
                'approved': approved,
                'denied': denied,
                'blacklisted_domains': len(self.data['blacklist']),
                'total_searches': self.data.get('total_searches', 0),
                'verified_sites': len(self.data.get('verified_sites', [])),
                'submitted_sites': len(self.data.get('submitted_sites', [])),
            }

    def get_total_searches(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return self.data.get('total_searches', 0)

    def increment_total_searches(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['total_searches'] = self.data.get('total_searches', 0) + 1
            _save_json(self.data)

    def _increment_searches_deferred(self):
        try:
            with self._lock:
                loaded = _load_json()
                if loaded:
                    self.data = loaded
                self.data['total_searches'] = self.data.get('total_searches', 0) + 1
                _save_json(self.data)
        except Exception:
            pass

    def get_celebration(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return self.data.get('celebration', '')

    def set_celebration(self, text):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['celebration'] = text
            _save_json(self.data)

    def get_announcement(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return self.data.get('announcement', '')

    def set_announcement(self, text):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['announcement'] = text
            _save_json(self.data)

    # ── Search Quota ──

    def get_or_create_daily_count(self, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('daily_searches', {})
            uid = str(user_id)
            user_data = self.data['daily_searches'].get(uid, {})
            today = datetime.utcnow().strftime('%Y-%m-%d')
            if user_data.get('date') != today:
                user_data = {'date': today, 'count': 0}
                self.data['daily_searches'][uid] = user_data
                _save_json(self.data)
            return user_data['date'], user_data['count']

    def increment_daily_count(self, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('daily_searches', {})
            uid = str(user_id)
            today = datetime.utcnow().strftime('%Y-%m-%d')
            user_data = self.data['daily_searches'].get(uid, {})
            if user_data.get('date') != today:
                user_data = {'date': today, 'count': 0}
            user_data['count'] = user_data.get('count', 0) + 1
            self.data['daily_searches'][uid] = user_data
            _save_json(self.data)
            return user_data['count']

    def get_daily_remaining(self, user_id):
        return UNLIMITED

    def get_trending_news(self, country_code):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            trending = self.data.get('trending_news', {})
            cached = trending.get(country_code)
            if cached:
                now = time.time()
                age = now - cached.get('cached_at', 0)
                if age < 10800:  # 3 hour TTL
                    return cached
            return None

    def set_trending_news(self, country_code, data):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('trending_news', {})
            data['cached_at'] = time.time()
            data['country'] = country_code
            self.data['trending_news'][country_code] = data
            _save_json(self.data)

    def get_places_cache(self, key):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            cached = self.data.get('places_cache', {}).get(key)
            if cached:
                now = time.time()
                if now - cached.get('cached_at', 0) < PLACES_CACHE_TTL:
                    return cached
            return None

    def set_places_cache(self, key, places):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('places_cache', {})
            self.data['places_cache'][key] = {
                'cached_at': time.time(),
                'places': places,
            }
            _save_json(self.data)

    def get_geo_cache(self, location):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            cached = self.data.get('geo_cache', {}).get(location)
            if cached:
                now = time.time()
                if now - cached.get('cached_at', 0) < PLACES_GEO_TTL:
                    return cached.get('coords')
            return None

    def set_geo_cache(self, location, coords):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('geo_cache', {})
            self.data['geo_cache'][location] = {
                'cached_at': time.time(),
                'coords': coords,
            }
            _save_json(self.data)

    def flush(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            _save_json(self.data)

    def add_verified_site(self, domain, name, description, email, phone='', region='us', plan='monthly', scope='regional', regions=None):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('verified_sites', [])
            for site in self.data['verified_sites']:
                if site['domain'] == domain:
                    site.update(name=name, description=description, email=email,
                                phone=phone, region=region, plan=plan, scope=scope,
                                regions=regions or [region])
                    _save_json(self.data)
                    return site
            site = {
                'domain': domain, 'name': name, 'description': description,
                'email': email, 'phone': phone, 'region': region, 'plan': plan,
                'scope': scope, 'regions': regions or [region],
                'verified_at': datetime.now().isoformat(),
                'subscription': 'active',
            }
            self.data['verified_sites'].append(site)
            _save_json(self.data)
            return site

    def get_verified_sites(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return list(self.data.get('verified_sites', []))

    def is_verified(self, domain, user_country=None):
        domain = domain.lower().replace('www.', '')
        sites = self.get_verified_sites()
        for s in sites:
            if domain in s['domain'] or s['domain'] in domain:
                if s.get('scope') == 'global':
                    return True
                regions = s.get('regions') or [s.get('region', 'us')]
                if user_country and user_country in regions:
                    return True
        return False

    def get_verified_info(self, domain, user_country=None):
        domain = domain.lower().replace('www.', '')
        sites = self.get_verified_sites()
        for s in sites:
            if domain in s['domain'] or s['domain'] in domain:
                if s.get('scope') == 'global':
                    return s
                regions = s.get('regions') or [s.get('region', 'us')]
                if user_country and user_country in regions:
                    return s
        return None

    def remove_verified_site(self, domain):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['verified_sites'] = [s for s in self.data.get('verified_sites', []) if s['domain'] != domain]
            _save_json(self.data)

    def add_submitted_site(self, domain, sitemap_url, robots_txt_url, email,
                           name='', description='', phone='', category='', submitted_by=None):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('submitted_sites', [])
            for site in self.data['submitted_sites']:
                if site['domain'] == domain:
                    return None  # prevent resubmission
            site = {
                'domain': domain, 'name': name, 'description': description,
                'phone': phone, 'category': category,
                'sitemap_url': sitemap_url, 'robots_txt_url': robots_txt_url,
                'email': email, 'submitted_by': submitted_by,
                'submitted_at': datetime.now().isoformat(),
            }
            self.data['submitted_sites'].append(site)
            _save_json(self.data)
            return site

    def get_submitted_sites(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return list(self.data.get('submitted_sites', []))

    def get_submitted_site(self, domain):
        sites = self.get_submitted_sites()
        for s in sites:
            if s['domain'] == domain:
                return s
        return None

    def approve_submission(self, domain):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for s in self.data.get('submitted_sites', []):
                if s['domain'] == domain:
                    s['verified'] = True
                    _save_json(self.data)
                    return True
            return False

    # ── Community system: users, votes, domain reports ──

    def hash_password(self, password):
        return generate_password_hash(password)

    def check_password(self, password, stored):
        try:
            return check_password_hash(stored, password)
        except:
            return False

    def hash_ip(self, ip):
        return hashlib.sha256(ip.encode()).hexdigest()[:16]

    def _invalidate_user_cache(self):
        if hasattr(self, '_user_cache'):
            del self._user_cache

    def create_user(self, username, password, security_question, security_answer, ip, email='', weather_location=''):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('users', [])
            if any(u['username'].lower() == username.lower() for u in self.data['users']):
                return None, 'Username taken'
            if email:
                email_lower = email.strip().lower()
                if any(u.get('email', '').lower() == email_lower for u in self.data['users'] if u.get('email')):
                    return None, 'Email already in use'
            user = {
                'user_id': str(uuid.uuid4()),
                'username': username,
                'email': email.strip().lower() if email else '',
                'weather_location': weather_location.strip() if weather_location else '',
                'password_hash': self.hash_password(password),
                'security_question': security_question,
                'security_answer_hash': self.hash_password(security_answer),
                'ip_hashes': [self.hash_ip(ip)],
                'created_at': datetime.now().isoformat(),
                'last_action_at': None,
            }
            self.data['users'].append(user)
            _save_json(self.data)
            self._invalidate_user_cache()
            return user, None

    def authenticate_user(self, username, password):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        users = self.data.get('users', [])
        for u in users:
            if u['username'].lower() == username.lower():
                if self.check_password(password, u['password_hash']):
                    return u
        return None

    def get_user_by_id(self, user_id):
        if not user_id:
            return None
        key = str(user_id)
        if hasattr(self, '_user_cache') and key in self._user_cache:
            return self._user_cache.get(key)
        for u in self.data.get('users', []):
            if u['user_id'] == user_id:
                if not hasattr(self, '_user_cache'):
                    self._user_cache = {}
                self._user_cache[key] = u
                return u
        return None

    def get_all_users(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        return self.data.get('users', [])

    def delete_user(self, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            users = self.data.get('users', [])
            self.data['users'] = [u for u in users if u['user_id'] != user_id]
            _save_json(self.data)
            self._invalidate_user_cache()

    def report_domain(self, user_id, domain, reason):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('domain_reports', [])
            for r in self.data['domain_reports']:
                if r['domain'] == domain:
                    if user_id in r['reported_by']:
                        return 'already'
                    r['reported_by'].append(user_id)
                    r['downvotes'] += 1
                    _save_json(self.data)
                    return 'added'
            self.data['domain_reports'].append({
                'domain': domain,
                'reported_by': [user_id],
                'downvotes': 1,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
            })
            _save_json(self.data)
            return 'created'

    def get_pending_domain_reports(self):
        return [r for r in self.data.get('domain_reports', []) if r.get('status') == 'pending']

    def resolve_domain_report(self, domain, action):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for r in self.data.get('domain_reports', []):
                if r['domain'] == domain:
                    r['status'] = action
                    if action == 'approved':
                        self.data.setdefault('blacklist', {})
                        self.data['blacklist'][domain] = -50
                    _save_json(self.data)
                    return

    # ── Collections (community curation) ──

    def create_collection(self, user_id, username, name, description, content='', pin_color='#800000', transparent=False, background_image='', background_style='cover', theme='', thumbnail=''):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('collections', [])
            c = {
                'id': str(uuid.uuid4()),
                'name': name[:100],
                'description': description[:500] if description else '',
                'content': content,
                'pin_color': pin_color,
                'transparent': transparent,
                'background_image': background_image,
                'background_style': background_style if background_style in ('cover','repeat','contain') else 'cover',
                'theme': theme[:200] if theme else '',
                'thumbnail': thumbnail[:500] if thumbnail else '',
                'post_type': 'blog',
                'creator_id': user_id,
                'creator_name': username,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'websites': [],
                'pinned_links': [],
                'is_public': True,
                'is_listed': False,
                'quality_score': 0,
                'view_count': 0,
                'upvote_count': 0,
                'flags': 0,
                'is_approved': False,
            }
            self.data['collections'].append(c)
            self._auto_approve(c)
            _save_json(self.data)
            return c

    def _normalize_collection(self, c):
        c.setdefault('quality_score', 0)
        c.setdefault('view_count', 0)
        c.setdefault('upvote_count', 0)
        c.setdefault('flags', 0)
        c.setdefault('websites', [])
        c.setdefault('pinned_links', [])
        c.setdefault('thumbnail', '')
        c.setdefault('post_type', 'blog')
        c.setdefault('content', '')
        c.setdefault('description', '')
        c.setdefault('transparent', False)
        c.setdefault('background_image', '')
        c.setdefault('background_style', 'cover')
        c.setdefault('theme', '')
        c.setdefault('is_approved', False)
        c.setdefault('is_listed', False)
        c.setdefault('pin_color', '#800000')
        c.setdefault('creator_name', 'Anonymous')
        c.setdefault('created_at', '')
        c.setdefault('updated_at', '')
        c.setdefault('name', 'Untitled')
        return c

    def get_collections(self, sort='new', page=1, per_page=20):
        cols = [self._normalize_collection(c) for c in self.data.get('collections', []) if c.get('is_public', True)]
        if sort == 'new':
            cols.sort(key=lambda c: c.get('created_at', ''), reverse=True)
        elif sort == 'popular':
            cols.sort(key=lambda c: c.get('upvote_count', 0) + len(c.get('websites', [])), reverse=True)
        elif sort == 'updated':
            cols.sort(key=lambda c: c.get('updated_at', ''), reverse=True)
        elif sort == 'top':
            cols.sort(key=lambda c: c.get('quality_score', 0), reverse=True)
        total = len(cols)
        start = (page - 1) * per_page
        return cols[start:start + per_page], total

    def get_collection(self, collection_id):
        for c in self.data.get('collections', []):
            if c['id'] == collection_id:
                return self._normalize_collection(c)
        return None

    def get_user_collections(self, user_id):
        return [self._normalize_collection(c) for c in self.data.get('collections', []) if c['creator_id'] == user_id]

    def update_collection(self, collection_id, user_id, **kwargs):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id and c['creator_id'] == user_id:
                    allowed = ['name','description','content','pin_color','transparent',
                               'background_image','background_style','theme','thumbnail','is_public','pinned_links']
                    for k, v in kwargs.items():
                        if k in allowed and v is not None:
                            if k == 'name':
                                c[k] = v[:100]
                            elif k == 'description':
                                c[k] = v[:500] if v else ''
                            elif k == 'content':
                                c[k] = v
                            elif k == 'pin_color':
                                c[k] = v
                            elif k == 'transparent':
                                c[k] = bool(v)
                            elif k == 'background_image':
                                c[k] = v
                            elif k == 'background_style':
                                c[k] = v if v in ('cover','repeat','contain') else 'cover'
                            elif k == 'theme':
                                c[k] = v[:200] if v else ''
                            elif k == 'thumbnail':
                                c[k] = v[:500] if v else ''
                            elif k == 'pinned_links':
                                c[k] = v if isinstance(v, list) else []
                            elif k == 'is_public':
                                c[k] = bool(v)
                    c['updated_at'] = datetime.now().isoformat()
                    self._auto_approve(c)
                    _save_json(self.data)
                    return c
            return None

    def add_website_to_collection(self, collection_id, user_id, url, title, note):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    if any(w['url'] == url for w in c.get('websites', [])):
                        return None, 'Already in collection'
                    if not note or len(note.strip()) < 10:
                        return None, 'Explanation required (min 10 characters)'
                    w = {
                        'id': str(uuid.uuid4()),
                        'url': url,
                        'title': title[:200] if title else url,
                        'note': note.strip()[:500],
                        'added_by': user_id,
                        'added_at': datetime.now().isoformat(),
                    }
                    c.setdefault('websites', []).append(w)
                    c['updated_at'] = datetime.now().isoformat()
                    c['quality_score'] = self._compute_quality_score(c)
                    _save_json(self.data)
                    return w, None
            return None, 'Collection not found'

    def remove_website_from_collection(self, collection_id, user_id, website_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    c['websites'] = [w for w in c.get('websites', [])
                                     if not (w['id'] == website_id and w['added_by'] == user_id)]
                    c['updated_at'] = datetime.now().isoformat()
                    c['quality_score'] = self._compute_quality_score(c)
                    _save_json(self.data)
                    return True
            return False

    def delete_collection(self, collection_id, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['collections'] = [c for c in self.data.get('collections', [])
                                        if not (c['id'] == collection_id and c['creator_id'] == user_id)]
            _save_json(self.data)
            return True

    def toggle_pin_link(self, collection_id, user_id, website_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id and c['creator_id'] == user_id:
                    pinned = c.get('pinned_links', [])
                    if website_id in pinned:
                        pinned.remove(website_id)
                    else:
                        pinned.append(website_id)
                    c['pinned_links'] = pinned
                    c['updated_at'] = datetime.now().isoformat()
                    _save_json(self.data)
                    return True, 'unpinned' if website_id not in pinned else 'pinned'
            return False, None

    def reorder_websites(self, collection_id, user_id, website_ids):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id and c['creator_id'] == user_id:
                    existing = {w['id']: w for w in c.get('websites', [])}
                    ordered = []
                    for wid in website_ids:
                        if wid in existing:
                            ordered.append(existing[wid])
                    for w in c.get('websites', []):
                        if w['id'] not in website_ids:
                            ordered.append(w)
                    c['websites'] = ordered
                    c['updated_at'] = datetime.now().isoformat()
                    _save_json(self.data)
                    return True
            return False

    QUALITY_THRESHOLD = 20

    def _compute_quality_score(self, collection):
        """Naver-inspired anti-spam + originality scoring.
        Rewards: human-written, personal experience, depth, originality.
        Penalizes: affiliate spam, promo overload, duplicate text, keyword stuffing.
        Shadowbans: content that triggers multiple spam signals."""
        score = 0
        spam_penalty = 0
        content = collection.get('content', '') or ''
        content_lower = content.lower()
        desc = (collection.get('description', '') or '').strip()
        name = (collection.get('name', '') or '').strip()
        content_len = len(content)

        # ── Base quality (original scoring) ──
        if content_len >= 500:
            score += 30
        elif content_len >= 200:
            score += 20
        elif content_len >= 80:
            score += 10
        if collection.get('thumbnail', ''):
            score += 15
        if len(desc) >= 30:
            score += 10
        elif desc:
            score += 5
        websites = collection.get('websites', [])
        if websites:
            expl_len = sum(len(w.get('note', '') or '') for w in websites)
            avg_expl = expl_len / len(websites)
            if avg_expl >= 50:
                score += 25
            elif avg_expl >= 20:
                score += 15
            elif avg_expl >= 10:
                score += 5
            score += min(len(websites) * 3, 20)
        score += min(collection.get('upvote_count', 0) * 2, 15)

        # ── ANTI-SPAM: Affiliate & promotional link detection ──
        AFFILIATE_PATTERNS = [
            'amazon.com/', 'amzn.to', 'amzn.com',
            'shareasale.com', 'rakuten.com', 'cj.com',
            'clickbank.net', 'jvzoo.com', 'warriorplus.com',
            'affiliate', 'ref=', 'tag=', 'utm_source=affiliate',
            'bit.ly/', 'tinyurl.com', 't.co/',
            'bit.do/', 'rb.gy/', 'cutt.ly/',
        ]
        affiliate_count = sum(1 for p in AFFILIATE_PATTERNS if p in content_lower)
        if affiliate_count >= 3:
            spam_penalty += 30
        elif affiliate_count >= 2:
            spam_penalty += 20
        elif affiliate_count >= 1:
            spam_penalty += 8

        # Link-to-content ratio (too many links = spam)
        link_count = content_lower.count('[') + content_lower.count('http')
        words = content_lower.split()
        word_count = max(1, len(words))
        link_ratio = link_count / word_count * 100
        if link_ratio > 8:
            spam_penalty += 25
        elif link_ratio > 5:
            spam_penalty += 15
        elif link_ratio > 3:
            spam_penalty += 5

        # ── ANTI-SPAM: Promotional keyword density ──
        PROMO_KEYWORDS = [
            'buy now', 'limited time', 'act fast', 'order today',
            'discount code', 'coupon', 'promo code', 'special offer',
            'free trial', 'sign up now', 'click here', 'don\'t miss out',
            'exclusive deal', 'best price', 'lowest price', 'save big',
            'money back guarantee', 'risk free', 'no brainer',
            'once in a lifetime', 'insane deal', 'grab yours',
            'affiliate disclosure', 'sponsored post', 'paid partnership',
            'commission', 'earning potential', 'passive income',
        ]
        promo_hits = sum(1 for kw in PROMO_KEYWORDS if kw in content_lower)
        if promo_hits >= 4:
            spam_penalty += 25
        elif promo_hits >= 2:
            spam_penalty += 15
        elif promo_hits >= 1:
            spam_penalty += 5

        # ── ANTI-SPAM: Duplicate / repetitive text ──
        sentences = [s.strip() for s in re.split(r'[.!?]+', content) if len(s.strip()) > 20]
        if sentences:
            unique_sentences = set(s.lower()[:80] for s in sentences)
            dup_ratio = 1.0 - (len(unique_sentences) / len(sentences))
            if dup_ratio > 0.4:
                spam_penalty += 25
            elif dup_ratio > 0.25:
                spam_penalty += 15
            elif dup_ratio > 0.15:
                spam_penalty += 5

        # Repetitive phrase detection
        if word_count > 50:
            bigrams = [' '.join(words[i:i+2]) for i in range(len(words)-1)]
            bigram_counts = {}
            for b in bigrams:
                bigram_counts[b] = bigram_counts.get(b, 0) + 1
            max_rep = max(bigram_counts.values()) if bigram_counts else 0
            rep_ratio = max_rep / len(bigrams) if bigrams else 0
            if rep_ratio > 0.08:
                spam_penalty += 15
            elif rep_ratio > 0.05:
                spam_penalty += 8

        # ── ANTI-SPAM: Keyword stuffing ──
        if word_count > 100:
            unique_words = set(words)
            lexical_diversity = len(unique_words) / word_count
            if lexical_diversity < 0.25:
                spam_penalty += 20
            elif lexical_diversity < 0.35:
                spam_penalty += 10

        # All-caps abuse
        caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
        if caps_words > 5 and caps_words / word_count > 0.03:
            spam_penalty += 10

        # Excessive exclamation/question marks
        exclamations = content.count('!') + content.count('!!') + content.count('!!!')
        if exclamations > 10:
            spam_penalty += 8
        elif exclamations > 5:
            spam_penalty += 3

        # Title clickbait patterns
        CLICKBAIT = ['you won\'t believe', 'shocking', 'this one trick',
                      'doctors hate', 'what they don\'t tell you',
                      'the truth about', 'secret method', 'hack that',
                      'mind blowing', 'unbelievable', 'insane']
        title_lower = name.lower()
        clickbait_hits = sum(1 for kw in CLICKBAIT if kw in title_lower)
        if clickbait_hits >= 2:
            spam_penalty += 15
        elif clickbait_hits >= 1:
            spam_penalty += 8

        # ── ORIGINALITY REWARDS: Personal experience signals ──
        FIRST_PERSON = [' i ', ' my ', ' i\'m ', ' i\'ve ', ' i was ',
                        ' i had ', ' i felt ', ' i tested ', ' i tried ',
                        ' my experience', ' my opinion', ' my review',
                        ' personally', ' in my case', ' when i ', ' as i ']
        first_person_count = sum(1 for p in FIRST_PERSON if p in content_lower)
        if first_person_count >= 5:
            score += 20
        elif first_person_count >= 3:
            score += 12
        elif first_person_count >= 1:
            score += 5

        # ── ORIGINALITY REWARDS: Case study / research signals ──
        RESEARCH_SIGNALS = [
            'according to', 'study found', 'research shows', 'data suggests',
            'in my test', 'i measured', 'i compared', 'results showed',
            'based on my', 'after testing', 'my analysis', 'i tracked',
            'my findings', 'benchmark', 'experiment', 'case study',
            'i conducted', 'survey results', 'statistics show',
            'performance data', 'side by side', 'head to head',
        ]
        research_count = sum(1 for s in RESEARCH_SIGNALS if s in content_lower)
        if research_count >= 4:
            score += 20
        elif research_count >= 2:
            score += 10
        elif research_count >= 1:
            score += 5

        # ── ORIGINALITY REWARDS: Technical depth ──
        if word_count > 800:
            score += 10
        elif word_count > 400:
            score += 5

        # Paragraph structure (good content has paragraphs)
        paragraphs = [p.strip() for p in content.split('\n') if p.strip()]
        if len(paragraphs) >= 5:
            score += 5
        elif len(paragraphs) >= 3:
            score += 3

        # Code blocks or technical formatting (sign of real content)
        if '```' in content or '    ' in content:
            score += 5

        # Lists (sign of structured content)
        list_items = len(re.findall(r'^\s*[-*]\s', content, re.MULTILINE))
        if list_items >= 3:
            score += 3

        # Numbers/data in content (signals real research)
        numbers = len(re.findall(r'\b\d+(\.\d+)?%?\b', content))
        if numbers >= 8:
            score += 5
        elif numbers >= 4:
            score += 3

        # ── ORIGINALITY REWARDS: Sentiment & opinion signals ──
        OPINION_SIGNALS = [
            'i recommend', 'i suggest', 'in my opinion', 'i think',
            'i believe', 'i prefer', 'honestly', 'truthfully',
            'pros and cons', 'the downside', 'the upside',
            'what i liked', 'what i didn\'t like', 'overall',
            'my verdict', 'my take', 'final thoughts',
        ]
        opinion_count = sum(1 for s in OPINION_SIGNALS if s in content_lower)
        if opinion_count >= 3:
            score += 8
        elif opinion_count >= 1:
            score += 3

        # ── Shadowban: apply spam penalty ──
        score -= spam_penalty

        # ── Flag penalty (community reports) ──
        score -= collection.get('flags', 0) * 10

        # ── Shadowban threshold: if too spammy, zero out ──
        if spam_penalty >= 40:
            score = min(score, 0)

        return max(score, 0)

    def _auto_approve(self, collection):
        score = self._compute_quality_score(collection)
        collection['quality_score'] = score
        if score >= self.QUALITY_THRESHOLD:
            collection['is_approved'] = True
            collection['is_listed'] = True
        return collection

    def flag_collection(self, collection_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    c['flags'] = c.get('flags', 0) + 1
                    c['quality_score'] = self._compute_quality_score(c)
                    _save_json(self.data)
                    return True
            return False

    def upvote_collection(self, collection_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    c['upvote_count'] = c.get('upvote_count', 0) + 1
                    c['quality_score'] = self._compute_quality_score(c)
                    _save_json(self.data)
                    return True
            return False

    def increment_collection_views(self, collection_id):
        with self._lock:
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    c['view_count'] = c.get('view_count', 0) + 1
                    return

    def search_collections(self, query, limit=5):
        import re as _re
        q = query.lower().strip()
        query_words = [w for w in q.split() if len(w) > 2]
        if not query_words or len(q) < 3:
            return []
        cols = [self._normalize_collection(c) for c in self.data.get('collections', [])
                if c.get('is_public', True) and (c.get('quality_score', 0) >= self.QUALITY_THRESHOLD or (c.get('is_listed') and c.get('is_approved')))]
        if not cols:
            return []
        scored = []
        for c in cols:
            score = 0
            name = (c.get('name', '') or '').lower()
            desc = (c.get('description', '') or '').lower()
            if not name:
                continue

            # Exact full-phrase in title (strongest signal)
            if q in name:
                score += 50
            else:
                # Word-level matching — use word boundaries to prevent substring false positives
                def word_in_text(word, text):
                    return bool(_re.search(r'(?<!\w)' + _re.escape(word) + r'(?!\w)', text))

                matching_in_name = sum(1 for w in query_words if word_in_text(w, name))
                if matching_in_name == 0:
                    continue

                if matching_in_name < len(query_words):
                    # Not all words match — for multi-word queries, require most
                    if len(query_words) >= 2 and matching_in_name < len(query_words) * 0.5:
                        continue
                    elif len(query_words) >= 2:
                        score += 8
                    elif len(query_words) == 1:
                        # Single word not in title — skip
                        continue

                # Partial phrase match in title
                for i in range(len(query_words)):
                    for j in range(i + 2, len(query_words) + 1):
                        phrase = ' '.join(query_words[i:j])
                        if phrase in name:
                            score += 25

                # All words in title bonus
                if matching_in_name == len(query_words) and len(query_words) > 1:
                    score += 25
                elif matching_in_name == len(query_words):
                    score += 15

            # Quality bonus (very small — never override relevance)
            score += min(c.get('quality_score', 0) * 0.1, 5)

            if score >= 15:
                scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:limit]]

    def get_flagged_collections(self):
        return sorted(
            [self._normalize_collection(c) for c in self.data.get('collections', []) if c.get('flags', 0) > 0],
            key=lambda c: c.get('flags', 0), reverse=True
        )

    def approve_collection(self, collection_id, approve=True):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    c['is_approved'] = approve
                    c['is_listed'] = approve
                    c['flags'] = 0
                    c['quality_score'] = self._compute_quality_score(c)
                    _save_json(self.data)
                    return True
            return False

    # ── User stats / profile ──

    def update_user_email(self, user_id, email):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for u in self.data.get('users', []):
                if u['user_id'] == user_id:
                    email_lower = email.strip().lower()
                    if any(u2.get('email', '').lower() == email_lower for u2 in self.data.get('users', []) if u2.get('email') and u2['user_id'] != user_id):
                        return False, 'Email already in use'
                    u['email'] = email_lower
                    _save_json(self.data)
                    return True, None
            return False, 'User not found'

    def update_user_password(self, user_id, current_password, new_password):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for u in self.data.get('users', []):
                if u['user_id'] == user_id:
                    if not self.check_password(current_password, u['password_hash']):
                        return False, 'Current password is incorrect'
                    if len(new_password) < 8:
                        return False, 'Password must be at least 8 characters'
                    if not re.search(r'[A-Za-z]', new_password) or not re.search(r'[0-9]', new_password):
                        return False, 'Password must contain both letters and numbers'
                    u['password_hash'] = self.hash_password(new_password)
                    _save_json(self.data)
                    return True, None
            return False, 'User not found'

    def update_user_weather_location(self, user_id, location):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for u in self.data.get('users', []):
                if u['user_id'] == user_id:
                    u['weather_location'] = location[:100] if location else ''
                    _save_json(self.data)
                    self._invalidate_user_cache()
                    return True
            return False

    def update_user_bio(self, user_id, bio):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for u in self.data.get('users', []):
                if u['user_id'] == user_id:
                    u['bio'] = bio[:300] if bio else ''
                    _save_json(self.data)
                    self._invalidate_user_cache()
                    return True
            return False

    def get_user_preferences(self, user_id):
        """Get user preferences (ai_summary, etc.)."""
        for u in self.data.get('users', []):
            if u['user_id'] == user_id:
                return u.get('preferences', {'ai_summary': True})
        return {'ai_summary': True}

    def update_user_preferences(self, user_id, prefs):
        """Update user preferences. prefs is a dict like {'ai_summary': True}."""
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for u in self.data.get('users', []):
                if u['user_id'] == user_id:
                    existing = u.get('preferences', {'ai_summary': True})
                    existing.update(prefs)
                    u['preferences'] = existing
                    _save_json(self.data)
                    return True
            return False

    def get_user_profile(self, username):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        users = self.data.get('users', [])
        user = None
        for u in users:
            if u['username'] == username:
                user = u
                break
        if not user:
            return None

        user_id = user['user_id']

        collections_count = sum(1 for c in self.data.get('collections', []) if c['creator_id'] == user_id)
        blogs_count = sum(1 for c in self.data.get('collections', []) if c['creator_id'] == user_id and c.get('post_type') == 'blog')
        pins_count = sum(len(c.get('websites', [])) for c in self.data.get('collections', []) if c['creator_id'] == user_id)
        submissions_count = sum(1 for s in self.data.get('submitted_sites', []) if s.get('submitted_by') == user_id)
        reports_approved = sum(1 for r in self.data.get('domain_reports', []) if user_id in r.get('reported_by', []) and r.get('status') == 'approved')

        # User's collections (for card grid)
        user_collections = []
        for c in self.data.get('collections', []):
            if c['creator_id'] == user_id:
                nc = self._normalize_collection(c)
                user_collections.append({
                    'id': nc['id'],
                    'name': nc['name'],
                    'description': nc.get('description', ''),
                    'thumbnail': nc.get('thumbnail', ''),
                    'pin_color': nc.get('pin_color', '#800000'),
                    'pin_count': len(nc.get('websites', [])),
                    'upvote_count': nc.get('upvote_count', 0),
                    'view_count': nc.get('view_count', 0),
                    'created_at': nc.get('created_at', ''),
                })
        user_collections.sort(key=lambda c: c.get('created_at', ''), reverse=True)

        # Recent activity
        recent = []
        for c in self.data.get('collections', []):
            if c['creator_id'] == user_id:
                recent.append({'type': 'collection', 'url': '/explore/' + c['id'], 'title': c['name'], 'created_at': c.get('created_at', '')})
        for s in self.data.get('submitted_sites', []):
            if s.get('submitted_by') == user_id:
                recent.append({'type': 'submission', 'url': 'https://' + s['domain'], 'title': s.get('name', s['domain']), 'created_at': s.get('submitted_at', '')})
        recent.sort(key=lambda r: r.get('created_at', ''), reverse=True)
        recent = recent[:30]

        joined_date = user.get('created_at', '')[:10] if user.get('created_at') else ''

        return {
            'username': username,
            'bio': user.get('bio', '') or '',
            'weather_location': user.get('weather_location', '') or '',
            'created_at': user.get('created_at', ''),
            'joined_date': joined_date,
            'premium_tier': None,
            'collections_count': collections_count,
            'blogs_count': blogs_count,
            'pins_count': pins_count,
            'submissions_count': submissions_count,
            'reports_approved': reports_approved,
            'user_collections': user_collections[:12],
            'recent': recent,
            'is_owner': False,
        }

    # ── Product Key System ──




data_manager = DataManager()


class KumoCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'KumoCrawler/1.0 (arlong search engine; +https://aoogle.railway.app/)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

    def fetch_sitemap(self, sitemap_url):
        try:
            resp = self.session.get(sitemap_url, timeout=10)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}"
            soup = BeautifulSoup(resp.text, 'xml')
            urls = []
            for loc in soup.select('urlset url loc'):
                url = loc.get_text(strip=True)
                if url:
                    urls.append(url)
            if not urls:
                for loc in soup.select('sitemapindex sitemap loc'):
                    url = loc.get_text(strip=True)
                    if url:
                        sub_urls, _ = self.fetch_sitemap(url)
                        if sub_urls:
                            urls.extend(sub_urls)
            return urls[:200] if urls else None, None
        except Exception as e:
            return None, str(e)

    def check_robots_txt(self, domain):
        try:
            resp = self.session.get(f'https://{domain}/robots.txt', timeout=5)
            if resp.status_code == 200:
                return resp.text, None
            return None, f"No robots.txt (HTTP {resp.status_code})"
        except Exception as e:
            return None, str(e)


kumo = KumoCrawler()

# Entity detection for cross-entity penalty in ranking (deprecated, kept for reference)
BANK_ENTITIES = {
}

def _detect_query_entity(query):
    return None

def _detect_domain_entity(domain):
    return None


def _extract_page_text(url, timeout=5):
    try:
        ua = UserAgent()
        headers = {'User-Agent': ua.random}
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript', 'form', 'svg', 'iframe']):
            tag.decompose()
        body = soup.find('body') or soup
        text = body.get_text(separator=' ', strip=True)
        text = re.sub(r'\s+', ' ', text)
        return text[:5000]
    except Exception:
        return None


class ImprovedSearch:
    def __init__(self):
        self.session = requests.Session()
        # Connection pool with keep-alive for faster repeats
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        try:
            self.user_agent = UserAgent(fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        except:
            self.user_agent = type('SimpleUA',(),{'random':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','__getitem__':lambda s,k:s.random})()
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.search_urls = ["ddg_html://text", "ddg_reddit://text", "ddg_video://text", "google://text", "brave://text", "reddit_scrape://text", "invidious://text"]
        if ddgs_available:
            self.ddgs = DDGS()
            self.search_urls.append("ddgs://text")
            # Warm up DDGS by making a quick harmless query at startup
            try:
                list(self.ddgs.text('warmup', max_results=1, backend='auto', safesearch='on'))
            except Exception:
                pass
        else:
            self.ddgs = None
        self.in_memory_cache = {}
        self.cache_lock = threading.Lock()

    def _get_cache_key(self, query, page):
        """Generate unique cache key for query"""
        return hashlib.md5(f"{query}_{page}".encode()).hexdigest()

    def _get_from_cache(self, key):
        """Retrieve results from cache"""
        if redis_client:
            try:
                cached = redis_client.get(key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass
        with self.cache_lock:
            entry = self.in_memory_cache.get(key)
            if entry:
                data, expire_time = entry
                if time.time() < expire_time:
                    return data
                else:
                    del self.in_memory_cache[key]
        return None

    def _save_to_cache(self, key, data, expire_time=3600):
        """Save results to cache"""
        if redis_client:
            try:
                redis_client.setex(key, expire_time, json.dumps(data))
                return
            except Exception:
                pass
        with self.cache_lock:
            self.in_memory_cache[key] = (data, time.time() + expire_time)

    def _get_headers(self):
        """Generate realistic browser headers to avoid detection"""
        accept_values = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        ]
        return {
            'User-Agent': self.user_agent.random,
            'Accept': random.choice(accept_values),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

    def _fetch_with_retry(self, url, params, max_retries=1, backoff_factor=0):
        last_exception = None

        for attempt in range(max_retries):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    headers=self._get_headers(),
                    timeout=5,
                    allow_redirects=True
                )

                if response.status_code == 200:
                    return response
                elif response.status_code in [429, 403]:
                    app.logger.warning(f"Rate limited on attempt {attempt + 1} for {url}")
                else:
                    app.logger.error(f"HTTP {response.status_code} on attempt {attempt + 1} for {url}")

            except requests.exceptions.RequestException as e:
                last_exception = e
                app.logger.error(f"Request failed on attempt {attempt + 1} for {url}: {str(e)}")

        if last_exception:
            raise last_exception
        else:
            raise Exception(f"Failed to fetch {url} after {max_retries} attempts")

    def _extract_date(self, text):
        """Extract date from result snippet"""
        date_patterns = [
            r'\d{1,2}\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s\d{4}',
            r'\d{4}-\d{2}-\d{2}',
            r'\d{1,2}/\d{1,2}/\d{4}'
        ]

        for pattern in date_patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    return datetime.strptime(match.group(), '%Y-%m-%d').strftime('%b %d, %Y')
                except:
                    return match.group()
        return None

    def _categorize_result(self, url, title, snippet):
        domain = urlparse(url).netloc.lower()
        text = f"{title.lower()} {snippet.lower()}"

        categories = {
            'news': ['news', 'breaking', 'latest', 'report', 'update', 'headline'],
            'shopping': ['shop', 'buy', 'price', 'deal', 'amazon', 'store', 'cart'],
            'social': ['facebook', 'twitter', 'instagram', 'linkedin', 'reddit'],
            'video': ['youtube', 'video', 'watch', 'stream', 'vimeo', 'tiktok'],
            'academic': ['research', 'study', 'paper', 'journal', '.edu', 'scholar'],
            'official': ['official', 'gov', 'organization', '.gov', '.org', 'government'],
            'tech': ['technology', 'software', 'hardware', 'review', 'digital', 'api', 'sdk'],
            'discussion': ['forum', 'discussion', 'thread', 'reddit', 'stackexchange', 'community']
        }

        for category, keywords in categories.items():
            if any(keyword in domain for keyword in keywords) or \
               any(keyword in text for keyword in keywords):
                return category

        return 'general'

    def _score_title_match(self, query, intent, result):
        query_lower = query.lower()
        title_lower = result.title.lower()
        query_terms = intent.terms
        score = 0

        exact_match_bonus = 0
        if query_lower in title_lower:
            exact_match_bonus = 25
            title_start_ratio = title_lower.find(query_lower) / max(len(title_lower), 1)
            if title_start_ratio < 0.3:
                exact_match_bonus += 10

        phrase_in_title = 0
        for i in range(len(query_terms)):
            for j in range(i + 2, min(i + 5, len(query_terms) + 1)):
                phrase = ' '.join(query_terms[i:j])
                if len(phrase) > 4 and phrase in title_lower:
                    phrase_in_title = max(phrase_in_title, len(phrase.split()))

        matching_terms = sum(1 for t in query_terms if t in title_lower)
        term_ratio = matching_terms / max(len(query_terms), 1)

        score = exact_match_bonus
        score += min(phrase_in_title * 5, 15)

        if term_ratio > 0 and not exact_match_bonus:
            score += term_ratio * 8

        if matching_terms == len(query_terms) and not exact_match_bonus:
            score += 12

        short_title_penalty = max(0, 8 - len(result.title.split())) * 1.5
        score -= short_title_penalty

        title_is_list = bool(re.search(r'^\d+\s', title_lower))
        if title_is_list:
            score -= 5

        age_nums = re.findall(r'\b(\d{1,2})\b', query_lower)
        if age_nums and ('year' in query_lower or 'yr' in query_lower or 'old' in query_lower):
            for num in age_nums:
                if num in title_lower:
                    score += 15
                if f'{num} year' in title_lower or f'{num} yr' in title_lower:
                    score += 25

        return max(0, min(score, 50))

    def _score_domain_authority(self, url):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)

        # Check hardcoded domain authority first (authoritative overrides)
        for known_domain, authority in DOMAIN_AUTHORITY.items():
            if domain == known_domain or domain.endswith('.' + known_domain):
                return authority

        # Check Tranco list (top 1M ranked domains)
        if TRANCO_AUTHORITY:
            if domain in TRANCO_AUTHORITY:
                return TRANCO_AUTHORITY[domain]
            parts = domain.split('.')
            for i in range(1, len(parts) - 1):
                parent = '.'.join(parts[i:])
                if parent in TRANCO_AUTHORITY:
                    return max(TRANCO_AUTHORITY[parent] - 5, 5)

        return 8

    def _score_url_quality(self, query, url):
        domain = urlparse(url).netloc.lower()
        path = urlparse(url).path.lower()
        score = 0

        if len(domain.split('.')) == 2 or (len(domain.split('.')) == 3 and domain.startswith('www.')):
            score += 10

        if path and path != '/':
            score += 5
            path_terms = path.replace('-', ' ').replace('_', ' ').replace('/', ' ').split()
            query_terms = query.lower().split()
            path_matches = sum(1 for t in query_terms if t in path_terms)
            score += path_matches * 3

        if '?' in url or 'utm_' in url:
            score -= 5

        if 'blog' in path or 'article' in path:
            score += 5

        content_farms = ['betanet', 'guru99', 'hackr', 'cto', 'blogger', 'hubpages', 'ezinearticles',
                         'articlesfactory', 'article', 'weebly', 'wixsite', 'yolasite',
                         'thecinemaworld', 'ottupdate', 'ottplay', 'bloggingaunty',
                         'theenvoyweb', 'wikibiowiki', 'ottfree', 'gadgets360',
                         'technews', 'tamilanjobs', 'biographyninja',
                         'topstoriesworld', 'dailyentertainment', 'webnewswire',
                         'thetalko', 'screenrant', 'cbr.com', 'whatculture',
                         'fandomwire', 'pinkvilla', 'filmibeat', 'filmfare',
                         'koimoi', 'bollywoodhungama', 'indiatimes',
                         'timesofindia.indiatimes', 'hindustantimes',
                         'indianexpress', 'deccanchronicle', 'thehindu']
        for farm in content_farms:
            if farm in domain:
                score -= 20
                break

        return max(0, score)

    def _score_snippet_relevance(self, query, intent, result):
        query_lower = query.lower()
        snippet_lower = result.snippet.lower()
        query_terms = intent.terms
        score = 0

        matching_terms = sum(1 for t in query_terms if t in snippet_lower)
        term_ratio = matching_terms / max(len(query_terms), 1)
        score += term_ratio * 25

        if query_lower in snippet_lower:
            score += 20

        snippet_word_count = len(snippet_lower.split())
        if 10 <= snippet_word_count <= 50:
            score += 5
        elif snippet_word_count < 5:
            score -= 5

        term_positions = []
        for t in query_terms:
            pos = snippet_lower.find(t)
            if pos >= 0:
                term_positions.append(pos)

        if len(term_positions) > 1:
            proximity = max(term_positions) - min(term_positions)
            if proximity < 50:
                score += 12
            elif proximity < 100:
                score += 6

        # Age/year detection in snippet
        age_nums = re.findall(r'\b(\d{1,2})\b', query_lower)
        if age_nums and ('year' in query_lower or 'yr' in query_lower or 'old' in query_lower):
            for num in age_nums:
                if num in snippet_lower:
                    score += 10
                if f'{num} year' in snippet_lower:
                    score += 20
                if 'minor' in snippet_lower or 'minor account' in snippet_lower:
                    score += 15

        # Long-tail phrase match in snippet
        if len(query_terms) >= 3:
            for i in range(len(query_terms) - 2):
                phrase = ' '.join(query_terms[i:i+3])
                if phrase in snippet_lower:
                    score += 15

        return min(60, max(0, score))

    def _score_freshness(self, result, query_intent='general'):
        if not result.date:
            return 5

        try:
            for fmt in ['%b %d, %Y', '%Y-%m-%d', '%m/%d/%Y']:
                try:
                    date = datetime.strptime(result.date, fmt)
                    break
                except:
                    continue
            else:
                return 5

            days_old = (datetime.now() - date).days
            if query_intent in ('definition', 'explanation'):
                # For timeless queries, reduce freshness pressure
                if days_old < 7:
                    return 15
                elif days_old < 30:
                    return 13
                elif days_old < 90:
                    return 12
                elif days_old < 365:
                    return 10
                elif days_old < 730:
                    return 8
                else:
                    return 5
            else:
                if days_old < 7:
                    return 30
                elif days_old < 30:
                    return 25
                elif days_old < 90:
                    return 20
                elif days_old < 365:
                    return 12
                elif days_old < 730:
                    return 8
                else:
                    return 4
        except:
            return 5

    def _score_reddit_boost(self, query, intent, result):
        domain = urlparse(result.url).netloc.lower()
        title_lower = result.title.lower()
        snippet_lower = result.snippet.lower()
        body = title_lower + ' ' + snippet_lower

        is_actual_reddit = 'reddit.com' in domain
        is_reddit_scraper = not is_actual_reddit and ('reddit' in title_lower.lower() or 'reddit' in snippet_lower.lower())

        if is_reddit_scraper:
            return -25

        if not is_actual_reddit and 'redditmedia.com' not in domain:
            return 0

        if not intent.wants_discussion():
            return -15

        query_terms = intent.terms

        boost = 50
        matching_terms = sum(1 for t in query_terms if t in body)
        boost += matching_terms * 8

        if 'megathread' in body or 'discussion' in body:
            boost += 10

        subreddit_match = re.search(r'r/[\w]+', title_lower + ' ' + snippet_lower)
        if subreddit_match:
            boost += 10

        if 'reddit.com' in domain:
            has_opinion_words = any(w in body for w in ['recommend', 'suggest', 'opinion', 'review', 'experience', 'advice', 'help', 'guide', 'thought'])
            if has_opinion_words:
                boost += 15

        post_age = re.search(r'(\d+)\s*(year|month|week|day|hour)\s*ago', body)
        if post_age:
            boost += 5

        return boost

    def _score_category_relevance(self, query, intent, result):
        query_lower = query.lower()
        cat_scores = {
            'discussion': 8, 'news': 6, 'tech': 5, 'academic': 5,
            'official': 4, 'video': 3, 'shopping': 3, 'social': 2, 'general': 1
        }
        score = cat_scores.get(result.category, 1)

        if intent.wants_discussion() and result.category in ('discussion', 'social'):
            score += 10

        if result.category == 'tech' and any(t in query_lower for t in
            ['code', 'programming', 'software', 'api', 'library', 'framework', 'language']):
            score += 5

        return score

    def _score_content_quality(self, result):
        score = 0
        snippet = result.snippet

        if snippet.endswith(('.', '!', '?')):
            score += 3

        cap_ratio = sum(1 for c in snippet if c.isupper()) / max(len(snippet), 1)
        if 0.05 < cap_ratio < 0.4:
            score += 2
        elif cap_ratio > 0.6:
            score -= 3

        title = result.title
        if title.endswith(('.', '!', '?')):
            score += 1
        if len(title) > 15:
            score += 2

        domain = urlparse(result.url).netloc.lower()
        if any(spam_pattern in domain for spam_pattern in
               ['xyz', '.tk', '.ml', '.ga', '.cf', 'biz', 'info', 'loan', 'casino',
                'porn', 'sex', 'click']):
            score -= 15

        known_low_quality = {
            'w3schools.com': -3, 'tutorialspoint.com': -3,
            'geeksforgeeks.org': -25, 'betanet.net': -40, 'betanet': -40,
            'medium.com': 0, 'guru99.com': -20, 'cto': -15, 'hackr': -15,
            'educative.io': -5, 'pieces.app': -12, 'upgrad': -10,
            'thecinemaworld': -40, 'ottupdate': -40, 'ottplay': -35,
            'bloggingaunty': -40, 'gadgets360': -15, 'technews': -15,
            'theenvoyweb': -30, 'wikibiowiki': -35, 'ottfree': -35,
            'blogger': -10, 'hubpages': -20, 'ezinearticles': -25,
            'articlesfactory': -25, 'weebly': -15, 'wixsite': -15,
            'yolasite': -15, 'wordpress.com': 0, 'blogspot': -10,
            'medium.com': 0, 'substack.com': 5,
            'decider.com': -5, 'whats-on-netflix': 10,
            'eatingwell.com': -15, 'southernliving.com': -15,
            'dailypaws.com': -15, 'realsimple.com': -15,
            'bhg.com': -15, 'thespruce.com': -15,
            'marthastewart.com': -15, 'foodandwine.com': -15,
            'allrecipes.com': -15, 'verywellmind.com': -15,
            'thesprucepets.com': -15, 'travelandleisure.com': -15,
            'brides.com': -15, 'simplyrecipes.com': -15,
            'health.com': -15, 'verywellfamily.com': -15,
            'people.com': -15, 'investopedia.com': -15,
            'byrdie.com': -15, 'bestlifeonline.com': -20,
            'mydomaine.com': -15, 'seriouseats.com': -10,
            'thespruceeats.com': -15, 'verywellhealth.com': -15,
            'tripsavvy.com': -15, 'parents.com': -15,
            'eatthis.com': -20, 'lifewire.com': -15,
            'woodmagazine.com': -10, 'shape.com': -15,
            'learnreligions.com': -15, 'liquor.com': -15,
            'verywellfit.com': -15, 'instyle.com': -15,
            'midwestliving.com': -10, 'treehugger.com': -10,
            'ew.com': -15, 'thoughtco.com': -15,
            'liveabout.com': -15, 'celebwell.com': -20,
            'agriculture.com': -10, 'thebalancemoney.com': -15,
            'allpeoplequilt.com': -10, 'thesprucecrafts.com': -15,
            'thebalance.com': -15, 'thebalancecareers.com': -15,
            'lifesavvy.com': -15, 'businessinsider.com': -10,
        }
        for low_domain, penalty in known_low_quality.items():
            if low_domain in domain:
                score += penalty

        if 'reddit.com' not in domain and 'reddit' in title.lower():
            score -= 30

        # --- AI / scraped content pattern detection ---
        body = (title + ' ' + snippet).lower()

        ai_phrases = [
            "in today's digital", "in today's world", "let's dive in", "let us dive in",
            "in conclusion", "it's worth noting", "it is worth noting",
            "landscape of", "the realm of", "a plethora of",
            "we will explore", "we'll explore", "this comprehensive guide",
            "ever-evolving", "ever evolving", "in this digital age",
            "delve into", "diving into", "look no further",
            "in the ever-growing", "this article will provide", "read on to",
            "in this blog post", "welcome to our", "the ultimate guide",
            "everything you need to know about", "here's everything",
            "here is everything", "in this article we", "this article aims to",
            "we will delve", "we'll delve", "you may have heard",
            "if you're a fan", "if you are a fan", "fans of the",
            "for those unfamiliar", "for those who don't know",
            "let's take a look", "let us take a look", "let's explore",
        ]
        ai_match_count = sum(1 for phrase in ai_phrases if phrase in body)
        if ai_match_count >= 3:
            score -= ai_match_count * 4
        elif ai_match_count >= 1:
            score -= ai_match_count * 2

        # Detect excessive keyword repetition (AI stuffing)
        words = body.split()
        word_freq = {}
        for w in words:
            if len(w) > 3:
                word_freq[w] = word_freq.get(w, 0) + 1
        if word_freq:
            max_freq = max(word_freq.values())
            if max_freq > 4:
                score -= (max_freq - 3) * 2

        # Overly long SEO-stuffed title
        if len(title) > 100:
            score -= 8
        elif len(title) > 70:
            score -= 3

        # Very short repetitive snippet structure
        sentences = re.split(r'[.!?]+', snippet)
        if len(sentences) >= 3:
            short_sentences = sum(1 for s in sentences if len(s.strip().split()) < 6)
            if short_sentences >= len(sentences) // 2:
                score -= 5

        # Excessive comma usage (list-style AI writing)
        if snippet.count(',') > 5:
            score -= 3

        # Detect "also" overuse (AI hallmark)
        also_count = body.count(' also ')
        if also_count >= 2:
            score -= also_count * 2

        return score

    def _score_exact_domain_match(self, query, result):
        query_lower = query.lower()
        domain = urlparse(result.url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)

        for platform_name, platform_domain in PLATFORM_DOMAINS.items():
            if platform_name in query_lower and platform_domain in domain:
                return 50
        return 0

    def _score_navigational_domain_boost(self, query, result):
        query_lower = query.lower().strip()
        query_terms = set(query_lower.split())
        domain = urlparse(result.url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        domain_parts = domain.split('.')
        title_lower = (result.title or '').lower()
        snippet_lower = (result.snippet or '').lower()
        body = title_lower + ' ' + snippet_lower
        body_terms = set(body.split())
        matching_in_body = len(query_terms & body_terms)

        # Exact domain match: query itself is the domain (e.g. "github.com")
        for term in query_terms:
            if term == domain or term == '.'.join(domain_parts[-2:]):
                return 50

        # Relevance gate: require at least 2 query terms in body for domain boost
        if matching_in_body < 2:
            return 0

        for term in query_terms:
            if len(term) <= 2:
                continue
            if any(term == part for part in domain_parts):
                return 40
            if any(term in part for part in domain_parts):
                return 20
        return 0

    def _score_academic_boost(self, query, intent, result):
        if not intent.wants_academic():
            return 0
        domain = urlparse(result.url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        url_lower = result.url.lower()
        title_lower = result.title.lower() if result.title else ''
        snippet_lower = result.snippet.lower() if result.snippet else ''
        body = title_lower + ' ' + snippet_lower
        boost = 0

        if any(acad_domain.strip('.') in domain for acad_domain in ACADEMIC_PRIMARY_DOMAINS):
            boost += 50
        if domain.endswith('.edu'):
            boost += 40
        if '.ac.' in domain:
            boost += 35
        if domain.endswith('.gov'):
            boost += 30

        if result.category == 'academic':
            boost += 25

        if any(d in url_lower for d in ['/doi/', '/abs/', '/pdf/', '/pub/', '/record/', '/articles/']):
            boost += 15

        if re.search(r'\b(doi|arxiv|pmc|pmid)\b', body):
            boost += 15

        if re.search(r'\b(pages?|pp\.|vol\.|no\.|volume|issue)\b', body):
            boost += 10

        if re.search(r'\b19\d{2}|20\d{2}\b', title_lower):
            boost += 5

        if any(d in domain for d in ['wikipedia.org']):
            boost += 5

        for blog_domain in ACADEMIC_NEWS_BLOG_PENALTY_DOMAINS:
            if blog_domain in domain:
                boost -= 35

        if result.category == 'news' and not any(
            src in domain for src in ['nature.com', 'science.org', 'sciencedirect.com',
                                      'springer.com', 'wiley.com', 'pubmed.', 'ncbi.',
                                      'cell.com', 'thelancet.com', 'nejm.org']
        ):
            boost -= 25

        known_commentary = ['review of', 'editorial', 'opinion:', 'commentary', 'news & views',
                            'perspective', 'what is', 'explainer', 'overview of']
        if any(phrase in title_lower for phrase in known_commentary):
            boost -= 20

        return boost

    def _score_clickbait_penalty(self, title):
        title_lower = title.lower()
        penalty = 0
        clickbait_patterns = [
            r'you.won.t.believe', r'you.ll.never', r'blow.your.mind',
            r'jaw.dropping', r'mind.blowing', r'shocking', r'incredible',
            r'this.will', r'what.happens.when', r'the truth about',
            r'why you should', r'(?<!\w)\d+\s+(reason|thing|fact|tip|trick|way|sign)',
            r'you.need.to.know', r'you.need.to.see', r'will.surprise',
            r'can.t.believe', r'don.t.ignore', r'stop.doing',
            r'what.nobody.tells', r'secret', r'xposed', r'guaranteed',
        ]
        for pat in clickbait_patterns:
            if re.search(pat, title_lower):
                penalty -= 12
                break
        excl = title.count('!') + title.count('?')
        if excl >= 2:
            penalty -= 8
        caps_words = sum(1 for w in title.split() if w.isupper() and len(w) > 1)
        total_words = max(len(title.split()), 1)
        if total_words >= 3 and caps_words / total_words > 0.5:
            penalty -= 10
        return max(-25, penalty)

    def _score_answer_quality(self, query, snippet):
        query_lower = query.lower().strip()
        snippet_lower = snippet.lower().strip()
        if not snippet_lower or not query_lower:
            return 0
        boost = 0
        if query_lower.endswith('?'):
            snippet_start = snippet_lower[:80]
            if snippet_lower.startswith(query_lower[:-1].strip()):
                boost += 20
            answer_indicators = ['is a', 'is an', 'is the', 'are a', 'refers to', 'means',
                                 'is defined as', 'can be described', 'is used for']
            if any(ind in snippet_start for ind in answer_indicators):
                boost += 15
            if '?' not in snippet_start and snippet_start.rstrip().endswith(('.', '!', '?')):
                boost += 10
        query_terms = query_lower.split()
        if len(query_terms) >= 2:
            first_term_pos = snippet_lower.find(query_terms[0])
            if first_term_pos >= 0:
                proximity = 0
                for t in query_terms[1:]:
                    pos = snippet_lower.find(t, first_term_pos)
                    if pos >= 0:
                        proximity += pos - first_term_pos
                if proximity < 60:
                    boost += 12
                elif proximity < 120:
                    boost += 6
        if len(snippet_lower) > 150 and snippet_lower.count('.') >= 2:
            boost += 5
        if re.search(r'\d+%|\$\d+|\d+ (year|month|day|hour|minute|person|people|time)', snippet_lower):
            boost += 8
        return min(30, boost)

    def _score_title_naturalness(self, title):
        title_lower = title.lower().strip()
        penalty = 0
        words = title_lower.split()
        if len(words) <= 2:
            return -15
        pipe_count = title.count('|')
        if pipe_count >= 3:
            penalty -= 10
        elif pipe_count >= 2:
            penalty -= 5
        hyphen_words = sum(1 for w in words if '-' in w)
        if len(words) >= 3 and hyphen_words / len(words) > 0.4:
            penalty -= 8
        comma_separated = len(re.findall(r'\w+,\s+\w+', title))
        if len(words) >= 4 and comma_separated >= 2:
            penalty -= 10
        if re.search(r'(?:^|\s)[A-Z]{2,}(?:\s|$)', title):
            penalty -= 5
        has_verb = any(w.endswith(('ed', 'ing', 's')) and len(w) > 3 for w in words)
        has_preposition = any(w in title_lower for w in ['of', 'in', 'for', 'with', 'at', 'by', 'on', 'from'])
        if not has_verb and not has_preposition and len(words) >= 4:
            penalty -= 8
        return max(-20, penalty)

    def _score_url_depth_penalty(self, url):
        path = urlparse(url).path.strip('/')
        if not path:
            return 0
        segments = [s for s in path.split('/') if s and not s.startswith('#')]
        depth = len(segments)
        penalty = 0
        if depth >= 6:
            penalty = -15
        elif depth >= 4:
            penalty = -8
        elif depth >= 3:
            penalty = -3
        hex_patterns = sum(1 for s in segments if re.match(r'^[0-9a-f]{8,}$', s))
        if hex_patterns >= 1:
            penalty -= 10
        num_segments = sum(1 for s in segments if re.match(r'^\d+$', s))
        if num_segments >= 2:
            penalty -= 8
        encoded_chars = path.count('%') + path.count('+') + path.count('_')
        if encoded_chars > depth * 2:
            penalty -= 5
        return max(-20, penalty)

    def _score_snippet_substance(self, snippet):
        snippet_lower = snippet.lower().strip()
        if not snippet_lower:
            return 0
        score = 0
        word_count = len(snippet_lower.split())
        if word_count < 20:
            score -= 10
        elif word_count < 40:
            score -= 3
        if word_count > 80:
            score += 5
        num_count = len(re.findall(r'\d+', snippet_lower))
        if num_count >= 3:
            score += 8
        elif num_count >= 1:
            score += 3
        if '"' in snippet or '&ldquo;' in snippet:
            score += 6
        if re.search(r'https?://|\.com|\.org|\.gov', snippet_lower):
            score += 4
        stats_indicator = ['%', 'percent', 'according to', 'study found', 'research shows',
                           'ranked', 'rated', 'survey', 'statistics', 'data shows']
        if any(ind in snippet_lower for ind in stats_indicator):
            score += 8
        if snippet_lower.count('.') >= 3:
            score += 4
        return min(20, max(-15, score))

    def _is_discussion_site(self, url):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)
        for d in DISCUSSION_DOMAINS:
            if d.endswith('.') and d[:-1] in domain:
                return True
            if domain == d or domain.endswith('.' + d):
                return True
        return False

    def _classify_query_intent(self, query):
        q = query.lower().strip()
        if re.search(r'^how do(?:es)?\s+\S+\s+work', q):
            return 'explanation'
        if q.startswith('how do i') or q.startswith('how can i') or q.startswith('how to'):
            return 'tutorial'
        if q.startswith('how does') or q.startswith('how do'):
            return 'tutorial'
        if q.startswith('what is') or q.startswith('what are') or q.startswith('what does') or q.startswith('define'):
            return 'definition'
        if q.startswith('why') or q.startswith('what causes') or q.startswith('what makes'):
            return 'reason'
        if q.startswith('where') or q.startswith('who') or q.startswith('when'):
            return 'fact'
        if q.startswith('best') or q.startswith('top') or ' vs ' in q or 'versus' in q:
            return 'comparison'
        if q.startswith('how much') or q.startswith('how many') or q.startswith('price') or q.startswith('cost'):
            return 'quantitative'
        return 'general'

    def _score_intent_match(self, query_intent, title, snippet, query=''):
        tl = (title or '').lower()
        sl = (snippet or '').lower()
        combined = tl + ' ' + sl
        query_lower = query.lower()
        if query_intent == 'explanation':
            if tl.startswith('how does') or tl.startswith('how do'):
                return 30
            if 'how it work' in combined or 'how does it work' in combined or 'explain' in tl:
                return 30
            if 'overview' in tl or 'guide' in tl or '的工作原理' in combined:
                return 20
            if 'how to' in tl and 'use' in tl:
                return -15
            if 'getting started' in tl:
                return -12
            return 0
        if query_intent == 'tutorial':
            if 'how to' in tl or 'tutorial' in tl or 'guide' in tl or 'step' in tl:
                return 25
            if 'getting started' in tl:
                return 20
            return 0
        if query_intent == 'definition':
            if 'what is' in tl[:30] or 'define' in tl or 'meaning' in tl:
                return 25
            if 'what is' in combined[:60]:
                return 15
            return 0
        if query_intent == 'comparison':
            if 'vs' in combined or 'versus' in combined or 'compared' in combined or 'comparison' in combined or 'difference' in combined:
                return 25
            if 'review' in tl or 'best' in tl:
                return 15
            return 0
        if query_intent == 'reason':
            if 'why' in tl or 'cause' in combined or 'reason' in combined or 'because' in combined:
                return 25
            return 0
        if query_intent == 'fact':
            if any(w in tl for w in ['when', 'who', 'where', 'founded', 'born', 'located', 'established']):
                return 25
            if re.search(r'\d{4}', combined[:80]):
                return 10
            return 0
        if query_intent == 'quantitative':
            if re.search(r'\d+%|\$\d+|\d+ (million|billion|trillion|year|people)', combined):
                return 25
            if any(w in combined for w in ['price', 'cost', 'revenue', 'population', 'statistics', 'data']):
                return 15
            return 0
        if query_intent == 'general':
            matching = sum(1 for w in query_lower.split() if w in combined)
            if matching >= 2:
                return 5
            return 0
        return 0

    def _rank_results(self, query, results):
        intent = SearchIntent(query)
        query_lower = query.lower().strip()
        query_intent_subtype = self._classify_query_intent(query)
        blacklist = data_manager.get_blacklist()

        scored = []
        for result in results:
            s = 0

            s += self._score_title_match(query, intent, result) * 0.18
            s += self._score_snippet_relevance(query, intent, result) * 0.14
            s += self._score_domain_authority(result.url) * 0.08
            s += self._score_exact_domain_match(query, result) * 0.10
            s += self._score_url_quality(query, result.url) * 0.06
            s += self._score_freshness(result, query_intent_subtype) * 0.08
            s += self._score_category_relevance(query, intent, result) * 0.06
            s += self._score_content_quality(result) * 0.10
            s += self._score_reddit_boost(query, intent, result) * 0.07
            s += self._score_navigational_domain_boost(query, result) * 0.10
            s += self._score_answer_quality(query, result.snippet) * 0.08
            s += self._score_snippet_substance(result.snippet) * 0.07
            s += self._score_clickbait_penalty(result.title)
            s += self._score_title_naturalness(result.title)
            s += self._score_url_depth_penalty(result.url)
            s += self._score_academic_boost(query, intent, result)
            s += self._score_intent_match(query_intent_subtype, result.title, result.snippet, query) * 0.20

            domain = urlparse(result.url).netloc.lower()
            domain = re.sub(r'^www\.', '', domain)
            for bl_domain, bl_penalty in blacklist.items():
                if bl_domain in domain:
                    s += bl_penalty

            s = max(0, s)

            result.score = round(s, 2)
            # Exact-match amplifier: if the exact query appears in the title, boost it
            if query_lower in (result.title or '').lower():
                result.score = round(result.score * 1.3, 2)
            scored.append(result)

        scored.sort(key=lambda x: x.score, reverse=True)

        deduplicated = []
        seen_titles = set()
        domain_count = {}
        seen_base_urls = {}

        def normalize_article_url(url):
            u = urlparse(url)
            path = re.sub(r'\.(pdf|html?|php|asp|aspx)$', '', u.path.rstrip('/'))
            path = re.sub(r'/(print|full|fulltext|abstract|download|view)$', '', path)
            path = re.sub(r'/(v[\d]+|abs|pdf|epdf)$', '', path)
            path = re.sub(r'[?#].*$', '', path)
            return u.netloc.lower() + path

        for r in scored:
            if SearchBlocker.is_ad(r.url, r.title, r.snippet):
                continue
            if SearchBlocker.is_blocklisted(r.url):
                continue

            domain = urlparse(r.url).netloc.lower()
            domain = re.sub(r'^www\.', '', domain)
            parts = domain.split('.')
            if len(parts) > 2:
                # Handle multi-part TLDs like co.uk, com.au
                if parts[-2] in ('co', 'com', 'org', 'net', 'ac', 'edu', 'gov', 'or', 'ne'):
                    domain = '.'.join(parts[-3:])
                else:
                    domain = '.'.join(parts[-2:])
            title_norm = r.title.lower().strip()

            if title_norm in seen_titles:
                continue
            seen_titles.add(title_norm)

            base_url = normalize_article_url(r.url)
            if base_url in seen_base_urls:
                seen_base_urls[base_url] = max(seen_base_urls[base_url], r.score)
                continue
            seen_base_urls[base_url] = r.score

            if domain not in domain_count:
                domain_count[domain] = 0
            domain_count[domain] += 1

            if domain_count[domain] > 2:
                continue
            elif domain_count[domain] > 1:
                r.score *= 0.4

            deduplicated.append(r)

        deduplicated.sort(key=lambda x: x.score, reverse=True)

        # Drop very low-scored results (likely irrelevant)
        if deduplicated and deduplicated[0].score > 0:
            threshold = deduplicated[0].score * 0.05
            deduplicated = [r for r in deduplicated if r.score >= threshold]

        return deduplicated[:50]

    def _group_results_by_domain(self, results):
        """Group non-discussion results by domain. Returns list of groups.
        Each group: {'domain': str, 'favicon': str, 'results': [SearchResult, ...]}
        Discussion results are excluded (handled separately in template).
        Handles both SearchResult objects and dicts.
        """
        DISC_KEYWORDS = ('reddit', 'forum', 'stackexchange')
        groups = []
        seen = {}
        for r in results:
            if isinstance(r, dict):
                r_cat = r.get('category', 'general')
                r_url = r.get('url', '')
                r_domain = r.get('domain', '')
                r_favicon = r.get('favicon', '')
            else:
                r_cat = r.category
                r_url = r.url
                r_domain = r.domain or ''
                r_favicon = r.favicon
            is_disc = r_cat in ('discussions', 'discussion') or any(k in r_url for k in DISC_KEYWORDS)
            if is_disc:
                continue
            domain = r_domain.lower().replace('www.', '')
            if not domain:
                try:
                    domain = urlparse(r_url).netloc.lower().replace('www.', '')
                except Exception:
                    domain = 'unknown'
            if domain not in seen:
                g = {'domain': domain, 'favicon': r_favicon, 'results': [r]}
                seen[domain] = g
                groups.append(g)
            else:
                seen[domain]['results'].append(r)
        return groups

    def _parse_duckduckgo_results(self, html):
        results = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for div in soup.find_all('div', class_='result'):
                try:
                    title_elem = div.select_one('.result__a')
                    if not title_elem:
                        continue
                    title = title_elem.get_text().strip()

                    url = title_elem.get('href', '')
                    if not url:
                        continue

                    if SearchBlocker.is_ad(url, title, ''):
                        continue

                    snippet_elem = div.select_one('.result__snippet')
                    snippet = snippet_elem.get_text().strip() if snippet_elem else ''

                    if SearchBlocker.is_ad(url, title, snippet):
                        continue

                    if title and url:
                        date = self._extract_date(snippet)
                        category = self._categorize_result(url, title, snippet)
                        result = SearchResult(title, url, snippet, category, date)
                        results.append(result)

                except Exception as e:
                    app.logger.error(f"Error parsing DuckDuckGo result: {str(e)}")
                    continue
        except Exception as e:
            app.logger.error(f"Error parsing DuckDuckGo HTML: {str(e)}")
        return results

    def _search_ddg_with_site(self, query, site_filter):
        try:
            q = query + ' ' + site_filter
            r = self.session.post('https://html.duckduckgo.com/html/', data={'q': q}, headers=self._get_headers(), timeout=2.5)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, 'html.parser')
            results = []
            seen = set()
            for result in soup.find_all('div', class_='result') or soup.find_all('div', class_='result__body'):
                try:
                    a = result.find('a', class_='result__a') or result.find('a', href=True)
                    if not a or not a.get('href'):
                        continue
                    href = a['href']
                    if not href.startswith('http') or href in seen:
                        continue
                    seen.add(href)
                    title = a.get_text().strip()
                    if not title:
                        continue
                    snippet_el = result.find('a', class_='result__snippet') or result.find('div', class_='result__snippet')
                    snippet = snippet_el.get_text().strip()[:300] if snippet_el else ''
                    parsed = urlparse(href)
                    category = 'discussion' if 'site:reddit.com' in site_filter else 'video'
                    results.append(SearchResult(
                        title=title, url=href, snippet=snippet,
                        category=category, date=None, domain=parsed.netloc
                    ))
                except Exception:
                    continue
                if len(results) >= 5:
                    break
            return results
        except Exception as e:
            app.logger.error(f"DDG site search ({site_filter[:20]}) error: {e}")
            return []

    def _search_duckduckgo_html(self, query):
        try:
            url = 'https://html.duckduckgo.com/html/'
            params = {'q': query}
            headers = self._get_headers()
            r = self.session.post(url, data=params, headers=headers, timeout=5)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, 'html.parser')
            results = []
            seen = set()
            for result in soup.find_all('div', class_='result') or soup.find_all('div', class_='result__body'):
                try:
                    a = result.find('a', class_='result__a') or result.find('a', href=True)
                    if not a or not a.get('href'):
                        continue
                    href = a['href']
                    if not href.startswith('http'):
                        continue
                    if href in seen:
                        continue
                    seen.add(href)
                    title = a.get_text().strip()
                    if not title:
                        continue
                    snippet_el = result.find('a', class_='result__snippet') or result.find('div', class_='result__snippet')
                    snippet = snippet_el.get_text().strip()[:300] if snippet_el else ''
                    parsed = urlparse(href)
                    date = self._extract_date(snippet)
                    category = self._categorize_result(href, title, snippet)
                    results.append(SearchResult(
                        title=title, url=href, snippet=snippet,
                        category=category, date=date, domain=parsed.netloc
                    ))
                except Exception:
                    continue
                if len(results) >= 15:
                    break
            return results
        except Exception as e:
            app.logger.error(f"DDG HTML search error: {e}")
            return []

    def _search_reddit_scrape(self, query):
        try:
            resp = self.session.get(
                'https://old.reddit.com/search',
                params={'q': query, 'sort': 'relevance', 't': 'all'},
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'},
                timeout=10
            )
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, 'html.parser')
            results = []
            seen = set()
            for post in soup.find_all('div', class_='search-result-link'):
                if len(results) >= 5:
                    break
                title_el = post.find('a', class_='search-title')
                if not title_el:
                    continue
                title = title_el.get_text(strip=True)[:150]
                url = title_el.get('href', '')
                if not title or not url or url in seen:
                    continue
                seen.add(url)
                body_el = post.find('div', class_='search-result-body')
                snippet = body_el.get_text(strip=True)[:300] if body_el else ''
                sub_el = post.find('a', class_='search-subreddit-link')
                subreddit = sub_el.get_text(strip=True) if sub_el else ''
                time_el = post.find('time')
                date_str = time_el.get('datetime', '')[:10] if time_el else ''
                domain = urlparse(url).netloc.lower()
                results.append(SearchResult(
                    title=title, url=url, snippet=snippet or subreddit,
                    category='discussion', date=date_str, domain=domain or 'reddit.com',
                    source='reddit'
                ))
            return results
        except Exception as e:
            app.logger.error(f"Reddit scrape error: {e}")
            return []

    def _search_invidious(self, query):
        try:
            resp = self.session.get(
                'https://inv.nadeko.net/search',
                params={'q': query},
                headers=self._get_headers(),
                timeout=10
            )
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, 'html.parser')
            results = []
            seen = set()
            for card in soup.find_all('div', class_='video-card-row'):
                if len(results) >= 5:
                    break
                a = card.find('a', href=lambda h: h and '/watch?v=' in h)
                if not a:
                    continue
                href = a.get('href', '')
                vid_id = href.split('v=')[-1].split('&')[0] if 'v=' in href else ''
                if not vid_id or vid_id in seen:
                    continue
                seen.add(vid_id)
                title_p = a.find('p')
                title = title_p.get_text(strip=True)[:150] if title_p else ''
                if not title:
                    continue
                url = f'https://www.youtube.com/watch?v={vid_id}'
                thumb = f'https://i.ytimg.com/vi/{vid_id}/hqdefault.jpg'
                results.append(SearchResult(
                    title=title, url=url, snippet='',
                    category='video', domain='youtube.com', source='invidious',
                    favicon=thumb
                ))
            return results
        except Exception as e:
            app.logger.error(f"Invidious search error: {e}")
            return []

    def _search_single_engine(self, search_url, query, page, region=None):
        try:
            if search_url == 'ddg_html://text':
                return self._search_duckduckgo_html(query)
            elif search_url == 'ddgs://text':
                if not self.ddgs:
                    return []
                try:
                    ddgs_kwargs = dict(query=query, max_results=10, backend='html', safesearch='off')
                    if region:
                        ddgs_kwargs['region'] = region
                    raw = self.ddgs.text(**ddgs_kwargs)
                    results = []
                    for r in raw:
                        title = r.get('title', '')
                        href = r.get('href', '')
                        body = r.get('body', '')
                        if not title or not href:
                            continue
                        parsed = urlparse(href)
                        results.append(SearchResult(
                            title=title, url=href, snippet=body[:300],
                            category='general', date=None, domain=parsed.netloc
                        ))
                    return results
                except Exception as e:
                    app.logger.error(f"DDGS search error: {e}")
                    return []
            elif search_url == 'ddg_reddit://text':
                return self._search_ddg_with_site(query, 'site:reddit.com')
            elif search_url == 'ddg_video://text':
                return self._search_ddg_with_site(query, 'site:youtube.com OR site:vimeo.com OR site:dailymotion.com')
            elif search_url == 'google://text':
                return _search_google(query, max_results=5)
            elif search_url == 'brave://text':
                return _search_brave(query, max_results=10)
            elif search_url == 'reddit_scrape://text':
                return self._search_reddit_scrape(query)
            elif search_url == 'invidious://text':
                return self._search_invidious(query)
            elif 'duckduckgo' in search_url:
                all_results = []
                offsets = [0]
                for i, offset in enumerate(offsets):
                    try:
                        data = {'q': query}
                        if offset > 0:
                            data['s'] = str(offset)
                        response = self.session.post(
                            search_url,
                            data=data,
                            headers=self._get_headers(),
                            timeout=8,
                            allow_redirects=True
                        )
                        if response and response.status_code == 200 and response.text:
                            page_results = self._parse_duckduckgo_results(response.text)
                            all_results.extend(page_results)
                            if len(page_results) < 3:
                                break
                        elif response and response.status_code == 202:
                            app.logger.warning(f"DDG CAPTCHA block for query: {query[:30]}")
                            break
                        else:
                            break
                    except Exception as e:
                        app.logger.error(f"DDG page {i} error: {str(e)}")
                        continue
                    if len(all_results) >= 20:
                        break
                return all_results
            else:
                return []
        except Exception as e:
            app.logger.error(f"Search error on {search_url}: {str(e)}")
            return []
        return []

    def _search_fallback(self, query, region=None):
        """Fallback search when primary methods fail"""
        results = []
        seen = set()

        # 0. DDGS metasearch (fastest, uses multiple engines)
        if self.ddgs:
            try:
                ddgs_kwargs = dict(query=query, max_results=25, backend='auto', safesearch='on')
                if region:
                    ddgs_kwargs['region'] = region
                raw = self.ddgs.text(**ddgs_kwargs)
                for r in raw:
                    title = r.get('title', '')
                    href = r.get('href', '')
                    body = r.get('body', '')
                    if not title or not href or href in seen:
                        continue
                    seen.add(href)
                    results.append(SearchResult(
                        title=title, url=href, snippet=body[:300],
                        category='general', domain=urlparse(href).netloc
                    ))
                    if len(results) >= 30:
                        break
            except Exception as e:
                app.logger.error(f"Fallback DDGS error: {e}")

        # 1. DDG Instant Answer API (works without CAPTCHA)
        if len(results) < 10:
            try:
                r = self.session.get('https://api.duckduckgo.com/', params={
                    'q': query, 'format': 'json', 'no_html': 1, 'skip_disambig': 1
                }, headers=self._get_headers(), timeout=5)
                if r and r.status_code == 200:
                    data = r.json()
                    if data.get('AbstractURL') and data.get('AbstractText'):
                        url = data['AbstractURL']
                        if url not in seen:
                            seen.add(url)
                            results.append(SearchResult(
                                title=data.get('Heading', query)[:80],
                                url=url, snippet=data.get('AbstractText', '')[:200],
                                category='general', domain=urlparse(url).netloc
                            ))
                    for topic in data.get('RelatedTopics', []):
                        if isinstance(topic, dict) and topic.get('FirstURL'):
                            url = topic['FirstURL']
                            if url in seen:
                                continue
                            seen.add(url)
                            text = topic.get('Text', '')
                            title = text.split(' - ')[0] if ' - ' in text else text[:80]
                            results.append(SearchResult(
                                title=title, url=url, snippet=text[:200],
                                category='general', domain=urlparse(url).netloc
                            ))
                            if len(results) >= 15:
                                break
            except Exception as e:
                app.logger.error(f"Fallback DDG API error: {e}")

        return results

    def search(self, query, page=1, filter_type='general', region=None):
        """Main search method with pagination and fallback"""
        self._current_region = region
        per_page = 20
        cache_key = self._get_cache_key(f"{query}_{filter_type}_{region or 'all'}", 1)
        cached_all = self._get_from_cache(cache_key)
        all_results = None

        if cached_all:
            all_results = cached_all
        else:
            results = []
            errors = []
            all_results = None

            futures = {}
            for search_url in self.search_urls:
                future = self.executor.submit(self._search_single_engine, search_url, query, page, region)
                futures[future] = search_url

            try:
                # Stage 1: collect fast results (DDG sources typically finish in 1-2s)
                done, not_done = wait(list(futures.keys()), timeout=2.5, return_when=FIRST_COMPLETED)
                seen_urls = set()
                for future in done:
                    try:
                        current_results = future.result()
                        if current_results:
                            for r in current_results:
                                if r.url not in seen_urls:
                                    seen_urls.add(r.url)
                                    results.append(r)
                    except Exception as e:
                        errors.append(str(e))
                # Stage 2: always wait for remaining engines (Brave needs 2-4s)
                if not_done:
                    remaining, _ = wait(not_done, timeout=2.5, return_when=ALL_COMPLETED)
                    for future in remaining:
                        try:
                            current_results = future.result()
                            if current_results:
                                for r in current_results:
                                    if r.url not in seen_urls:
                                        seen_urls.add(r.url)
                                        results.append(r)
                        except Exception as e:
                            errors.append(str(e))
                for f in futures:
                    if not f.done():
                        f.cancel()
            except TimeoutError:
                app.logger.warning(f"Search timed out for query: {query[:50]}")

            if not results:
                app.logger.warning("Primary search returned no results, trying fallback")
                results = self._search_fallback(query, region)

            if results:
                ranked_results = self._rank_results(query, results)
                all_results = [result.to_dict() for result in ranked_results]
                self._save_to_cache(cache_key, all_results)

        if not all_results:
            return [], 0

        total = len(all_results)
        start = (page - 1) * per_page
        end = start + per_page
        page_results = all_results[start:end]

        return page_results, total

    def _extract_ddg_url(self, url):
        if url.startswith('//duckduckgo.com/l/') or 'duckduckgo.com/l/' in url:
            parsed = urlparse(url if '://' in url else 'https:' + url)
            params = parse_qs(parsed.query)
            if 'uddg' in params:
                return unquote(params['uddg'][0])
        return url


    def _is_relevant_image(self, title, src_url, query):
        """Check if an image result is relevant to the query."""
        q_lower = query.lower().strip()
        if not q_lower:
            return True
        q_words = [w for w in q_lower.split() if len(w) > 2]
        if not q_words:
            return True
        text = (title.lower() + ' ' + src_url.lower())
        return any(w in text for w in q_words)

    def search_images(self, query):
        images = []
        seen_urls = set()
        query_keywords = [w.lower() for w in query.split() if len(w) > 2]

        # Primary: ddgs metasearch
        if ddgs_available:
            try:
                ddgs_results = DDGS(timeout=5).images(query, max_results=50, safesearch='on')
                for item in ddgs_results:
                    img_url = item.get('image', '')
                    if not img_url or img_url in seen_urls:
                        continue
                    seen_urls.add(img_url)
                    title = (item.get('title', '') or '')[:100]
                    thumb = item.get('thumbnail', '') or img_url
                    src = item.get('url', '') or '#'
                    dom = urlparse(src).netloc if src != '#' else ''
                    if query_keywords and not self._is_relevant_image(title, src, query):
                        app.logger.debug(f"Skipping irrelevant image: {title}")
                        continue
                    images.append({'thumbnail': thumb, 'full_url': img_url, 'title': title or dom or query, 'source_url': src, 'source_domain': dom or 'image'})
                    if len(images) >= 50:
                        break
            except Exception as e:
                app.logger.error(f"DDGS images: {e}")

        # Fallback 1: Bing scrape (only if ddgs returned too few)
        if len(images) < 20:
            try:
                r = self.session.get('https://www.bing.com/images/search', params={'q': query, 'form': 'HDRSC2'}, headers=self._get_headers(), timeout=10)
                if r and r.status_code == 200:
                    for a in BeautifulSoup(r.text, 'html.parser').find_all('a', class_='iusc'):
                        try:
                            d = json.loads(a.get('m', '{}'))
                            murl = d.get('murl', '')
                            if not murl or murl in seen_urls:
                                continue
                            seen_urls.add(murl)
                            if 'pinterest' in murl.lower():
                                continue
                            img = a.find('img')
                            title = img.get('alt', '') if img else ''
                            if title and title.startswith('Image result'):
                                title = ''
                            purl = d.get('purl', '')
                            dom = urlparse(purl).netloc if purl else ''
                            turl = (d.get('turl', '') or '').split('&pid')[0] or murl
                            if query_keywords and not self._is_relevant_image(title, purl, query):
                                continue
                            images.append({'thumbnail': turl, 'full_url': murl, 'title': title[:100] or dom or query, 'source_url': purl or '#', 'source_domain': dom or 'image'})
                            if len(images) >= 50:
                                break
                        except:
                            continue
            except Exception as e:
                app.logger.error(f"Bing images: {e}")

        # Fallback 2: DDG VQD (usually blocked on Railway)
        if len(images) < 10:
            try:
                def extract_vqd(html):
                    for p in [r'vqd=([\d-]+)&', r'vqd=([\d-]+)', r'"vqd":"([\d-]+)"', r"'vqd':\s*'([\d-]+)'"]:
                        m = re.search(p, html)
                        if m:
                            return m.group(1)
                    return None
                r = self.session.get('https://duckduckgo.com/', params={'q': query, 'iax': 'images', 'ia': 'images'}, headers=self._get_headers(), timeout=8)
                vqd = extract_vqd(r.text) if r and r.status_code == 200 else None
                if vqd:
                    api_resp = self.session.get('https://duckduckgo.com/i.js', params={'q': query, 'o': 'json', 'vqd': vqd, 'f': ',,,'}, headers={**self._get_headers(), 'Referer': 'https://duckduckgo.com/'}, timeout=8)
                    if api_resp and api_resp.status_code == 200:
                        for item in api_resp.json().get('results', []):
                            try:
                                img_url = item.get('image', '')
                                if not img_url or img_url in seen_urls:
                                    continue
                                seen_urls.add(img_url)
                                title = (item.get('title', '') or '')[:100]
                                thumb = item.get('thumbnail', '') or img_url
                                src = item.get('url', '') or '#'
                                dom = urlparse(src).netloc if src != '#' else ''
                                if query_keywords and not self._is_relevant_image(title, src, query):
                                    continue
                                images.append({'thumbnail': thumb, 'full_url': img_url, 'title': title or dom or query, 'source_url': src, 'source_domain': dom or 'image'})
                                if len(images) >= 50:
                                    break
                            except:
                                continue
            except Exception as e:
                app.logger.error(f"DDG images fallback: {e}")

        return images[:50]

    def search_videos(self, query):
        cache_key = f"videos:{query.lower().strip()}"
        with self.cache_lock:
            cached = self.in_memory_cache.get(cache_key)
            if cached and time.time() < cached.get('expires', 0):
                return cached['data']

        videos = []
        seen_ids = set()

        # Primary: ddgs metasearch (fastest, most reliable)
        if ddgs_available:
            try:
                ddgs_results = DDGS(timeout=5).videos(query, max_results=30, backend='auto', safesearch='on')
                for item in ddgs_results:
                    vid = item.get('content', '')
                    if not vid:
                        continue
                    vid_id = vid.split('v=')[-1].split('&')[0] if 'v=' in vid else vid
                    if vid_id in seen_ids:
                        continue
                    seen_ids.add(vid_id)
                    images = item.get('images', {}) or {}
                    thumb = images.get('medium', '') or images.get('small', '') or images.get('large', '') or ''
                    videos.append({
                        'id': vid_id,
                        'title': (item.get('title', '') or '')[:120],
                        'url': vid,
                        'thumbnail': thumb,
                        'duration': item.get('duration', '') or '',
                        'views': '',
                        'published': '',
                        'channel': '',
                        'channel_url': '',
                    })
                    if len(videos) >= 30:
                        break
            except Exception as e:
                app.logger.error(f"DDGS videos: {e}")

        # Fallback: YouTube scrape
        if len(videos) < 6:
            def extract_json(text):
                m = re.search(r'ytInitialData\s*=\s*(\{)', text)
                if not m:
                    return None
                brace_start = m.start(1)
                depth = 0
                in_str = False
                esc = False
                for i in range(brace_start, len(text)):
                    ch = text[i]
                    if in_str:
                        if esc:
                            esc = False
                        elif ch == '\\':
                            esc = True
                        elif ch == '"':
                            in_str = False
                    elif ch == '"':
                        in_str = True
                    elif ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            return text[brace_start:i+1]
                return None

            def raw_to_json(raw):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    raw = re.sub(r"(?<!\\)'", '"', raw)
                    raw = re.sub(r',\s*}', '}', raw)
                    raw = re.sub(r',\s*]', ']', raw)
                    raw = re.sub(r'\bundefined\b', 'null', raw)
                    raw = re.sub(r'\bNaN\b', 'null', raw)
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        app.logger.error(f"YouTube JSON parse failed, raw[:200]: {raw[:200]}")
                        raise

            def fetch_page(query):
                r = self.session.get('https://www.youtube.com/results', params={'search_query': query}, headers={**self._get_headers(), 'Accept-Language': 'en-US,en;q=0.5'}, timeout=15)
                if r and r.status_code == 200:
                    raw = extract_json(r.text)
                    if raw:
                        return raw
                r2 = self.session.get(f'https://www.youtube.com/results?search_query={query}', headers={**self._get_headers(), 'Accept-Language': 'en-US,en;q=0.5'}, timeout=15)
                if r2 and r2.status_code == 200:
                    raw = extract_json(r2.text)
                    if raw:
                        return raw
                return None

            for attempt in range(2):
                try:
                    raw = fetch_page(query)
                    if not raw:
                        continue
                    data = raw_to_json(raw)
                    c = data
                    for key in ['contents', 'twoColumnSearchResultsRenderer', 'primaryContents', 'sectionListRenderer', 'contents']:
                        c = c.get(key, {}) if isinstance(c, dict) else {}
                    for section in c if isinstance(c, list) else []:
                        items = (section.get('itemSectionRenderer', {}) if isinstance(section, dict) else {}).get('contents', [])
                        for item in items:
                            vr = item.get('videoRenderer', {}) if isinstance(item, dict) else {}
                            if not vr:
                                continue
                            vid = vr.get('videoId', '')
                            if not vid or vid in seen_ids:
                                continue
                            seen_ids.add(vid)
                            tr = vr.get('title', {}).get('runs', [])
                            title = ''.join(t.get('text', '') for t in tr) if tr else vr.get('title', {}).get('simpleText', '')
                            thumbs = vr.get('thumbnail', {}).get('thumbnails', [])
                            thumb = thumbs[-1]['url'] if thumbs else ''
                            videos.append({
                                'id': vid,
                                'title': title[:120],
                                'url': f'https://www.youtube.com/watch?v={vid}',
                                'thumbnail': thumb,
                                'duration': vr.get('lengthText', {}).get('simpleText', ''),
                                'views': vr.get('viewCountText', {}).get('simpleText', '') or (vr.get('viewCountText', {}).get('runs', [{}])[0].get('text', '') if vr.get('viewCountText', {}).get('runs') else ''),
                                'published': vr.get('publishedTimeText', {}).get('simpleText', ''),
                                'channel': (vr.get('ownerText', {}).get('runs', []) or vr.get('shortBylineText', {}).get('runs', []) or [{}])[0].get('text', ''),
                                'channel_url': '',
                            })
                            ch_id = ((vr.get('ownerText', {}).get('runs', []) or vr.get('shortBylineText', {}).get('runs', []) or [{}])[0].get('navigationEndpoint', {}) or {}).get('browseEndpoint', {}) or {}
                            ch_id = ch_id.get('browseId', '')
                            if ch_id:
                                videos[-1]['channel_url'] = f'https://www.youtube.com/channel/{ch_id}'
                            if len(videos) >= 30:
                                break
                        if len(videos) >= 30:
                            break
                except Exception as e:
                    app.logger.error(f"YouTube search error: {e}")
                if videos:
                    break

        with self.cache_lock:
            self.in_memory_cache[cache_key] = {'data': videos, 'expires': time.time() + 1800}
        return videos

    def get_suggestions(self, query):
        """Get search suggestions with error handling"""
        if not query or len(query) < 2:
            return []

        cache_key = f"suggest_{query}"
        cached_suggestions = self._get_from_cache(cache_key)

        if cached_suggestions:
            return cached_suggestions

        # 1. DuckDuckGo suggest API (fast, <500ms typical)
        try:
            r = self.session.get(
                'https://duckduckgo.com/ac/',
                params={'q': query, 'type': 'list'},
                timeout=1.5
            )
            if r and r.status_code == 200 and r.text.strip():
                data = r.json()
                if isinstance(data, list) and len(data) >= 2:
                    suggestions = data[1]
                    if isinstance(suggestions, list) and suggestions:
                        self._save_to_cache(cache_key, suggestions, expire_time=1800)
                        return suggestions
        except Exception as e:
            app.logger.debug(f"DDG suggest failed: {e}")

        # 2. Google suggest API (fallback)
        try:
            r = self.session.get(
                'https://suggestqueries.google.com/complete/search',
                params={'q': query, 'client': 'firefox', 'hl': 'en'},
                timeout=1.5
            )
            if r and r.status_code == 200 and r.text.strip():
                data = r.json()
                if isinstance(data, list) and len(data) >= 2:
                    suggestions = data[1]
                    if isinstance(suggestions, list):
                        suggestions = [s[0] if isinstance(s, list) else s for s in suggestions]
                        if suggestions:
                            self._save_to_cache(cache_key, suggestions, expire_time=1800)
                            return suggestions
        except Exception as e:
            app.logger.debug(f"Google suggest failed: {e}")

        # 3. Local fallback — generate basic completions so box never stalls
        try:
            local = self._generate_local_suggestions(query)
            if local:
                self._save_to_cache(cache_key, local, expire_time=300)
                return local
        except Exception:
            pass

        return []

    def _generate_local_suggestions(self, query):
        """Fast local suggestion generator when APIs are unavailable"""
        q = query.lower().strip()
        starters = {
            'how': ['how to', 'how does', 'how do', 'how can', 'how is'],
            'what': ['what is', 'what are', 'what does', 'what was', 'what if'],
            'why': ['why is', 'why does', 'why do', 'why are', 'why was'],
            'when': ['when is', 'when does', 'when will', 'when did', 'when was'],
            'where': ['where is', 'where can', 'where does', 'where are', 'where to'],
            'who': ['who is', 'who are', 'who was', 'who invented', 'who created'],
            'which': ['which is', 'which are', 'which one', 'which way', 'which side'],
            'best': ['best', 'best way', 'best place', 'best time', 'best website'],
            'top': ['top 10', 'top 5', 'top rated', 'top', 'top websites'],
            'can': ['can you', 'can i', 'can we', 'can someone', 'can python'],
            'is': ['is there', 'is it', 'is this', 'is that', 'is python'],
            'does': ['does anyone', 'does python', 'does this', 'does it', 'does windows'],
        }
        results = []
        first_word = q.split()[0] if q.split() else q
        for starter, completions in starters.items():
            if first_word.startswith(starter):
                for c in completions:
                    if q.startswith(c):
                        results.append(query)
                    else:
                        results.append(c)
                break
        if query not in results:
            results.insert(0, query)
        return results[:5]

KNOWLEDGE_PANELS = {
    'python': {
        'title': 'Python (programming language)',
        'image': 'https://www.python.org/static/community_logos/python-logo-master-v3-TM.png',
        'type': 'Programming language',
        'description': 'Python is a high-level, general-purpose programming language. Its design philosophy emphasizes code readability with the use of significant indentation. Python is dynamically typed and garbage-collected.',
        'facts': [
            ('Designed by', 'Guido van Rossum'),
            ('First appeared', '1991'),
            ('Typing discipline', 'Duck, dynamic, strong'),
            ('OS', 'Windows, macOS, Linux, Unix'),
            ('License', 'Python Software Foundation License'),
            ('Website', 'python.org'),
        ]
    },
    'google': {
        'title': 'Google',
        'image': 'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png',
        'type': 'Technology company',
        'description': 'Google LLC is an American multinational technology company focusing on online advertising, search engine technology, cloud computing, computer software, quantum computing, e-commerce, and artificial intelligence.',
        'facts': [
            ('Founded', 'September 4, 1998'),
            ('Founders', 'Larry Page, Sergey Brin'),
            ('CEO', 'Sundar Pichai'),
            ('Headquarters', 'Mountain View, California'),
            ('Parent', 'Alphabet Inc.'),
            ('Employees', '190,000+ (2024)'),
        ]
    },
    'flask': {
        'title': 'Flask (web framework)',
        'image': 'https://flask.palletsprojects.com/en/stable/_images/flask-horizontal.png',
        'type': 'Web framework',
        'description': 'Flask is a micro web framework written in Python. It is classified as a microframework because it does not require particular tools or libraries. It has no database abstraction layer, form validation, or any other components.',
        'facts': [
            ('Developer', 'Pallets project'),
            ('First appeared', '2010'),
            ('Written in', 'Python'),
            ('License', 'BSD'),
            ('Website', 'flask.palletsprojects.com'),
            ('Repository', 'github.com/pallets/flask'),
        ]
    },
    'linux': {
        'title': 'Linux',
        'image': 'https://upload.wikimedia.org/wikipedia/commons/a/af/Tux.png',
        'type': 'Operating system',
        'description': 'Linux is a family of open-source Unix-like operating systems based on the Linux kernel, an operating system kernel first released on September 17, 1991, by Linus Torvalds.',
        'facts': [
            ('Developer', 'Community / Linus Torvalds'),
            ('Written in', 'C, Assembly'),
            ('OS family', 'Unix-like'),
            ('First release', '1991'),
            ('Kernel type', 'Monolithic'),
            ('License', 'GPLv2'),
        ]
    },
    'docker': {
        'title': 'Docker',
        'type': 'Software platform',
        'description': 'Docker is a set of platform-as-a-service products that use OS-level virtualization to deliver software in packages called containers. Containers are isolated from one another and bundle their own software, libraries, and configuration files.',
        'facts': [
            ('Developer', 'Docker, Inc.'),
            ('First released', '2013'),
            ('Written in', 'Go'),
            ('Platform', 'Linux, Windows, macOS'),
            ('Type', 'Containerization'),
            ('Website', 'docker.com'),
        ]
    },
    'react': {
        'title': 'React (JavaScript library)',
        'type': 'JavaScript library',
        'description': 'React is a free and open-source front-end JavaScript library for building user interfaces based on components. It is maintained by Meta and a community of individual developers and companies.',
        'facts': [
            ('Developer', 'Meta (Facebook)'),
            ('First released', '2013'),
            ('Written in', 'JavaScript, TypeScript'),
            ('License', 'MIT License'),
            ('Type', 'Frontend library'),
            ('Website', 'react.dev'),
        ]
    },
    'vim': {
        'title': 'Vim (text editor)',
        'type': 'Text editor',
        'description': 'Vim is a highly configurable text editor built to enable efficient text editing. It is an improved version of the vi editor distributed with most UNIX systems. Vim is known for its modal editing paradigm.',
        'facts': [
            ('Developer', 'Bram Moolenaar'),
            ('First released', '1991'),
            ('Written in', 'C, Vim script'),
            ('License', 'Vim (GPL-compatible)'),
            ('Type', 'Text editor'),
            ('Website', 'vim.org'),
        ]
    },
    'nginx': {
        'title': 'Nginx',
        'type': 'Web server',
        'description': 'Nginx is a web server that can also be used as a reverse proxy, load balancer, mail proxy, and HTTP cache. It is free and open-source software released under the terms of the BSD license.',
        'facts': [
            ('Developer', 'Igor Sysoev'),
            ('First released', '2004'),
            ('Written in', 'C'),
            ('License', 'BSD'),
            ('Type', 'Web server, reverse proxy'),
            ('Website', 'nginx.org'),
        ]
    },
}

WIKI_CACHE = {}
WIKI_CACHE_LOCK = threading.Lock()
WIKI_CACHE_TTL = 86400

WEATHER_CACHE = {}
WEATHER_CACHE_LOCK = threading.Lock()
WEATHER_CACHE_TTL = 1800

DEF_CACHE = {}
DEF_CACHE_LOCK = threading.Lock()
DEF_CACHE_TTL = 86400

MEDIA_CACHE = {}
MEDIA_CACHE_LOCK = threading.Lock()
MEDIA_CACHE_TTL = 86400
TMDB_IMG = 'https://image.tmdb.org/t/p'

WMO_CODES = {
    0: 'Clear sky', 1: 'Mainly clear', 2: 'Partly cloudy', 3: 'Overcast',
    45: 'Foggy', 48: 'Depositing rime fog',
    51: 'Light drizzle', 53: 'Moderate drizzle', 55: 'Dense drizzle',
    56: 'Light freezing drizzle', 57: 'Dense freezing drizzle',
    61: 'Slight rain', 63: 'Moderate rain', 65: 'Heavy rain',
    66: 'Light freezing rain', 67: 'Heavy freezing rain',
    71: 'Slight snow', 73: 'Moderate snow', 75: 'Heavy snow',
    77: 'Snow grains',
    80: 'Slight rain showers', 81: 'Moderate rain showers', 82: 'Violent rain showers',
    85: 'Slight snow showers', 86: 'Heavy snow showers',
    95: 'Thunderstorm', 96: 'Thunderstorm with slight hail', 99: 'Thunderstorm with heavy hail',
}

def get_weather_panel(query):
    q = query.lower().strip()
    weather_kw = ['weather', 'temperature', 'forecast', 'temp']
    if not any(kw in q for kw in weather_kw):
        return None

    location = None
    for prefix in ['weather in ', 'temperature in ', 'forecast in ', 'temp in ']:
        if prefix in q:
            location = q.split(prefix, 1)[1].strip()
            break
    if not location:
        for suffix in [' weather', ' temperature', ' forecast', ' temp']:
            if q.endswith(suffix):
                location = q[:-len(suffix)].strip()
                break
    if not location:
        for pattern in [r'^(?:what(?:\'s| is) the )?(weather|temperature|temp|forecast)(?:\s+(?:in|at|for)\s+(.+))?$',
                        r'^(.+?)\s+(?:weather|temperature|forecast)$',
                        r'^(?:how\s+is\s+the\s+)?(?:weather|temperature|forecast)\s+(?:in|at|for)\s+(.+)$',
                        r'^(?:weather|temperature|forecast|temp)\s+(.+)$']:
            import re
            m = re.search(pattern, q)
            if m:
                groups = [g for g in m.groups() if g is not None]
                loc = groups[-1] if groups else None
                if isinstance(loc, str) and loc and loc not in ('weather', 'temperature', 'temp', 'forecast'):
                    location = loc
                    break

    if not location:
        try:
            ip_r = requests.get('https://ip-api.com/json/', headers={'User-Agent': 'arlong-search/1.0'}, timeout=4)
            if ip_r.status_code == 200:
                ip_data = ip_r.json()
                if ip_data.get('status') == 'success':
                    loc_str = ', '.join(filter(None, [ip_data.get('city', ''), ip_data.get('countryCode', '')]))
                    if loc_str:
                        location = loc_str
        except:
            pass

    if not location:
        return None

    cache_key = f'weather:{location.lower()}'
    with WEATHER_CACHE_LOCK:
        cached = WEATHER_CACHE.get(cache_key)
        if cached and time.time() < cached['expires']:
            return cached['data']

    try:
        from urllib.parse import quote_plus
        import re
        geo_r = requests.get(
            f'https://geocoding-api.open-meteo.com/v1/search?name={quote_plus(location)}&count=1&language=en&format=json',
            timeout=5)
        if geo_r.status_code != 200:
            return None
        geo_data = geo_r.json()
        results = geo_data.get('results')
        if not results:
            return None
        lat = results[0]['latitude']
        lon = results[0]['longitude']
        loc_name = results[0].get('name', location)
        country = results[0].get('country', '')
        tz = results[0].get('timezone', 'auto')

        wx_r = requests.get(
            f'https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}'
            f'&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m'
            f'&daily=temperature_2m_max,temperature_2m_min&timezone={tz}&forecast_days=1',
            timeout=5)
        if wx_r.status_code != 200:
            return None
        wx = wx_r.json()
        current = wx.get('current', {})
        daily = wx.get('daily', {})

        temp = current.get('temperature_2m')
        feels_like = current.get('apparent_temperature')
        humidity = current.get('relative_humidity_2m')
        wind_speed = current.get('wind_speed_10m')
        wmo_code = current.get('weather_code', 0)
        high = daily.get('temperature_2m_max', [None])[0] if daily.get('temperature_2m_max') else None
        low = daily.get('temperature_2m_min', [None])[0] if daily.get('temperature_2m_min') else None

        condition = WMO_CODES.get(wmo_code, 'Unknown')

        wx_icon = 'clear' if wmo_code == 0 else \
                  'cloudy' if wmo_code in (1, 2, 3, 45, 48) else \
                  'rainy' if wmo_code in (51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82) else \
                  'snowy' if wmo_code in (71, 73, 75, 77, 85, 86) else \
                  'stormy'

        display_loc = loc_name
        if country:
            display_loc = f'{loc_name}, {country}'

        facts = []
        if feels_like is not None:
            facts.append(('Feels like', f'{feels_like:.0f}°C'))
        if humidity is not None:
            facts.append(('Humidity', f'{humidity}%'))
        if wind_speed is not None:
            facts.append(('Wind', f'{wind_speed:.0f} km/h'))
        if high is not None and low is not None:
            facts.append(('High / Low', f'{high:.0f}°C / {low:.0f}°C'))

        panel = {
            'panel_type': 'weather',
            'title': display_loc,
            'type': 'Weather',
            'image': wx_icon,
            'description': '',
            'temp': f'{temp:.0f}°C' if temp is not None else '',
            'condition': condition,
            'facts': facts,
        }

        with WEATHER_CACHE_LOCK:
            WEATHER_CACHE[cache_key] = {'data': panel, 'expires': time.time() + WEATHER_CACHE_TTL}
        return panel
    except Exception:
        return None


def get_definition_panel(query):
    q = query.lower().strip()
    if not q or len(q) < 2:
        return None

    word = None
    patterns = [
        r'^define\s+(.+?)$',
        r'^(.+?)\s+definition$',
        r'^what\s+(?:does|is)\s+(.+?)\s+mean',
        r'^meaning\s+of\s+(.+?)$',
        r'^what\s+is\s+the\s+(?:definition|meaning)\s+of\s+(.+?)$',
    ]
    import re
    for pat in patterns:
        m = re.search(pat, q)
        if m:
            word = m.group(1).strip()
            break

    if not word or not word.replace(' ', '').isalpha():
        return None

    cache_key = f'def:{word.lower()}'
    with DEF_CACHE_LOCK:
        cached = DEF_CACHE.get(cache_key)
        if cached and time.time() < cached['expires']:
            return cached['data']

    try:
        from urllib.parse import quote_plus
        r = requests.get(f'https://api.dictionaryapi.dev/api/v2/entries/en/{quote_plus(word)}', timeout=6)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data or not isinstance(data, list):
            return None
        entry = data[0]
        entry_word = entry.get('word', word)
        phonetic = entry.get('phonetic', '')
        meanings = entry.get('meanings', [])
        if not meanings:
            return None

        first = meanings[0]
        part_of_speech = first.get('partOfSpeech', '')
        defs = first.get('definitions', [])
        if not defs:
            return None
        definition_text = defs[0].get('definition', '')
        example = defs[0].get('example', '')
        synonyms = defs[0].get('synonyms', [])[:3]

        panel = {
            'panel_type': 'definition',
            'title': entry_word,
            'type': part_of_speech,
            'image': None,
            'description': definition_text,
            'phonetic': phonetic,
            'example': example,
            'synonyms': synonyms,
            'facts': [
                ('Source', 'Dictionary'),
            ],
        }

        with DEF_CACHE_LOCK:
            DEF_CACHE[cache_key] = {'data': panel, 'expires': time.time() + DEF_CACHE_TTL}
        return panel
    except Exception:
        return None


STOP_SNIPPET_WORDS = frozenset({
    'the', 'and', 'for', 'with', 'from', 'that', 'this', 'what', 'when', 'where', 'who',
    'how', 'are', 'was', 'were', 'has', 'have', 'had', 'about', 'into', 'your', 'their',
})

AI_FACTUAL_QUERY_KEYWORDS = (
    'education', 'born', 'birth', 'age', 'who is', 'who was', 'what is', 'when did',
    'founder', 'co-founder', 'ceo', 'net worth', 'married', 'nationality', 'degree',
    'email', 'phone', 'address', 'contact', 'number', 'website', 'salary', 'price',
    'how much', 'how many', 'population', 'area', 'distance', 'height', 'weight',
)


def clean_snippet_text(text):
    """Normalize engine snippets for display."""
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', ' ', str(text))
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'\s+([.,!?;:])', r'\1', text)
    text = re.sub(r'(\w)\1{3,}', r'\1\1', text)
    return text[:500]


def _wiki_page_title_from_url(url):
    if not url:
        return None
    m = re.search(r'wikipedia\.org/wiki/([^#?]+)', url, re.I)
    if not m:
        return None
    return unquote(m.group(1).replace('_', ' ')).strip()


def _query_focused_excerpt(text, query, max_len=280):
    text = clean_snippet_text(text)
    if not text:
        return ''
    if len(text) <= max_len:
        return text
    terms = [t.lower() for t in query.split() if len(t) > 2 and t.lower() not in STOP_SNIPPET_WORDS]
    if not terms:
        return text[: max_len - 3].rstrip() + '...'
    lower = text.lower()
    best_pos = 0
    best_score = -1
    step = max(1, len(text) // 40)
    for i in range(0, len(text) - 40, step):
        window = lower[i : i + 140]
        score = sum(1 for t in terms if t in window)
        if score > best_score:
            best_score = score
            best_pos = i
    excerpt = text[best_pos : best_pos + max_len].strip()
    if best_pos > 0:
        excerpt = '...' + excerpt
    if best_pos + max_len < len(text):
        excerpt = excerpt.rstrip() + '...'
    return excerpt


def highlight_snippet(snippet, query):
    text = clean_snippet_text(snippet)
    if not text:
        return ''
    from html import escape as _html_escape
    escaped = _html_escape(text)
    terms = []
    seen = set()
    for raw in query.lower().split():
        term = raw.strip('.,?!\'"')
        if len(term) <= 2 or term in STOP_SNIPPET_WORDS or term in seen:
            continue
        seen.add(term)
        terms.append(term)
    for term in sorted(terms, key=len, reverse=True):
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        escaped = pattern.sub(lambda m: f'<b class="rc-hl">{m.group(0)}</b>', escaped)
    return escaped


def polish_ai_summary_text(text):
    if not text:
        return text
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'\s+([.,!?;:])', r'\1', text)
    text = re.sub(r'\s+\)', ')', text)
    text = re.sub(r'\[\s*(\d+)\s*\]\s*\(\s*([^)]+?)\s*\)', r'[\1](\2)', text)
    text = re.sub(r'^(According to .+?,\s*)', '', text)
    text = re.sub(r'^(Based on .+?,\s*)', '', text)
    text = re.sub(r'^(In summary,?\s*)', '', text)
    text = re.sub(r'^(To summarize,?\s*)', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def polish_result_snippets(results, query):
    """Clean snippets, enrich Wikipedia rows, add query-aware highlights."""
    if not results:
        return results
    wiki_enriched = 0
    for r in results:
        url = (r.get('url') or '').lower()
        snippet = clean_snippet_text(r.get('snippet') or '')
        if wiki_enriched < 2 and 'wikipedia.org/wiki/' in url:
            page_title = _wiki_page_title_from_url(r.get('url'))
            if page_title:
                panel = get_wikipedia_panel(page_title)
                if panel and panel.get('description'):
                    snippet = _query_focused_excerpt(panel['description'], query)
                    wiki_enriched += 1
        r['snippet'] = snippet
        r['snippet_html'] = highlight_snippet(snippet, query)
    return results


def get_wikipedia_panel(query):
    query_lower = query.lower().strip()
    if not query_lower or len(query_lower) < 3:
        return None
    cache_key = f"wiki_panel:{query_lower}"
    with WIKI_CACHE_LOCK:
        cached = WIKI_CACHE.get(cache_key)
        if cached and time.time() < cached['expires']:
            return cached['data']
    try:
        params = {
            'action': 'query',
            'format': 'json',
            'titles': query_lower,
            'prop': 'extracts|pageimages|info|categories',
            'exintro': 1,
            'explaintext': 1,
            'pithumbsize': 300,
            'cllimit': 3,
            'inprop': 'url',
            'redirects': 1,
        }
        headers = {'User-Agent': 'arlong-search/1.0 (https://aoogle-production.up.railway.app; search@arlong.app)'}
        r = requests.get('https://en.wikipedia.org/w/api.php', params=params, headers=headers, timeout=5)
        if r.status_code != 200:
            return None
        data = r.json()
        pages = data.get('query', {}).get('pages', {})
        if not pages:
            return None
        page = next(iter(pages.values()))
        if 'missing' in page or not page.get('extract'):
            return None
        title = page.get('title', query)
        extract = clean_snippet_text(page.get('extract', ''))[:500]
        thumb_url = None
        thumb = page.get('thumbnail')
        if thumb:
            thumb_url = thumb.get('source')
        page_url = page.get('fullurl', f'https://en.wikipedia.org/wiki/{title.replace(" ", "_")}')
        cats = page.get('categories', [])
        cat_names = [c.get('title', '').replace('Category:', '') for c in cats[:3] if c.get('title')]
        facts = [('Source', 'Wikipedia'), ('Read more', page_url)]
        if cat_names:
            facts.insert(0, ('Type', ' · '.join(cat_names)))
        panel = {
            'title': title,
            'image': thumb_url,
            'type': 'Wikipedia article',
            'description': extract,
            'facts': facts,
        }
        with WIKI_CACHE_LOCK:
            WIKI_CACHE[cache_key] = {'data': panel, 'expires': time.time() + WIKI_CACHE_TTL}
        return panel
    except Exception:
        return None


def get_wiki_panel_from_results(results):
    if not results:
        return None
    wiki_url = None
    wiki_title = None
    for r in results[:5]:
        domain = (r.get('domain') or '').lower()
        url = (r.get('url') or '').lower()
        if 'wikipedia.org' in domain or 'wikipedia.org' in url:
            wiki_url = r.get('url')
            wiki_title = r.get('title')
            break
    if not wiki_url or not wiki_title:
        return None
    page_title = wiki_title.replace(' - Wikipedia', '').replace(' – Wikipedia', '').strip()
    panel = get_wikipedia_panel(page_title)
    if not panel:
        return None
    desc = panel.get('description', '') or ''
    if len(desc.strip()) < 20 and not panel.get('image'):
        return None
    return panel


def get_media_panel(query):
    api_key = os.environ.get('TMDB_API_KEY')
    if not api_key:
        return None
    q = query.lower().strip()
    cache_key = f"media:{q}"
    with MEDIA_CACHE_LOCK:
        cached = MEDIA_CACHE.get(cache_key)
        if cached and time.time() < cached['expires']:
            return cached['data']
    search_q = re.sub(r'\b(cast|movie|film|tv|show|series|television|watch|stream|trailer|season|episode|director|where to)\b', '', q).strip()
    if not search_q:
        search_q = q
    search_q = re.sub(r'\s+', ' ', search_q).strip()
    headers = {'User-Agent': 'arlong-search/1.0 (https://aoogle-production.up.railway.app; search@arlong.app)'}
    try:
        # Try both movie and TV, pick best result
        best_result = None
        best_type = None
        best_score = 0
        for attempt_type in ['movie', 'tv']:
            try:
                r = requests.get(
                    f'https://api.themoviedb.org/3/search/{attempt_type}',
                    params={'api_key': api_key, 'query': search_q, 'language': 'en-US', 'page': 1},
                    headers=headers, timeout=5
                )
                if r.status_code != 200:
                    continue
                data = r.json()
                results_list = data.get('results', [])
                if results_list:
                    cand = results_list[0]
                    score = (cand.get('vote_count', 0) or 0) + ((cand.get('popularity', 0) or 0) * 10)
                    if score > best_score:
                        best_score = score
                        best_result = cand
                        best_type = attempt_type
            except Exception:
                continue
        if not best_result:
            return None
        vote_cnt_check = best_result.get('vote_count', 0) or 0
        popularity = best_result.get('popularity', 0) or 0
        if vote_cnt_check < 20 and popularity < 5:
            return None
        result = best_result
        media_type = best_type
        tmdb_id = result['id']
        # Fetch details with credits, watch providers, and images
        detail_r = requests.get(
            f'https://api.themoviedb.org/3/{media_type}/{tmdb_id}',
            params={
                'api_key': api_key,
                'language': 'en-US',
                'append_to_response': 'credits,watch/providers,images'
            },
            headers=headers, timeout=5
        )
        if detail_r.status_code != 200:
            return None
        details = detail_r.json()
        title = details.get('title') or details.get('name') or result.get('title') or result.get('name', '')
        year = ''
        if media_type == 'movie':
            rd = details.get('release_date') or result.get('release_date', '')
            if rd:
                year = rd[:4]
        else:
            fd = details.get('first_air_date') or result.get('first_air_date', '')
            if fd:
                year = fd[:4]
        overview = details.get('overview') or result.get('overview', '') or ''
        overview = overview[:400]
        vote_avg = details.get('vote_average') or result.get('vote_average', 0)
        vote_cnt = details.get('vote_count') or result.get('vote_count', 0)
        poster = details.get('poster_path') or result.get('poster_path', '')
        poster_url = f'{TMDB_IMG}/w500{poster}' if poster else None
        type_label = 'Movie' if media_type == 'movie' else 'TV Series'
        if year:
            type_label += f' ({year})'
        # Cast
        cast_list = []
        credits = details.get('credits', {})
        for person in (credits.get('cast', []) or [])[:8]:
            name = person.get('name', '')
            character = person.get('character', '')
            profile = person.get('profile_path', '')
            photo = f'{TMDB_IMG}/w185{profile}' if profile else None
            cast_list.append({'name': name, 'character': character, 'photo': photo})
        # Watch providers (flatrate only)
        watch_list = []
        providers_data = details.get('watch/providers', {})
        results_providers = providers_data.get('results', {})
        us_providers = results_providers.get('US', {})
        for p in (us_providers.get('flatrate', []) or []):
            logo = p.get('logo_path', '')
            watch_list.append({
                'name': p.get('provider_name', ''),
                'logo': f'{TMDB_IMG}/original{logo}' if logo else None
            })
        # Gallery (backdrops)
        gallery = []
        images_data = details.get('images', {})
        for bp in (images_data.get('backdrops', []) or [])[:4]:
            fp = bp.get('file_path', '')
            if fp:
                gallery.append(f'{TMDB_IMG}/w780{fp}')
        # Ratings display
        rating_str = ''
        if vote_avg and vote_avg > 0:
            rating_str = f'{vote_avg:.1f}/10'
        vote_str = ''
        if vote_cnt and vote_cnt > 0:
            if vote_cnt >= 1000:
                vote_str = f'{vote_cnt/1000:.1f}K votes'
            else:
                vote_str = f'{vote_cnt} votes'
        # Facts
        facts = []
        genres = details.get('genres', []) or []
        if genres:
            facts.append(('Genres', ', '.join(g['name'] for g in genres[:3])))
        if media_type == 'movie':
            runtime = details.get('runtime')
            if runtime:
                h, m = divmod(runtime, 60)
                facts.append(('Runtime', f'{h}h {m}m' if h else f'{m}m'))
            status = details.get('status', '')
            if status:
                facts.append(('Status', status))
        else:
            seasons = details.get('number_of_seasons', 0)
            episodes = details.get('number_of_episodes', 0)
            if seasons:
                facts.append(('Seasons', str(seasons)))
            if episodes:
                facts.append(('Episodes', str(episodes)))
            status = details.get('status', '')
            if status:
                facts.append(('Status', status))
        panel = {
            'panel_type': 'media',
            'media_type': media_type,
            'title': title,
            'year': year,
            'image': poster_url,
            'type': type_label,
            'description': overview,
            'rating': rating_str,
            'vote_count': vote_str,
            'cast': cast_list,
            'watch_providers': watch_list,
            'gallery': gallery,
            'facts': facts,
        }
        with MEDIA_CACHE_LOCK:
            MEDIA_CACHE[cache_key] = {'data': panel, 'expires': time.time() + MEDIA_CACHE_TTL}
        return panel
    except Exception:
        return None


def get_info_box(query, results=None):
    query_lower = query.lower().strip()
    for key, panel in KNOWLEDGE_PANELS.items():
        if key in query_lower:
            return panel

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _try_weather():
        return get_weather_panel(query)
    def _try_definition():
        return get_definition_panel(query)
    def _try_wiki_results():
        return get_wiki_panel_from_results(results) if results else None
    def _try_media():
        return get_media_panel(query)
    def _try_wiki():
        return get_wikipedia_panel(query)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(_try_weather): 'weather',
            pool.submit(_try_definition): 'definition',
            pool.submit(_try_wiki_results): 'wiki_results',
            pool.submit(_try_media): 'media',
            pool.submit(_try_wiki): 'wiki',
        }
        for future in as_completed(futures, timeout=3):
            try:
                result = future.result(timeout=0)
                if result:
                    return result
            except Exception:
                pass
    return None

NEWS_TOPIC_KEYWORDS = ['latest','breaking','update','today','this week','this month','report','announced','unveiled','released','launched','happening','what happened','recap','highlights','analysis','coverage','live','watch']

def detect_news(query):
    q = query.lower().strip()
    if q.startswith('news ') or q.startswith('latest '):
        return {'topic': q.split(' ', 1)[1].strip(), 'intent': 'news'}
    return None

_amazon_session = None
_amazon_lock = threading.Lock()
_amazon_cache = {}
_amazon_cache_ttl = 600

def _get_amazon_session():
    global _amazon_session
    if _amazon_session is None:
        with _amazon_lock:
            if _amazon_session is None:
                s = requests.Session()
                s.headers.update({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                })
                _amazon_session = s
    return _amazon_session

def _amazon_affiliate_url(url):
    if not AMAZON_ASSOCIATE_TAG:
        return url
    if 'amazon.com' not in url and 'amazon.' not in url:
        return url
    separator = '&' if '?' in url else '?'
    return f"{url}{separator}tag={AMAZON_ASSOCIATE_TAG}"

def fetch_amazon_products(query, max_products=12):
    cache_key = query.lower().strip()
    cached = _amazon_cache.get(cache_key)
    if cached and (time.time() - cached['ts']) < _amazon_cache_ttl:
        return cached['data']
    try:
        session = _get_amazon_session()
        ua = UserAgent(fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        session.headers.update({'User-Agent': ua.random})
        url = f'https://www.amazon.com/s?k={quote_plus(cache_key)}'
        resp = session.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        soup = BeautifulSoup(resp.text, 'html.parser')
        products = []
        seen_asins = set()
        for div in soup.select('[data-component-type="s-search-result"]'):
            if len(products) >= max_products:
                break
            asin = div.get('data-asin', '')
            if not asin or asin in seen_asins:
                continue
            title_el = div.select_one('h2 a.a-link-normal span') or div.select_one('h2 span')
            if not title_el:
                title_el = div.select_one('h2 a')
            if not title_el:
                continue
            title = title_el.get_text(strip=True)
            link_el = div.select_one('h2 a.a-link-normal') or div.select_one('h2 a')
            if not link_el:
                continue
            href = link_el.get('href', '')
            if not href:
                continue
            product_url = 'https://www.amazon.com' + href if href.startswith('/') else href
            product_url = _amazon_affiliate_url(product_url)
            img_el = div.select_one('img.s-image')
            img = img_el.get('src', '') if img_el else ''
            price_el = div.select_one('.a-price .a-offscreen') or div.select_one('.a-price-whole')
            price = ''
            if price_el:
                raw = price_el.get_text(strip=True)
                if raw:
                    price = '$' + raw if not raw.startswith('$') else raw
            if not price:
                price_span = div.select_one('.a-price')
                if price_span:
                    whole = price_span.select_one('.a-price-whole')
                    fraction = price_span.select_one('.a-price-fraction')
                    if whole:
                        w = whole.get_text(strip=True)
                        f = fraction.get_text(strip=True) if fraction else '00'
                        price = f'${w}.{f}'
            rating_el = div.select_one('.a-star-small .a-icon-alt') or div.select_one('i.a-icon-star') or div.select_one('.a-icon-star')
            rating = ''
            if rating_el:
                rt = rating_el.get_text(strip=True)
                if rt:
                    m = re.search(r'[\d.]+', rt)
                    if m:
                        rating = m.group()
            seen_asins.add(asin)
            products.append({
                'title': title,
                'url': product_url,
                'price': price or None,
                'image': img or None,
                'source': 'Amazon',
                'domain': 'amazon.com',
                'rating': rating or None,
                'asin': asin,
            })
        result = products if products else None
        _amazon_cache[cache_key] = {'data': result, 'ts': time.time()}
        return result
    except Exception as e:
        app.logger.warning(f"Amazon scraping error: {e}")
        return None

def get_shopping_panel(query, results):
    q_lower = query.lower().strip()
    shopping_kw = ['buy', 'price', 'deal', 'discount', 'cheap', 'shop', 'purchase',
                   'order', 'cost', 'under', 'sale', 'coupon', 'offer', 'affordable',
                   'best', 'top', 'review', 'cheap', 'budget', 'for', 'vs', 'pro',
                   'new', '2025', '2026', 'amazon', 'walmart', 'ebay', 'near me']
    is_shopping = any(kw in q_lower for kw in shopping_kw)

    # Try Amazon first for shopping queries
    if is_shopping or (results and sum(1 for r in results if r.get('category') == 'shopping') >= 2):
        amazon_products = fetch_amazon_products(query)
        if amazon_products:
            return {'panel_type': 'shopping', 'products': amazon_products}

    if not results:
        return None

    products = []
    seen = set()

    def add_product(r):
        if r['url'] in seen:
            return
        seen.add(r['url'])
        title = r.get('title', '') or ''
        domain = (r.get('domain') or urlparse(r['url']).netloc).lower()
        snippet = r.get('snippet', '') or ''
        price = _extract_price(snippet) or _extract_price(title)
        products.append({
            'title': title,
            'url': r['url'],
            'price': price,
            'image': None,
            'source': _short_source(domain),
            'domain': domain,
            'rating': None,
            'asin': None,
        })

    for r in results:
        domain = (r.get('domain') or urlparse(r['url']).netloc).lower()
        if 'amazon' in domain or 'walmart' in domain or 'ebay' in domain:
            add_product(r)

    commerce_domains = ['bestbuy', 'target', 'etsy', 'newegg', 'homedepot',
                        'lowes', 'costco', 'shopify', 'alibaba', 'aliexpress',
                        'bhphotovideo', 'microcenter', 'macys', 'kohls', 'nike',
                        'adidas', 'gap', 'zara', 'harborfreight', 'acehardware']
    for r in results:
        domain = (r.get('domain') or urlparse(r['url']).netloc).lower()
        if any(d in domain for d in commerce_domains):
            add_product(r)

    for r in results:
        if r.get('category') == 'shopping':
            add_product(r)

    for r in results:
        snippet = r.get('snippet', '') or ''
        title = r.get('title', '') or ''
        if _extract_price(snippet) or _extract_price(title):
            add_product(r)

    if not products and is_shopping:
        for r in results[:10]:
            add_product(r)

    return {'panel_type': 'shopping', 'products': products[:12]} if products else None

def _short_source(domain):
    domain = domain.replace('www.', '')
    name_map = {
        'amazon': 'Amazon', 'walmart': 'Walmart', 'ebay': 'eBay',
        'bestbuy': 'Best Buy', 'target': 'Target', 'etsy': 'Etsy',
        'newegg': 'Newegg', 'homedepot': 'Home Depot', 'lowes': 'Lowe\'s',
        'costco': 'Costco',
    }
    for k, v in name_map.items():
        if k in domain:
            return v
    parts = domain.split('.')
    return parts[0].title() if parts else domain

def _extract_price(text):
    m = re.search(r'\$\s*\d+(?:,\d{3})*(?:\.\d{2})?', text)
    if m:
        return m.group()
    m = re.search(r'(?:USD|US\$)\s*\d+(?:,\d{3})*(?:\.\d{2})?', text, re.I)
    if m:
        return m.group()
    m = re.search(r'(?:price|from|only|just)\s*[:]?\s*\$?\s*\d+(?:\.\d{2})?', text, re.I)
    if m:
        return m.group()
    return None

class RateLimiter:
    def __init__(self, limit=25, window=3600):
        self.limit = limit
        self.window = window
        self._store = {}
        self._lock = threading.Lock()

    def _cleanup(self, now):
        cutoff = now - self.window
        for ip in list(self._store.keys()):
            self._store[ip] = [t for t in self._store[ip] if t > cutoff]
            if not self._store[ip]:
                del self._store[ip]

    def check(self, ip):
        now = time.time()
        with self._lock:
            self._cleanup(now)
            hits = self._store.get(ip, [])
            if len(hits) >= self.limit:
                oldest = now - hits[0]
                return {"allowed": False, "remaining": 0, "retry_after": int(self.window - oldest)}
            hits.append(now)
            self._store[ip] = hits
            return {"allowed": True, "remaining": self.limit - len(hits), "retry_after": 0}

api_limiter = RateLimiter(limit=125, window=3600)

class SearchStats:
    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def record(self):
        now = time.time()
        bucket = int(now // 3600)
        minute_bucket = int(now // 60)
        with self._lock:
            self._buckets[bucket] = self._buckets.get(bucket, 0) + 1
            self._buckets[minute_bucket * -1] = self._buckets.get(minute_bucket * -1, 0) + 1
            cutoff = bucket - 168
            for k in list(self._buckets.keys()):
                if isinstance(k, int) and k > 0 and k < cutoff:
                    del self._buckets[k]

    def get_hourly(self, hours=48):
        now = time.time()
        now_bucket = int(now // 3600)
        result = []
        with self._lock:
            for offset in range(hours, -1, -1):
                bucket = now_bucket - offset
                result.append({
                    "hour": datetime.fromtimestamp(bucket * 3600).strftime('%Y-%m-%d %H:00'),
                    "count": self._buckets.get(bucket, 0)
                })
        return result

    def get_recent_per_minute(self, minutes=30):
        now = time.time()
        now_bucket = int(now // 60)
        result = []
        with self._lock:
            for offset in range(minutes, -1, -1):
                bucket = now_bucket - offset
                result.append({
                    "minute": datetime.fromtimestamp(bucket * 60).strftime('%H:%M'),
                    "count": self._buckets.get(bucket * -1, 0)
                })
        return result

search_stats = SearchStats()

# Initialize search engine
search_engine = ImprovedSearch()

# ── Places helpers (Serper.dev) ──

def _clean_places_query(q):
    """Strip 'near me'-style phrases and tidy whitespace/punctuation."""
    if not q:
        return ''
    q = _NEAR_ME_RE.sub(' ', q)
    return re.sub(r'\s+', ' ', q).strip(' ,-')

def _find_city_in_query(query):
    """Return the longest known city name appearing anywhere in the query
    (case-insensitive), e.g. 'best malls mumbai' -> 'mumbai'."""
    low = (query or '').lower()
    best = None
    for city in _PLACES_KNOWN_CITIES:
        if city in low and (best is None or len(city) > len(best)):
            best = city
    return best

def extract_places_location(query):
    """Return (clean_query, location_titlecase) when a query mentions a location,
    e.g. 'best escape room near chennai', 'restaurants in new york' or
    'best malls mumbai' (city anywhere)."""
    if not query:
        return None, None
    for m in _PLACES_LOCATION_RE.finditer(query):
        raw = m.group(1).strip()
        words = re.split(r'[\s\.]+', raw)
        while words and words[-1].lower() in _LOCATION_STOPWORDS:
            words.pop()
        while words and words[0].lower() in _LOCATION_STOPWORDS:
            words.pop(0)
        if not words:
            continue
        loc = ' '.join(words).strip()
        if not loc or loc.lower() in _LOCATION_STOPWORDS or len(loc) < 2:
            continue
        clean = query[:m.start()] + query[m.end():]
        clean = _clean_places_query(clean)
        return (clean or None), _correct_places_location(loc)
    city = _find_city_in_query(query)
    if city:
        clean = re.sub(r'\b' + re.escape(city) + r'\b', ' ', query, flags=re.IGNORECASE)
        clean = _clean_places_query(clean)
        return (clean or None), city.title()
    return None, None

def has_places_intent(query):
    """True for local-business queries (escape rooms, restaurants, hotels, ...)."""
    if not query:
        return False
    q = query.lower().strip()
    if _NEAR_ME_RE.search(q):
        return True
    clean, loc = extract_places_location(query)
    if loc:
        return any(w in q for w in _PLACES_LOCAL_WORDS)
    return any(w in q for w in _PLACES_LOCAL_WORDS)

def _haversine_km(lat1, lon1, lat2, lon2):
    from math import asin, cos, radians, sin, sqrt
    r = 6371.0
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * r * asin(sqrt(a))

def _geocode_location(location):
    """Geocode a location once via Nominatim, cached in data.json."""
    cached = data_manager.get_geo_cache(location)
    if cached:
        return cached
    try:
        resp = requests.get(
            'https://nominatim.openstreetmap.org/search',
            params={'q': location, 'format': 'jsonv2', 'limit': 1, 'accept-language': 'en'},
            headers={'User-Agent': 'aoogle-search/1.0 (local search engine)'},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.warning(f"Places geocode error for {location!r}: {e}")
        return None
    if data and 'lat' in data[0] and 'lon' in data[0]:
        coords = (float(data[0]['lat']), float(data[0]['lon']))
        data_manager.set_geo_cache(location, coords)
        return coords
    return None

def _filter_places_by_distance(places, lat, lng, radius_km=PLACES_RADIUS_KM):
    """Drop places farther than radius_km from the target. Places without
    coordinates are kept only when nothing else survives (fail-open)."""
    kept = []
    missing = []
    for p in places:
        try:
            pl, pn = float(p.get('latitude')), float(p.get('longitude'))
        except (TypeError, ValueError):
            missing.append(p)
            continue
        if _haversine_km(lat, lng, pl, pn) <= radius_km:
            kept.append(p)
    if kept:
        return kept
    return places if missing else []

_GOOGLE_TYPE_LABELS = {
    'shopping_mall': 'Shopping mall', 'restaurant': 'Restaurant', 'cafe': 'Cafe',
    'bakery': 'Bakery', 'hotel': 'Hotel', 'hospital': 'Hospital', 'pharmacy': 'Pharmacy',
    'gas_station': 'Gas station', 'gym': 'Gym', 'spa': 'Spa', 'beauty_salon': 'Beauty salon',
    'barber_shop': 'Barber shop', 'supermarket': 'Supermarket',
    'grocery_or_supermarket': 'Supermarket', 'movie_theater': 'Movie theater',
    'museum': 'Museum', 'park': 'Park', 'zoo': 'Zoo', 'bank': 'Bank', 'atm': 'ATM',
    'school': 'School', 'university': 'University', 'library': 'Library',
    'place_of_worship': 'Place of worship', 'airport': 'Airport',
    'train_station': 'Train station', 'bus_station': 'Bus station',
    'clothing_store': 'Clothing store', 'electronics_store': 'Electronics store',
    'department_store': 'Department store', 'furniture_store': 'Furniture store',
    'home_goods_store': 'Home goods store', 'jewelry_store': 'Jewelry store',
    'shoe_store': 'Shoe store', 'store': 'Store', 'meal_takeaway': 'Takeaway',
    'food': 'Food', 'bar': 'Bar', 'night_club': 'Night club', 'dentist': 'Dentist',
    'doctor': 'Doctor', 'health': 'Health', 'pet_store': 'Pet store',
    'veterinary_care': 'Veterinary care', 'car_repair': 'Car repair',
    'car_dealer': 'Car dealer', 'parking': 'Parking', 'amusement_park': 'Amusement park',
    'bowling_alley': 'Bowling alley', 'casino': 'Casino', 'stadium': 'Stadium',
    'swimming_pool': 'Swimming pool', 'lodging': 'Lodging',
    'travel_agency': 'Travel agency', 'tourist_attraction': 'Tourist attraction',
    'point_of_interest': 'Place of interest', 'establishment': 'Place',
    'neighborhood': 'Area', 'locality': 'Area', 'political': 'Area',
    'premise': 'Place', 'subpremise': 'Place', 'route': 'Road',
    'street_address': 'Address', 'postal_code': 'Postal code',
    'general_contractor': 'Contractor', 'hardware_store': 'Hardware store',
    'laundry': 'Laundry', 'car_wash': 'Car wash', 'florist': 'Florist',
    'book_store': 'Book store', 'convenience_store': 'Convenience store',
    'liquor_store': 'Liquor store', 'plumber': 'Plumber', 'electrician': 'Electrician',
    'moving_company': 'Moving company', 'real_estate_agency': 'Real estate agency',
    'hair_care': 'Hair care', 'lawyer': 'Lawyer', 'accounting': 'Accounting',
    'local_government_office': 'Government office', 'cemetery': 'Cemetery',
    'church': 'Church', 'hindu_temple': 'Temple', 'mosque': 'Mosque',
    'synagogue': 'Synagogue',
}

_PREFERRED_GOOGLE_TYPES = [
    'shopping_mall','restaurant','cafe','bakery','bar','night_club','meal_takeaway',
    'hotel','lodging','hospital','pharmacy','dentist','doctor','gas_station','gym',
    'spa','beauty_salon','barber_shop','movie_theater','museum','zoo','park',
    'amusement_park','stadium','supermarket','grocery_or_supermarket','department_store',
    'clothing_store','electronics_store','furniture_store','home_goods_store',
    'jewelry_store','shoe_store','convenience_store','liquor_store','book_store',
    'hardware_store','florist','pet_store','veterinary_care','bank','atm','car_dealer',
    'car_repair','car_wash','parking','school','university','library','place_of_worship',
    'church','hindu_temple','mosque','synagogue','airport','train_station','bus_station',
    'tourist_attraction','travel_agency','laundry','hair_care','plumber','electrician',
    'lawyer','accounting',
]

def _google_type_label(types):
    ts = set(types or [])
    for t in _PREFERRED_GOOGLE_TYPES:
        if t in ts:
            return _GOOGLE_TYPE_LABELS[t]
    for t in types or []:
        if t in _GOOGLE_TYPE_LABELS:
            return _GOOGLE_TYPE_LABELS[t]
    if types:
        return types[0].replace('_', ' ').title()
    return ''

def _fetch_google_place_details(place_id):
    """One Place Details call (billed) to enrich a place with phone/website/hours/
    photos/reviews. Returns the raw result dict, or {}."""
    if not place_id:
        return {}
    try:
        resp = requests.get(
            'https://maps.googleapis.com/maps/api/place/details/json',
            params={
                'place_id': place_id,
                'fields': 'formatted_phone_number,international_phone_number,website,'
                          'opening_hours,price_level,url,business_status,photos,reviews',
                'language': 'en',
                'key': GOOGLE_PLACES_API_KEY,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Google Place Details error: {e}")
        return {}
    if data.get('status') != 'OK':
        return {}
    return data.get('result') or {}

def _fetch_google_places(query, lat, lng):
    """Query Google Places Text Search (billed). Returns up to
    PLACES_MAX_RESULTS card dicts enriched with Place Details, or None."""
    if not GOOGLE_PLACES_API_KEY:
        return None
    params = {
        'query': query,
        'location': f'{lat},{lng}',
        'radius': GOOGLE_PLACES_RADIUS_M,
        'language': 'en',
        'key': GOOGLE_PLACES_API_KEY,
    }
    try:
        resp = requests.get(GOOGLE_PLACES_TEXTSEARCH_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Google Places error: {e}")
        return None
    if data.get('status') != 'OK':
        return None
    places = []
    for i, r in enumerate((data.get('results') or [])[:PLACES_MAX_RESULTS], 1):
        loc = (r.get('geometry') or {}).get('location') or {}
        p = {
            'title': r.get('name'),
            'address': r.get('formatted_address'),
            'rating': r.get('rating'),
            'ratingCount': r.get('user_ratings_total'),
            'category': _google_type_label(r.get('types') or []),
            'position': i,
            'latitude': loc.get('lat'),
            'longitude': loc.get('lng'),
            'cid': '',
            'place_id': r.get('place_id'),
            'openNow': (r.get('opening_hours') or {}).get('open_now'),
            'website': None,
            'phoneNumber': None,
            'priceLevel': None,
            'openHours': [],
            'gmapsUrl': None,
            'businessStatus': None,
            'photos': [],
            'reviews': [],
        }
        det = _fetch_google_place_details(r.get('place_id'))
        if det:
            oh = det.get('opening_hours') or {}
            p['phoneNumber'] = det.get('formatted_phone_number') or p.get('phoneNumber')
            p['website'] = det.get('website') or p.get('website')
            if oh.get('open_now') is not None:
                p['openNow'] = oh.get('open_now')
            p['openHours'] = oh.get('weekday_text') or []
            p['priceLevel'] = det.get('price_level')
            p['gmapsUrl'] = det.get('url') or p.get('gmapsUrl')
            p['businessStatus'] = det.get('business_status')
            p['photos'] = _google_photo_refs(det.get('photos') or [])
            p['reviews'] = _google_review_summary(det.get('reviews') or [])
        places.append(p)
    return places or None

def _google_photo_refs(raw_photos):
    """Keep a small list of photo references. Each photo is fetched once via the
    server-side proxy, so Google Place Photo billing stays bounded."""
    refs = []
    seen = set()
    for ph in raw_photos[:PLACES_PHOTO_MAX]:
        ref = ph.get('photo_reference') or ''
        if not ref or ref in seen:
            continue
        seen.add(ref)
        refs.append({
            'ref': ref,
            'width': ph.get('width'),
            'height': ph.get('height'),
            'attribution': (ph.get('html_attributions') or [''])[0],
        })
    return refs

def _google_review_summary(raw_reviews):
    out = []
    for rv in raw_reviews[:5]:
        out.append({
            'author': rv.get('author_name'),
            'rating': rv.get('rating'),
            'time': rv.get('relative_time_description'),
            'text': (rv.get('text') or '')[:600],
        })
    return out

def _fetch_serper_places(query, location, gl):
    try:
        resp = requests.post(
            SERPER_PLACES_URL,
            json={'q': query, 'location': location, 'gl': gl},
            headers={'X-API-KEY': SERPER_API_KEY, 'Content-Type': 'application/json'},
            timeout=10,
        )
        resp.raise_for_status()
        parsed = resp.json()
    except Exception as e:
        app.logger.error(f"Serper places error: {e}")
        return None
    raw = (parsed.get('places') or None)
    if not raw:
        return None
    places = []
    for i, r in enumerate(raw[:PLACES_MAX_RESULTS], 1):
        img_url = r.get('imageUrl') or ''
        thumb_url = r.get('thumbnailUrl') or ''
        photos = []
        if img_url:
            photos = [{'ref': '', 'url': img_url, 'thumb': thumb_url, 'attribution': ''}]
        places.append({
            'title': r.get('title'),
            'address': r.get('address'),
            'rating': r.get('rating'),
            'ratingCount': r.get('reviewsCount'),
            'category': r.get('category') or r.get('eateryType') or r.get('hotelClass') or '',
            'position': i,
            'latitude': r.get('latitude'),
            'longitude': r.get('longitude'),
            'cid': r.get('cid') or '',
            'place_id': '',
            'openNow': None,
            'website': r.get('website'),
            'phoneNumber': r.get('phone'),
            'priceLevel': None,
            'openHours': [],
            'gmapsUrl': r.get('link'),
            'businessStatus': None,
            'photos': photos,
            'reviews': [],
        })
    return places or None

def fetch_places(query, location, gl=None):
    """Fetch places: Google Places API first, Serper as fallback. Results are
    cached in data.json and filtered by distance from the requested location."""
    gl = gl or PLACES_GL_DEFAULT
    location = _correct_places_location(location)
    location = _enrich_places_location(location, gl)
    key = hashlib.md5(f"{query.lower().strip()}|{location.lower().strip()}|{gl}|v{PLACES_CACHE_VERSION}".encode()).hexdigest()
    cached = data_manager.get_places_cache(key)
    if cached and cached.get('places'):
        places = cached['places']
        geo = _geocode_location(location)
        if geo:
            filtered = _filter_places_by_distance(places, *geo)
            if filtered:
                places = filtered
        return places[:PLACES_MAX_RESULTS], True
    if not SERPER_API_KEY and not GOOGLE_PLACES_API_KEY:
        return None, False
    geo = _geocode_location(location)
    places = None
    if geo:
        places = _fetch_google_places(query, geo[0], geo[1])
    if not places:
        places = _fetch_serper_places(query, location, gl)
    if not places:
        return None, False
    data_manager.set_places_cache(key, places)
    if geo:
        filtered = _filter_places_by_distance(places, *geo)
        if filtered:
            places = filtered
    return places[:PLACES_MAX_RESULTS], False

@app.route('/api/places')
def api_places():
    q = (request.args.get('q') or '').strip()
    location = (request.args.get('location') or '').strip()
    if not q or not location:
        return jsonify({'ok': False, 'error': 'q and location are required'}), 400
    gl = (request.args.get('gl') or PLACES_GL_DEFAULT).strip()
    places, cached = fetch_places(q, location, gl)
    if not places:
        return jsonify({'ok': False, 'error': 'No places found'}), 404
    return jsonify({'ok': True, 'places': places, 'location': location, 'cached': cached})

# ── Places photos (server-side proxy so the Google API key never reaches the client) ──
_PLACE_PHOTO_REF_RE = re.compile(r'^[A-Za-z0-9_\-+=/]+$')

def _fetch_google_place_photo(ref, maxwidth):
    """Fetch a photo once via Google Place Photo API and cache the bytes on disk.
    Returns (bytes, content_type) or None."""
    try:
        resp = requests.get(
            PLACES_PHOTO_URL,
            params={'photo_reference': ref, 'maxwidth': maxwidth, 'key': GOOGLE_PLACES_API_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        ctype = resp.headers.get('Content-Type', 'image/jpeg')
        if not ctype.startswith('image/'):
            ctype = 'image/jpeg'
        return resp.content, ctype
    except Exception as e:
        app.logger.warning(f"Google Place Photo error: {e}")
        return None

@app.route('/places/photo')
def places_photo():
    ref = request.args.get('ref', '')
    if not ref or not _PLACE_PHOTO_REF_RE.match(ref):
        return ('', 404)
    try:
        os.makedirs(PLACES_PHOTO_DIR, exist_ok=True)
    except OSError:
        pass
    digest = hashlib.md5(ref.encode()).hexdigest()
    path = os.path.join(PLACES_PHOTO_DIR, f'{digest}.img')
    if not os.path.isfile(path):
        fetched = _fetch_google_place_photo(ref, PLACES_PHOTO_MAXWIDTH)
        if not fetched:
            return ('', 404)
        try:
            with open(path, 'wb') as f:
                f.write(fetched[0])
        except OSError as e:
            app.logger.warning(f"Places photo cache write error: {e}")
        return send_file(io.BytesIO(fetched[0]), mimetype=fetched[1], max_age=86400 * 30)
    return send_file(path, max_age=86400 * 30)

# ── Email Helpers ──
WELCOME_EMAIL_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body{font-family:Arial,sans-serif;background:#202124;color:#e8eaed;margin:0;padding:0}
.container{max-width:560px;margin:0 auto;padding:32px 24px}
.logo{font-size:28px;font-weight:700;letter-spacing:-1px;text-align:center;margin-bottom:24px;color:#e8eaed}
.logo span{background:linear-gradient(to top,#0066cc,#3399ff 50%,#e8eaed 50%);background-size:100% 200%;-webkit-background-clip:text;background-clip:text;color:transparent}
.card{background:#303134;border:1px solid #5f6368;border-radius:12px;padding:28px}
.card h1{margin:0 0 8px;font-size:20px;font-weight:400}
.card p{color:#bdc1c6;font-size:14px;line-height:1.6;margin:12px 0}
.btn{display:inline-block;padding:10px 24px;background:#8ab4f8;color:#fff;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500;margin:8px 0}
.btn:hover{opacity:.9}
.footer{text-align:center;font-size:12px;color:#9aa0a6;margin-top:24px}
.footer a{color:#8ab4f8;text-decoration:none}
</style></head>
<body>
<div class="container">
<div class="logo"><span>a</span><span>r</span><span>l</span><span>o</span><span>n</span><span>g</span></div>
<div class="card">
<h1>Welcome to arlong, {username}!</h1>
<p>You've joined a privacy-first search community. Here's what you can do:</p>
<p>&bull; <strong>24 free searches/day</strong> with AI-powered summaries<br>
&bull; Create and share <strong>collections</strong> of your favorite sites<br>
&bull; Submit your website for indexing<br>
&bull; Upgrade to <strong>Premium</strong> for 500+ searches/day</p>
<p style="text-align:center"><a href="https://aoogle-production.up.railway.app/" class="btn">Start searching</a></p>
<p style="font-size:12px;color:#9aa0a6">No tracking. No ads. Just search.</p>
</div>
<div class="footer">
<a href="https://aoogle-production.up.railway.app/premium">Premium</a> &middot;
<a href="https://aoogle-production.up.railway.app/privacy">Privacy</a> &middot;
<a href="https://aoogle-production.up.railway.app/faq">FAQ</a>
</div>
</div>
</body>
</html>"""

LOGIN_EMAIL_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body{font-family:Arial,sans-serif;background:#202124;color:#e8eaed;margin:0;padding:0}
.container{max-width:560px;margin:0 auto;padding:32px 24px}
.logo{font-size:28px;font-weight:700;letter-spacing:-1px;text-align:center;margin-bottom:24px;color:#e8eaed}
.logo span{background:linear-gradient(to top,#0066cc,#3399ff 50%,#e8eaed 50%);background-size:100% 200%;-webkit-background-clip:text;background-clip:text;color:transparent}
.card{background:#303134;border:1px solid #5f6368;border-radius:12px;padding:28px}
.card h1{margin:0 0 8px;font-size:20px;font-weight:400}
.card p{color:#bdc1c6;font-size:14px;line-height:1.6;margin:12px 0}
.card .time{font-size:12px;color:#9aa0a6;margin-top:4px}
.footer{text-align:center;font-size:12px;color:#9aa0a6;margin-top:24px}
.footer a{color:#8ab4f8;text-decoration:none}
</style></head>
<body>
<div class="container">
<div class="logo"><span>a</span><span>r</span><span>l</span><span>o</span><span>n</span><span>g</span></div>
<div class="card">
<h1>Sign-in notification</h1>
<p>Hi {username},</p>
<p>A new sign-in to your arlong account was detected.</p>
<p>If this was you, no action is needed. If you don't recognize this activity, please change your password immediately.</p>
<p class="time">Time: {time}<br>IP: {ip}</p>
<p style="text-align:center;margin-top:16px"><a href="https://aoogle-production.up.railway.app/u/{username}" class="btn" style="display:inline-block;padding:10px 24px;background:#8ab4f8;color:#fff;border-radius:6px;text-decoration:none;font-size:14px;font-weight:500">Review account</a></p>
</div>
<div class="footer">
<a href="https://aoogle-production.up.railway.app/privacy">Privacy policy</a>
</div>
</div>
</body>
</html>"""

def send_resend_email(to_email, subject, html_body):
    if not RESEND_API_KEY or not to_email:
        return False
    try:
        r = resend.Emails.send({
            "from": RESEND_FROM,
            "to": to_email,
            "subject": subject,
            "html": html_body,
        })
        app.logger.info(f"Email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def send_welcome_email(email, username):
    html = WELCOME_EMAIL_HTML.replace('{username}', username)
    return send_resend_email(email, 'Welcome to arlong!', html)

def send_login_notification(email, username, ip):
    now_str = datetime.now().strftime('%B %d, %Y at %I:%M %p UTC')
    html = LOGIN_EMAIL_HTML.replace('{username}', username).replace('{time}', now_str).replace('{ip}', ip or 'Unknown')
    return send_resend_email(email, 'New sign-in to your arlong account', html)


@app.route('/land')
def land():
    return render_template('land.html')

@app.route('/')
def home():
    announcement = data_manager.get_announcement()
    user_stats = None
    daily_remaining = None
    quota_limit = None
    user_weather_location = ''
    preferences = {}
    if session.get('user_id'):
        profile = data_manager.get_user_profile(session.get('username'))
        user_stats = profile
        user_weather_location = (profile or {}).get('weather_location', '') or ''
        preferences = data_manager.get_user_preferences(session['user_id'])
    return render_template('search.html', announcement=announcement, blocked_count=BLOCKLIST_COUNT, user_country=session.get('user_country', ''), country_name=COUNTRY_NAMES.get(session.get('user_country', '')), user_stat=user_stats, daily_remaining=UNLIMITED, quota_limit=UNLIMITED, user_weather_location=user_weather_location, board_results=None, result_groups=[], ai_summary_enabled=True, preferences=preferences)

@app.route('/search')
def search():
    _search_start = time.time()
    query = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    filter_type = 'general'
    region = request.args.get('region', session.get('region', ''))

    announcement = data_manager.get_announcement()
    preferences = {}
    if not query:
        user_stats = None
        user_weather_location = ''
        user_country = session.get('user_country', '')
        if session.get('user_id'):
            profile = data_manager.get_user_profile(session.get('username'))
            user_stats = profile
            user_weather_location = (profile or {}).get('weather_location', '') or ''
            preferences = data_manager.get_user_preferences(session['user_id'])
        return render_template('search.html', announcement=announcement, blocked_count=BLOCKLIST_COUNT, user_country=user_country, country_name=COUNTRY_NAMES.get(user_country), user_stat=user_stats, daily_remaining=UNLIMITED, quota_limit=UNLIMITED, user_weather_location=user_weather_location, board_results=None, result_groups=[], ai_summary_enabled=True, preferences=preferences, video_results=[], image_results=[])

    bang_url = get_bang_redirect(query)
    if bang_url:
        return redirect(bang_url)

    user_country = ''

    user_id = session.get('user_id')

    crisis = detect_crisis(query)

    if crisis and crisis['type'] in ('harmful', 'crisis'):
        user_stats = None
        if session.get('user_id'):
            user_stats = data_manager.get_user_profile(session.get('username'))
        return render_template(
            'search.html',
            query=query,
            crisis_info=crisis,
            results=LIFE_RESOURCES,
            notice={'type': 'redirect', 'message': 'You matter. Here are resources that may help.'},
            page=1,
            total_results=len(LIFE_RESOURCES),
            info_box=None,
            shopping_products=None,
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name='',
            user_stat=user_stats,
            board_results=None,
            result_groups=[],
            ai_summary_enabled=True,
            preferences={},
            video_results=[],
            image_results=[],
        )

    notice = detect_notice(query)
    if notice and notice['type'] == 'redirect':
        user_stats = None
        if session.get('user_id'):
            user_stats = data_manager.get_user_profile(session.get('username'))
        return render_template(
            'search.html',
            query=query,
            results=BODY_POSITIVE_RESOURCES,
            notice=notice,
            page=1,
            total_results=0,
            info_box=None,
            shopping_products=None,
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name='',
            user_stat=user_stats,
            board_results=None,
            preferences={},
            video_results=[],
            image_results=[],
        )

    try:
        if region:
            session['region'] = region
        results, total_results = search_engine.search(query, page, filter_type, region or None)

        # ── Parallelize supplementary fetches alongside result processing ──
        from concurrent.futures import ThreadPoolExecutor as _SupPool, Future
        _sup_pool = _SupPool(max_workers=5)

        _f_videos = _sup_pool.submit(search_engine.search_videos, query)
        _f_info_box = _sup_pool.submit(get_info_box, query, results)
        _f_shopping = _sup_pool.submit(get_shopping_panel, query, results)
        _f_collections = _sup_pool.submit(data_manager.search_collections, query)
        _f_images = _sup_pool.submit(search_engine.search_images, query)

        # ── Places detection (local business queries) ──
        places_query = None
        places_location = None
        places_prompt = None
        places_results = None
        places_cached = False
        _f_places = None
        if has_places_intent(query):
            clean_q, loc = extract_places_location(query)
            if loc:
                places_query = (clean_q or _clean_places_query(query))[:80]
                places_location = loc
                _f_places = _sup_pool.submit(fetch_places, places_query, places_location)
            else:
                places_query = (_clean_places_query(query) or query)[:80]
                places_prompt = places_query

        verified_info = data_manager.get_verified_info(query.lower().strip(), user_country)
        if not verified_info and results:
            q_parts = query.lower().strip().split()
            for r in results:
                domain = (r.get('domain') or '').replace('www.', '')
                if data_manager.is_verified(domain, user_country):
                    verified_info = data_manager.get_verified_info(domain, user_country)
                    break
                name_match = any(p in r.get('title', '').lower() for p in q_parts if len(p) > 3)
                if name_match and data_manager.is_verified(domain, user_country):
                    verified_info = data_manager.get_verified_info(domain, user_country)
                    break

        if results:
            for r in results:
                domain = (r.get('domain') or urlparse(r['url']).netloc).lower().replace('www.', '')
                r['verified'] = data_manager.is_verified(domain, user_country)
            verified_results = [r for r in results if r.get('verified')]
            other_results = [r for r in results if not r.get('verified')]
            results = verified_results + other_results
            results = polish_result_snippets(results, query)

        _sup_pool.submit(search_stats.record)
        _sup_pool.submit(data_manager._increment_searches_deferred)

        safety_info = crisis if crisis and crisis['type'] == 'disaster' else None

        news_box = None
        news_intent = detect_news(query)
        news_candidates = [r for r in results if r.get('category') == 'news']
        if news_intent and news_candidates:
            news_box = {
                'topic': news_intent['topic'] or query,
                'items': news_candidates[:8]
            }
        elif query and len(news_candidates) >= 3 and any(kw in query.lower() for kw in NEWS_TOPIC_KEYWORDS):
            news_box = {
                'topic': query,
                'items': news_candidates[:8]
            }

        video_results = []
        info_box_data = None
        shopping_products = None
        board_results = None
        image_results = []
        try:
            video_results = _f_videos.result(timeout=4.0) or []
        except Exception:
            video_results = []
        try:
            info_box_data = _f_info_box.result(timeout=4.0)
        except Exception:
            info_box_data = None
        try:
            shopping_products = _f_shopping.result(timeout=4.0)
        except Exception:
            shopping_products = None
        try:
            board_results = _f_collections.result(timeout=4.0)
            if board_results:
                for b in board_results:
                    b['_type'] = 'board'
        except Exception:
            board_results = None
        try:
            image_results = _f_images.result(timeout=5.0) or []
        except Exception:
            image_results = []

        if _f_places is not None:
            try:
                places_results, places_cached = _f_places.result(timeout=6.0)
            except Exception:
                places_results, places_cached = None, False

        # Interleave video results into main results (BEFORE grouping so videos appear in domain groups)
        if video_results:
            from urllib.parse import urlparse
            inserted = 0
            for vi, v in enumerate(video_results):
                v_domain = urlparse(v.get('url', '')).netloc if v.get('url') else 'youtube.com'
                v_domain = re.sub(r'^www\.', '', v_domain)
                vr = {
                    'title': v.get('title', ''),
                    'url': v.get('url', ''),
                    'snippet': v.get('description', '') or '',
                    'category': 'video',
                    'domain': v_domain,
                    'favicon': '',
                    'date': v.get('published', '') or v.get('duration', ''),
                    'display_url': v.get('url', ''),
                    'source': 'video',
                    'thumbnail': v.get('thumbnail', ''),
                    'duration': v.get('duration', ''),
                    'channel': v.get('channel', ''),
                    'views': v.get('views', ''),
                    'video_id': v.get('id', ''),
                }
                pos = min(3 + inserted * 2, len(results))
                results.insert(pos, vr)
                inserted += 1

        result_groups = search_engine._group_results_by_domain(results)

        ai_summary_enabled = True
        if user_id:
            prefs = data_manager.get_user_preferences(user_id)
            ai_summary_enabled = prefs.get('ai_summary', True)

        search_time = round(time.time() - _search_start, 2)

        resp = make_response(render_template(
            'search.html',
            query=query,
            results=results,
            result_groups=result_groups,
            board_results=board_results,
            verified_info=verified_info,
            safety_info=safety_info,
            news_box=news_box,
            notice=notice,
            page=page,
            total_results=total_results,
            info_box=info_box_data,
            shopping_products=shopping_products,
            region=region or session.get('region', ''),
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name='',
            search_time=search_time,
            user_stat=None,
            ai_summary_enabled=ai_summary_enabled,
            preferences={},
            video_results=video_results,
            image_results=image_results,
            places_results=places_results,
            places_location=places_location,
            places_cached=places_cached,
            places_prompt=places_prompt,
        ))
        _sup_pool.shutdown(wait=False)
        return resp

    except Exception as e:
        import traceback
        app.logger.error(f"Search route error: {str(e)}\n{traceback.format_exc()}")
        resp = make_response(render_template(
            'search.html',
            query=query,
            notice=notice,
            error="An error occurred while processing your search. Please try again.",
            board_results=None,
            shopping_products=None,
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name='',
            user_stat=None,
            search_time=round(time.time() - _search_start, 2),
            result_groups=[],
            ai_summary_enabled=True,
            preferences={},
        ))
@app.route('/api/ai-summary', methods=['GET', 'POST'])
def api_ai_summary():
    try:
        if request.method == 'GET':
            q = (request.args.get('q') or '').strip()
        elif request.is_json:
            q = (request.json.get('q') or '').strip()
        else:
            q = (request.form.get('q') or '').strip()
        url = request.form.get('url', '') or request.args.get('url', '') or ''
        title = request.form.get('title', '') or request.args.get('title', '') or ''
        snippet = request.form.get('snippet', '') or request.args.get('snippet', '') or ''
        results_raw = request.form.get('results', '') or request.args.get('results', '') or ''

        if not q and not snippet:
            return jsonify({'ok': False, 'error': 'Query required'}), 400

        web_context = ''
        sources = []
        import re as _re
        if not (url and snippet):
            import httpx as _httpx
            from urllib.parse import urlparse as _urlparse
            _skip_domains = ['youtube.com', 'youtu.be', 'vimeo.com', 'instagram.com',
                             'facebook.com', 'fb.com', 'tiktok.com', 'twitter.com', 'x.com']
            if results_raw:
                try:
                    import json
                    provided = json.loads(results_raw)
                    news_items = [r for r in provided if r.get('category') == 'news']
                    wiki_items = [r for r in provided if 'wikipedia.org' in (r.get('url') or '').lower()]
                    rest_items = [r for r in provided if r not in news_items and r not in wiki_items]
                    q_lower = q.lower()
                    if any(kw in q_lower for kw in AI_FACTUAL_QUERY_KEYWORDS):
                        sorted_provided = wiki_items + news_items + rest_items
                    else:
                        sorted_provided = news_items + wiki_items + rest_items
                    snippet_context = ''
                    for r in sorted_provided[:5]:
                        r_snip = clean_snippet_text(r.get('snippet') or '')
                        r_url = (r.get('url') or '').strip()
                        if r_snip and r_url:
                            snippet_context += f"\n[Snippet] {r.get('title', '')}: {r_snip} ({r_url})"
                    if snippet_context:
                        web_context += snippet_context
                    for r in sorted_provided[:5]:
                        r_url = (r.get('url') or '').strip()
                        r_title = (r.get('title') or '').strip()
                        if not r_url or not r_url.startswith('http'):
                            continue
                        r_domain = _urlparse(r_url).netloc.lower()
                        r_domain = re.sub(r'^www\.', '', r_domain)
                        if any(s in r_domain for s in _skip_domains):
                            continue
                        try:
                            resp = _httpx.get(r_url, timeout=8, follow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0'})
                            if resp.status_code == 200:
                                text = resp.text
                                text = _re.sub(r'<script[^>]*>.*?</script>', '', text, flags=_re.DOTALL|_re.IGNORECASE)
                                text = _re.sub(r'<style[^>]*>.*?</style>', '', text, flags=_re.DOTALL|_re.IGNORECASE)
                                text = _re.sub(r'<[^>]+>', ' ', text)
                                text = _re.sub(r'\s+', ' ', text).strip()
                                text = text[:2000]
                                if len(text) > 100:
                                    idx = len(sources) + 1
                                    sources.append({'url': r_url, 'title': r_title})
                                    web_context += f"\n\n[Source {idx}]\nURL: {r_url}\nTitle: {r_title}\nContent: {text}"
                        except Exception:
                            continue
                except Exception:
                    pass
            if not web_context:
                try:
                    from ddgs import DDGS as _DDGS
                    _ddgs = _DDGS(timeout=5)
                    is_news_q = any(kw in q.lower() for kw in NEWS_TOPIC_KEYWORDS)
                    bk = 'news' if is_news_q else 'auto'
                    raw_results = list(_ddgs.text(q, max_results=4, backend=bk, safesearch='on'))
                    fetch_urls = []
                    for r in raw_results:
                        href = r.get('href', '')
                        if href and href.startswith('http'):
                            fetch_urls.append(href)
                    for fu in fetch_urls[:3]:
                        try:
                            resp = _httpx.get(fu, timeout=8, follow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0'})
                            if resp.status_code == 200:
                                text = resp.text
                                text = _re.sub(r'<script[^>]*>.*?</script>', '', text, flags=_re.DOTALL|_re.IGNORECASE)
                                text = _re.sub(r'<style[^>]*>.*?</style>', '', text, flags=_re.DOTALL|_re.IGNORECASE)
                                text = _re.sub(r'<[^>]+>', ' ', text)
                                text = _re.sub(r'\s+', ' ', text).strip()
                                text = text[:2000]
                                if len(text) > 100:
                                    idx = len(sources) + 1
                                    sources.append({'url': fu, 'title': ''})
                                    web_context += f"\n\n[Source {idx}]\nURL: {fu}\nContent: {text}"
                        except Exception:
                            continue
                except Exception as fetch_err:
                    app.logger.warning(f"AI web fetch error: {fetch_err}")

        system_msg = (
            "You are a world-class search assistant. "
            "Answer search queries with direct, specific, factual answers — like Google's featured snippet. "
            "Lead with the answer itself, not preamble like \"Based on\" or \"According to\". "
            "Use numbers, dates, names, and concrete details — not vague generalities. "
            "MATCH THE QUESTION TYPE: "
            "If the question asks for a specific detail (email, phone, address, price, date, etc.), give ONLY that detail — not a biography. "
            "If the query asks \"what is X\", define X in one crisp sentence first, then add 1-2 key facts. "
            "If the query asks \"who\", give the name + one defining fact. "
            "If the query asks \"when\", give the date/time directly. "
            "If the query asks \"how\", give the step or mechanism concisely. "
            "Never tell users to visit websites. Never use phrases like \"you can find\" or \"for more details\". "
            "Cite sources inline as [1], [2] only when there are multiple distinct facts from different sources. "
            "Keep total length to 2-4 sentences unless the question clearly requires more. "
            "Write in clean prose: no extra spaces before punctuation, no bullet symbols unless the user sees a list format."
        )
        if url and snippet:
            prompt = f"""Answer this question using the page content below. Start with the direct answer.

Page title: {title}
Page content: {clean_snippet_text(snippet)}

Question: {q}

Give the answer directly in 2-3 sentences. Include the key fact or definition upfront."""
        elif web_context:
            prompt = f"""Answer this question using ONLY the web content below.

CRITICAL: If the question asks for a specific piece of information (email, phone number, address, date, price, website, etc.), extract ONLY that specific information. Do NOT give a general biography or overview.

Question: {q}

Web sources:
{web_context}

Start with the direct answer to the specific question. Extract the exact information requested (e.g., if asked for email, give the email address). If the question asks "what is X's email/phone/address", answer with just the contact detail and source, not a biography. Cite sources as [1], [2] when citing different sources. Keep it to 1-4 sentences."""
        else:
            prompt = f"""Answer this question directly and concisely.

Question: {q}

Give the most accurate answer you can in 2-3 sentences. If you are not certain, say what you know and note the uncertainty."""

        from groq import Groq
        groq_client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
        ai_model = os.environ.get('GROQ_AI_MODEL', 'llama-3.3-70b-versatile')
        completion = groq_client.chat.completions.create(
            model=ai_model,
            messages=[{"role": "system", "content": system_msg}, {"role": "user", "content": prompt}],
            max_tokens=650,
            temperature=0.15,
        )
        answer = polish_ai_summary_text(completion.choices[0].message.content.strip())

        # Post-process: replace hallucinated URLs with real source URLs
        if url and snippet:
            safe_url = url.replace(')', '%29')
            answer = _re.sub(r'\[([^\]]+)\]\([^)]+\)', lambda m: f'[{m.group(1)}]({safe_url})', answer)
        elif sources:
            for i, src in enumerate(sources):
                n = i + 1
                safe_url = src["url"].replace(')', '%29')
                for pattern in (f'[Source {n}]', f'[source {n}]', f'[{n}]'):
                    answer = answer.replace(pattern, f'[{n}]({safe_url})')
            # Fallback: replace empty brackets with first source link
            first_url = sources[0]["url"].replace(')', '%29')
            answer = _re.sub(r'\(\s*\)', f'[1]({first_url})', answer)
            # Clean up any lingering bare brackets or empty links
            answer = _re.sub(r'\bhttps?://[^\s<)\]]+', '', answer)
            answer = _re.sub(r'\[\d+\]\(\)', '', answer)

        return jsonify({'ok': True, 'summary': answer, 'sources': sources})
    except Exception as e:
        app.logger.error(f"AI summary error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/search-supplement')
def api_search_supplement():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'ok': False, 'error': 'Query required'}), 400
    existing_urls = set(request.args.get('existing', '').split(',')) if request.args.get('existing') else set()
    try:
        extra = []
        seen_urls = set(existing_urls)
        # Run Brave search as background supplement
        try:
            brave_results = _search_brave(query, max_results=10)
            for r in brave_results:
                if r.url not in seen_urls:
                    seen_urls.add(r.url)
                    extra.append(r.to_dict())
        except Exception as e:
            app.logger.warning(f"Supplement Brave error: {e}")
        # Also try DDGS library if available
        if ddgs_available:
            try:
                from ddgs import DDGS as _DDGS
                _ddgs2 = _DDGS(timeout=5)
                ddgs_raw = list(_ddgs2.text(query, max_results=10, backend='auto', safesearch='on'))
                for r in ddgs_raw:
                    href = r.get('href', '')
                    title = r.get('title', '')
                    body = r.get('body', '')
                    if href and title and href not in seen_urls:
                        seen_urls.add(href)
                        from urllib.parse import urlparse as _up
                        extra.append({
                            'title': title,
                            'url': href,
                            'display_url': href[:60] + '...' if len(href) > 60 else href,
                            'snippet': (body or '')[:300],
                            'category': 'general',
                            'favicon': f"https://www.google.com/s2/favicons?domain={href}",
                            'domain': _up(href).netloc,
                            'date': None,
                            'score': 0,
                            'type': 'regular',
                        })
            except Exception as e:
                app.logger.warning(f"Supplement DDGS error: {e}")
        return jsonify({'ok': True, 'results': extra})
    except Exception as e:
        app.logger.error(f"Supplement search error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/search-images')
def api_search_images():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'ok': False, 'error': 'Query required'}), 400
    try:
        images = search_engine.search_images(query) or []
        return jsonify({'ok': True, 'query': query, 'images': images})
    except Exception as e:
        app.logger.error(f"Search images error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/search')
def api_search():
    query = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    pretty = request.args.get('pretty', '').lower() in ('1', 'true', 'yes')

    if not query:
        return jsonify({"error": "Missing query parameter", "usage": "/api/search?q=your+query"}), 400

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip()

    rate = api_limiter.check(ip)
    if not rate["allowed"]:
        resp = jsonify({
            "error": "Rate limit exceeded",
            "message": f"You have exceeded the rate limit of 25 requests per hour. Retry after {rate['retry_after']} seconds.",
            "retry_after": rate["retry_after"]
        })
        resp.status_code = 429
        resp.headers['X-RateLimit-Remaining'] = '0'
        resp.headers['X-RateLimit-Reset'] = str(rate['retry_after'])
        return resp

    crisis = detect_crisis(query)

    if crisis and crisis['type'] in ('harmful', 'crisis'):
        resp = jsonify({
            "query": query,
            "notice": {"type": "redirect", "message": "You matter. Here are resources that may help."},
            "results": LIFE_RESOURCES,
            "total_results": len(LIFE_RESOURCES),
            "page": page
        })
        resp.headers['X-RateLimit-Remaining'] = str(rate['remaining'])
        return resp

    notice = detect_notice(query)
    if notice and notice['type'] == 'redirect':
        resp = jsonify({
            "query": query,
            "notice": notice,
            "results": BODY_POSITIVE_RESOURCES,
            "total_results": len(BODY_POSITIVE_RESOURCES),
            "page": page
        })
        resp.headers['X-RateLimit-Remaining'] = str(rate['remaining'])
        return resp

    try:
        results, total_results = search_engine.search(query, page)
        search_stats.record()
        data_manager.increment_total_searches()

        data = {
            "query": query,
            "page": page,
            "total_results": total_results,
            "results": results,
            "info_box": get_info_box(query)
        }
        if crisis and crisis['type'] == 'disaster':
            data["safety_info"] = crisis
        if notice:
            data["notice"] = notice

        indent = 2 if pretty else None
        resp = app.response_class(
            response=json.dumps(data, indent=indent),
            status=200,
            mimetype='application/json'
        )
        resp.headers['X-RateLimit-Remaining'] = str(rate['remaining'])
        return resp

    except Exception as e:
        app.logger.error(f"API search error: {str(e)}")
        resp = jsonify({
            "error": "Search failed",
            "message": "An internal error occurred while searching."
        })
        resp.status_code = 500
        resp.headers['X-RateLimit-Remaining'] = str(rate['remaining'])
        return resp

@app.route('/api/enc-search', methods=['POST'])
def enc_search():
    try:
        body = request.get_json()
        query = _dec(body['iv'], body['data']).strip()
        if not query:
            return jsonify({'iv': '', 'data': ''}), 400
        crisis = detect_crisis(query)
        if crisis and crisis['type'] in ('harmful', 'crisis'):
            iv, ct = _enc(json.dumps({'results': LIFE_RESOURCES, 'total': len(LIFE_RESOURCES), 'crisis': crisis}))
            return jsonify({'iv': iv, 'data': ct})
        notice = detect_notice(query)
        bang_url = get_bang_redirect(query)
        if bang_url:
            iv, ct = _enc(json.dumps({'bang': bang_url}))
            return jsonify({'iv': iv, 'data': ct})
        results, total = search_engine.search(query, 1, 'general', None)
        if results:
            results = polish_result_snippets(results, query)
        board_results = data_manager.search_collections(query) if data_manager else []
        result_groups = search_engine._group_results_by_domain(results) if results else []
        out = {
            'results': results or [],
            'total': total,
            'result_groups': result_groups,
            'board_results': [{'name': b.get('name',''), 'id': b['id'], 'description': b.get('description','')} for b in (board_results or [])],
            'notice': notice,
        }
        iv, ct = _enc(json.dumps(out))
        return jsonify({'iv': iv, 'data': ct})
    except Exception as e:
        app.logger.error(f"Enc search error: {e}")
        return jsonify({'iv': '', 'data': _b64mod.b64encode(json.dumps({'error': str(e)}).encode()).decode()}), 500

@app.route('/api/enc-images', methods=['POST'])
def enc_images():
    try:
        body = request.get_json()
        query = _dec(body['iv'], body['data']).strip()
        if not query:
            return jsonify({'iv': '', 'data': ''}), 400
        img_results = search_engine.search_images(query)
        iv, ct = _enc(json.dumps({'images': img_results or []}))
        return jsonify({'iv': iv, 'data': ct})
    except Exception as e:
        app.logger.error(f"Enc images error: {e}")
        return jsonify({'iv': '', 'data': ''}), 500

@app.route('/api/enc-videos', methods=['POST'])
def enc_videos():
    try:
        body = request.get_json()
        query = _dec(body['iv'], body['data']).strip()
        if not query:
            return jsonify({'iv': '', 'data': ''}), 400
        vid_results = search_engine.search_videos(query)
        iv, ct = _enc(json.dumps({'videos': vid_results or []}))
        return jsonify({'iv': iv, 'data': ct})
    except Exception as e:
        app.logger.error(f"Enc videos error: {e}")
        return jsonify({'iv': '', 'data': ''}), 500

@app.route('/images')
def images():
    query = request.args.get('q', '').strip()
    if not query:
        return render_template('images.html')

    try:
        img_results = search_engine.search_images(query)
        return render_template('images.html', query=query, images=img_results)
    except Exception as e:
        app.logger.error(f"Images route error: {str(e)}")
        return render_template(
            'images.html',
            query=query,
            error="Failed to fetch images. Please try again."
        )

@app.route('/videos')
def videos():
    query = request.args.get('q', '').strip()
    if not query:
        return render_template('videos.html')
    try:
        vid_results = search_engine.search_videos(query)
        return render_template('videos.html', query=query, videos=vid_results)
    except Exception as e:
        app.logger.error(f"Videos route error: {str(e)}")
        return render_template('videos.html', query=query, error="Failed to fetch videos. Please try again.")

@app.route('/blog')
def blog():
    return redirect(url_for('land'))

@app.route('/about')
def about():
    return redirect(url_for('land'))

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/stats')
def stats():
    return render_template('stats.html')

@app.route('/api/stats')
def api_stats():
    hours = min(int(request.args.get('hours', 48)), 168)
    hourly = search_stats.get_hourly(hours)
    per_minute = search_stats.get_recent_per_minute(30)
    return jsonify({"hourly": hourly, "per_minute": per_minute})

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '').strip()
    try:
        suggestions = search_engine.get_suggestions(query)
        return jsonify(suggestions)
    except Exception as e:
        app.logger.error(f"Suggestion route error: {str(e)}")
        return jsonify([])

@app.route('/crisis', methods=['GET', 'POST'])
def crisis():
    if request.method == 'POST':
        region = request.form.get('region', 'global')
        crisis_type = request.form.get('crisis_type', '')
        return render_template(
            'crisis.html',
            query='',
            crisis={'type': 'resources', 'crisis_type': crisis_type or None},
            resources=CRISIS_RESOURCES,
            selected_region=region
        )
    q = request.args.get('q', '')
    crisis_data = detect_crisis(q) if q else None
    return render_template(
        'crisis.html',
        query=q,
        crisis=crisis_data or {'type': 'help'},
        resources=CRISIS_RESOURCES
    )

@app.route('/health')
def health():
    return 'ok', 200


@app.route('/policy')
def policy():
    return render_template('policy.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')


@app.route('/refund-policy')
def refund_policy():
    return render_template('refund_policy.html')


@app.route('/faq')
def faq():
    return render_template('faq.html')


@app.route('/changelogs')
def changelogs():
    return render_template('changelogs.html')


@app.route('/settings')
def settings():
    user_id = session.get('user_id')
    preferences = {'ai_summary': True}
    if user_id:
        preferences = data_manager.get_user_preferences(user_id)
    return render_template('settings.html', preferences=preferences, is_logged_in=bool(user_id))


@app.route('/robots.txt')
def robots_txt():
    lines = [
        'User-agent: *',
        'Allow: /',
        'Disallow: /admin',
        'Disallow: /admin/',
        '',
        'Sitemap: https://aoogle-production.up.railway.app/sitemap.xml',
        '',
        '# aoogle - a meta search engine',
        '# No tracking, no logging, no ads.',
    ]
    return app.response_class(
        response='\n'.join(lines),
        status=200,
        mimetype='text/plain'
    )


@app.route('/api/bangs')
def api_bangs():
    bang_list = []
    for key, url in BANG_REDIRECTS.items():
        domain = urlparse(url).netloc
        favicon = f'https://www.google.com/s2/favicons?domain={domain}&sz=16'
        bang_list.append({
            'bang': f'!{key}',
            'domain': domain,
            'url': url,
            'favicon': favicon,
        })
    return jsonify(sorted(bang_list, key=lambda x: x['bang']))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('search.html', error="Page not found", board_results=None, result_groups=[], ai_summary_enabled=True, preferences={}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {str(error)}")
    return render_template('search.html', error="An internal error occurred. Please try again.", board_results=None, result_groups=[], ai_summary_enabled=True, preferences={}), 500

@app.route('/api/report', methods=['POST'])
def api_report():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get('url', '')
    title = data.get('title', '')
    query = data.get('query', '')
    domain = urlparse(url).netloc.lower()
    domain = re.sub(r'^www\.', '', domain)
    if not url or not domain:
        return jsonify({"error": "Missing url"}), 400
    report = data_manager.add_report(url, title, query, domain)
    return jsonify({"status": "ok", "report_id": report['id']})

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    error = ''
    if request.method == 'POST':
        if not validate_csrf():
            error = 'Invalid form submission. Please try again.'
        else:
            password = request.form.get('password', '')
            if secrets.compare_digest(password, ADMIN_PASSWORD):
                session.clear()
                session['admin_logged_in'] = True
                return redirect(url_for('admin_dashboard'))
            else:
                error = 'Incorrect password'
    return render_template('admin.html', login=True, error=error)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    stats = data_manager.get_stats()
    reports = data_manager.get_all_reports()
    blacklist = data_manager.get_blacklist()
    total_searches = data_manager.get_total_searches()
    celebration = data_manager.get_celebration()
    announcement = data_manager.get_announcement()
    verified_sites = data_manager.get_verified_sites()
    submitted_sites = data_manager.get_submitted_sites()
    domain_reports = data_manager.get_pending_domain_reports()
    return render_template('admin.html', login=False, stats=stats, reports=reports, blacklist=blacklist, total_searches=total_searches, celebration=celebration, announcement=announcement, verified_sites=verified_sites, submitted_sites=submitted_sites, domain_reports=domain_reports)

@app.route('/admin/reports/<int:report_id>/approve', methods=['POST'])
def admin_approve_report(report_id):
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    penalty = int(request.form.get('penalty', -30))
    data_manager.approve_report(report_id, penalty)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reports/<int:report_id>/deny', methods=['POST'])
def admin_deny_report(report_id):
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    data_manager.deny_report(report_id)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/blacklist/remove', methods=['POST'])
def admin_remove_blacklist():
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    domain = request.form.get('domain', '')
    if domain:
        data_manager.remove_from_blacklist(domain)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/celebration', methods=['POST'])
def admin_celebration():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    values = request.form.getlist('celebration')
    text = values[-1].strip() if values else ''
    data_manager.set_celebration(text)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/verified/add', methods=['POST'])
def admin_add_verified():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain', '').strip().lower().replace('www.', '')
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    description = request.form.get('description', '').strip()
    phone = request.form.get('phone', '').strip()
    region = request.form.get('region', 'us').strip()
    plan = request.form.get('plan', 'monthly').strip()
    scope = request.form.get('scope', 'regional').strip()
    regions_raw = request.form.get('regions', '')
    regions = [r.strip() for r in regions_raw.split(',') if r.strip()] or [region]
    if domain and name:
        data_manager.add_verified_site(domain, name, description, email, phone, region, plan, scope, regions)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/verified/remove', methods=['POST'])
def admin_remove_verified():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain', '')
    if domain:
        data_manager.remove_verified_site(domain)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/announcement', methods=['POST'])
def admin_announcement():
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    values = request.form.getlist('announcement')
    text = values[-1].strip() if values else ''
    data_manager.set_announcement(text)
    return redirect(url_for('admin_dashboard'))

@app.route('/verified')
def verified_page():
    return render_template('verified.html',
        verified_sites=data_manager.get_verified_sites(),
        submitted_count=len(data_manager.get_submitted_sites()),
        announcement=data_manager.get_announcement()
    )

@app.route('/submit', methods=['GET', 'POST'])
def submit_site():
    error = None
    success = None
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        phone = request.form.get('phone', '').strip()
        category = request.form.get('category', '').strip()
        sitemap_url = request.form.get('sitemap_url', '').strip()
        robots_txt_url = request.form.get('robots_txt_url', '').strip()
        email = request.form.get('email', '').strip()
        if not domain or not email or not sitemap_url or not robots_txt_url:
            error = "Domain, email, sitemap URL, and robots.txt URL are required."
        else:
            domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
            existing = data_manager.add_submitted_site(
                domain, sitemap_url, robots_txt_url, email,
                name=name, description=description, phone=phone, category=category,
                submitted_by=session.get('user_id')
            )
            if existing is None:
                error = f"{domain} has already been submitted."
            else:
                success = f"{domain} submitted successfully."
    return render_template('submit.html', error=error, success=success, announcement=data_manager.get_announcement())

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html',
        verified_sites=data_manager.get_verified_sites(),
        submitted_sites=data_manager.get_submitted_sites(),
        announcement=data_manager.get_announcement()
    )

@app.route('/claim')
def claim_site():
    return render_template('claim.html', announcement=data_manager.get_announcement())

# ── Community: signup, login, vote, comment, domain reports ──

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if not validate_csrf():
            return render_template('signup.html', error='Invalid form submission. Please try again.')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        sq = request.form.get('security_question', '').strip()
        sa = request.form.get('security_answer', '').strip()
        weather_loc = request.form.get('weather_location', '').strip()
        if not username or not password or not sq or not sa:
            return render_template('signup.html', error='All fields required')
        if len(username) < 3 or len(username) > 24:
            return render_template('signup.html', error='Username 3-24 characters')
        if len(password) < 8:
            return render_template('signup.html', error='Password must be at least 8 characters')
        if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
            return render_template('signup.html', error='Password must contain both letters and numbers')
        if email and '@' not in email:
            return render_template('signup.html', error='Invalid email address', email=email)
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
        user, err = data_manager.create_user(username, password, sq, sa, ip, email, weather_loc)
        if err:
            return render_template('signup.html', error=err, email=email)
        session.clear()
        session.permanent = True
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        if email:
            send_welcome_email(email, username)
        return redirect(url_for('user_profile', username=username))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            return render_template('signup.html', login_error='Invalid form submission. Please try again.')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = data_manager.authenticate_user(username, password)
        if not user:
            return render_template('signup.html', login_error='Invalid credentials')
        session.clear()
        session.permanent = True
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        user_email = user.get('email', '')
        if user_email and RESEND_API_KEY:
            try:
                ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
                send_login_notification(user_email, username, ip)
            except:
                pass
        return redirect(url_for('home'))
    return redirect(url_for('signup', mode='login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/api/check-username')
def api_check_username():
    username = request.args.get('username', '').strip()
    if not username or len(username) < 3 or len(username) > 24:
        return jsonify({'available': False, 'error': 'Invalid username'})
    loaded = _load_json()
    users = loaded.get('users', []) if loaded else []
    taken = any(u['username'].lower() == username.lower() for u in users)
    return jsonify({'available': not taken})

@app.route('/api/check-email')
def api_check_email():
    email = request.args.get('email', '').strip().lower()
    if not email or '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({'available': False, 'error': 'Invalid email'})
    loaded = _load_json()
    users = loaded.get('users', []) if loaded else []
    taken = any(u.get('email', '').lower() == email for u in users if u.get('email'))
    return jsonify({'available': not taken})

@app.route('/api/captcha')
def captcha():
    words = ["apple","beach","cloud","dance","eagle","flame","grape","house","ivory","jewel","knife","lemon","mango","night","ocean","pearl","queen","river","stone","tiger","unity","vivid","water","yacht","zebra","bloom","creek","dwarf","ember","frost","globe","honey","image","jolly","koala","lunar","magic","noble","orbit","piano","quiet","radar","solar","tulip","umbra","vocal","wheat","algae","birch","coral","sunset","midnight","winter","summer","autumn","spring","mountain","forest","desert","garden","silver","golden","crystal","thunder","shadow","spirit"]
    word = random.choice(words).upper()
    # Build scrambled visual: intersperse noise chars between real chars
    noise_pool = '@#&$%+!?~`*|\\/<>{}[]^=;:.,'
    scrambled_parts = []
    for i, ch in enumerate(word):
        rot = random.randint(-15, 15)
        oy = random.randint(-3, 3)
        colors = ['#ddd', '#ccc', '#eee', '#ffddaa', '#ddffdd', '#ddaaff']
        color = random.choice(colors)
        scrambled_parts.append({'ch': ch, 'rot': rot, 'oy': oy, 'color': color})
    # Generate HTML for the captcha display
    chars_html = ''
    for p in scrambled_parts:
        chars_html += '<span style="display:inline-block;transform:rotate(%ddeg);margin-top:%dpx;color:%s;font-weight:700">%s</span>' % (p['rot'], p['oy'], p['color'], p['ch'])
    # Add a few random noise chars as overlay
    noise_html = ''
    for _ in range(random.randint(15, 30)):
        nc = random.choice(noise_pool)
        left = random.randint(5, 250)
        top = random.randint(5, 35)
        noise_html += '<span style="position:absolute;pointer-events:none;z-index:1;color:#666;opacity:.25;font-family:monospace;font-size:%dpx;left:%dpx;top:%dpx">%s</span>' % (random.choice([8,9,10,11]), left, top, nc)
    # Scratch lines
    scratch_html = ''
    for _ in range(random.randint(2, 3)):
        x = random.randint(10, 240)
        y = random.randint(10, 30)
        w = random.randint(30, 80)
        scratch_html += '<div style="position:absolute;z-index:0;background:#555;opacity:.12;border-radius:2px;left:%dpx;top:%dpx;width:%dpx;height:2px"></div>' % (x, y, w)
    token = secrets.token_hex(8)
    session['captcha_token'] = token
    session['captcha_answer'] = word.lower()
    session['captcha_expires'] = time.time() + 60
    return jsonify({
        'token': token,
        'word_len': len(word),
        'html': '<div style="position:relative;display:flex;align-items:center;justify-content:center;min-height:40px;font-family:monospace;font-size:22px;font-weight:700;letter-spacing:2px;z-index:2;padding:4px">' + chars_html + '</div>' + noise_html + scratch_html,
        'expires_in': 60
    })

def check_captcha(token, answer):
    expires = session.get('captcha_expires', 0)
    if time.time() > expires:
        return False
    return (session.get('captcha_token') == token
            and session.get('captcha_answer') == answer.strip().lower()
            and token and answer.strip())

@app.route('/api/news')
def api_news():
    category = request.args.get('category', 'top')
    with NEWS_CACHE_LOCK:
        if category in NEWS_CACHE and NEWS_CACHE[category]:
            items = NEWS_CACHE[category]
        else:
            items = None
    if items is None:
        # On-demand refresh if cache is empty
        try:
            _fetch_and_cache_news()
            with NEWS_CACHE_LOCK:
                items = NEWS_CACHE.get(category, [])
        except Exception:
            items = []
    source_label = CATEGORY_SOURCE_LABELS.get(category, 'News')
    if category == 'top' and items:
        blog_items = _get_blog_news_items(max_items=2)
        if blog_items:
            items = list(items)
            insert_at = [p for p in BLOG_NEWSTAND_POSITIONS if p < len(items)]
            for i, blog_item in enumerate(blog_items):
                pos = insert_at[i] if i < len(insert_at) else len(items)
                items.insert(pos, blog_item)
    return jsonify({'ok': True, 'items': items, 'source': source_label})


@app.route('/api/trending')
def api_trending():
    country = request.args.get('country', '').lower().strip()[:2]
    if not country or country not in COUNTRY_NAMES:
        _, detected = detect_user_country()
        country = detected or 'us'

    # Check cache first
    cached = data_manager.get_trending_news(country)
    if cached:
        return jsonify({
            'ok': True,
            'regional': cached.get('regional', []),
            'global': cached.get('global', []),
            'cached_at': cached.get('cached_at', 0),
            'country': country,
            'source': 'cache',
        })

    # Cache miss — fetch fresh
    try:
        result = fetch_trending_news(country)
        regional = result.get('regional', [])
        global_top = result.get('global', [])

        # If regional empty, try to classify from all_regional
        if not regional:
            all_regional = result.get('all_regional', [])
            if all_regional:
                regional = all_regional[:3]
            else:
                # Last resort: use global as regional
                all_global = result.get('all_global', [])
                if all_global:
                    regional = all_global[:3]

        if not global_top:
            all_global = result.get('all_global', [])
            if all_global:
                global_top = all_global[:3]

        data_to_cache = {
            'regional': regional,
            'global': global_top,
        }
        data_manager.set_trending_news(country, data_to_cache)

        return jsonify({
            'ok': True if (regional or global_top) else False,
            'regional': regional,
            'global': global_top,
            'cached_at': time.time(),
            'country': country,
            'source': 'fetch',
        })
    except Exception as e:
        app.logger.error(f"Trending fetch error: {e}")
        return jsonify({
            'ok': False,
            'regional': [],
            'global': [],
            'country': country,
            'error': str(e),
        })




@app.route('/api/weather')
def api_weather():
    city = request.args.get('city', '')
    if not city:
        return jsonify({'ok': False, 'error': 'City required'}), 400
    try:
        resp = requests.get(f'https://wttr.in/{quote_plus(city)}?format=j1', timeout=5,
                            headers={'User-Agent': 'curl/7.68.0'})
        resp.raise_for_status()
        data = resp.json()
        current = data.get('current_condition', [{}])[0]
        area = data.get('nearest_area', [{}])[0]
        return jsonify({
            'ok': True,
            'temp': current.get('temp_C', ''),
            'feels': current.get('FeelsLikeC', ''),
            'desc': current.get('weatherDesc', [{}])[0].get('value', ''),
            'icon': current.get('weatherIconUrl', [{}])[0].get('value', ''),
            'humidity': current.get('humidity', ''),
            'wind': current.get('windspeedKmph', ''),
            'city': area.get('areaName', [{}])[0].get('value', city) if area.get('areaName') else city,
            'region': area.get('region', [{}])[0].get('value', '') if area.get('region') else '',
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/stocks')
def api_stocks():
    tickers = request.args.get('tickers', '^GSPC,^IXIC,^DJI,AAPL,MSFT,GOOGL,AMZN')
    try:
        results = []
        for t in tickers.split(','):
            t = t.strip()
            if not t:
                continue
            url = f'https://query1.finance.yahoo.com/v8/finance/chart/{t}?interval=1d&range=1mo'
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code != 200:
                continue
            data = resp.json()
            meta = data.get('chart', {}).get('result', [{}])[0].get('meta', {})
            quotes = data.get('chart', {}).get('result', [{}])[0].get('indicators', {}).get('quote', [{}])[0]
            closes = quotes.get('close', [])
            prev_close = meta.get('chartPreviousClose', 0)
            current = closes[-1] if closes else prev_close
            change = current - prev_close
            change_pct = (change / prev_close * 100) if prev_close else 0
            name = {'^GSPC': 'S&P 500', '^IXIC': 'NASDAQ', '^DJI': 'Dow Jones', 'AAPL': 'Apple', 'MSFT': 'Microsoft', 'GOOGL': 'Alphabet', 'AMZN': 'Amazon', 'TSLA': 'Tesla', 'META': 'Meta', 'NVDA': 'NVIDIA'}
            results.append({
                'ticker': t,
                'name': name.get(t, t),
                'price': round(current, 2),
                'change': round(change, 2),
                'change_pct': round(change_pct, 2),
            })
        return jsonify({'ok': True, 'items': results})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/scores')
def api_scores():
    soccer_leagues = [
        {'id': '4328', 'name': 'Premier League'},
        {'id': '4335', 'name': 'La Liga'},
        {'id': '4332', 'name': 'Bundesliga'},
        {'id': '4334', 'name': 'Serie A'},
        {'id': '4331', 'name': 'Ligue 1'},
        {'id': '4387', 'name': 'UEFA Champions League'},
    ]
    TEAM_CODES = {
        'Manchester United': 'MUN', 'Liverpool': 'LIV', 'Arsenal': 'ARS', 'Chelsea': 'CHE',
        'Manchester City': 'MCI', 'Tottenham': 'TOT', 'Newcastle United': 'NEW',
        'Aston Villa': 'AVL', 'West Ham United': 'WHU', 'Brighton': 'BRI',
        'Wolverhampton': 'WOL', 'Crystal Palace': 'CRY', 'Everton': 'EVE',
        'Fulham': 'FUL', 'Brentford': 'BRE', 'Nottingham Forest': 'NFO',
        'Bournemouth': 'BOU', 'Leicester City': 'LEI', 'Southampton': 'SOU',
        'Ipswich Town': 'IPS', 'Barcelona': 'BAR', 'Real Madrid': 'RMA',
        'Atletico Madrid': 'ATM', 'Athletic Bilbao': 'ATH', 'Real Sociedad': 'RSO',
        'Villarreal': 'VIL', 'Real Betis': 'BET', 'Sevilla': 'SEV',
        'Valencia': 'VAL', 'Celta Vigo': 'CEL', 'Getafe': 'GET',
        'Rayo Vallecano': 'RAY', 'Osasuna': 'OSA', 'Mallorca': 'MLL',
        'Bayern Munich': 'BAY', 'Borussia Dortmund': 'BVB', 'RB Leipzig': 'RBL',
        'Bayer Leverkusen': 'LEV', 'Eintracht Frankfurt': 'FRA',
        'Inter Milan': 'INT', 'AC Milan': 'ACM', 'Juventus': 'JUV',
        'Napoli': 'NAP', 'Roma': 'ROM', 'Lazio': 'LAZ', 'Atalanta': 'ATA',
        'PSG': 'PSG', 'Marseille': 'MAR', 'Lyon': 'LYO', 'Monaco': 'MON',
    }
    def short_code(name):
        return TEAM_CODES.get(name, ''.join(w[0] for w in name.split()[:3]).upper()[:3])
    live_statuses = ['LIVE', '1st Half', '2nd Half', 'Half Time', 'Extra Time', 'Penalties']
    try:
        results = []
        for league in soccer_leagues:
            try:
                url = f'https://www.thesportsdb.com/free/v1/json/3/eventsnextleague.php?id={league["id"]}'
                resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                events = data.get('events', [])
                for ev in events[:5]:
                    home = ev.get('strHomeTeam', '')
                    away = ev.get('strAwayTeam', '')
                    home_score = ev.get('intHomeScore', '')
                    away_score = ev.get('intAwayScore', '')
                    status = ev.get('strStatus', '')
                    date = ev.get('dateEvent', '')
                    time = ev.get('strTime', '')
                    badge_h = ev.get('strHomeTeamBadge', '')
                    badge_a = ev.get('strAwayTeamBadge', '')
                    if home and away:
                        is_live = status in live_statuses
                        results.append({
                            'league': league['name'],
                            'home': home,
                            'away': away,
                            'home_code': short_code(home),
                            'away_code': short_code(away),
                            'home_score': home_score,
                            'away_score': away_score,
                            'status': status,
                            'is_live': is_live,
                            'date': date,
                            'time': time,
                            'badge_h': badge_h,
                            'badge_a': badge_a,
                            'label': f'{home} vs {away}',
                        })
            except Exception:
                continue
        results.sort(key=lambda x: (0 if x['is_live'] else 1, x.get('date') or '', x.get('time') or ''))
        return jsonify({'ok': True, 'items': results[:8]})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/report-domain', methods=['POST'])
def api_report_domain():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    domain = request.form.get('domain', '').strip()
    reason = request.form.get('reason', 'Low quality').strip()[:200]
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain required'}), 400
    result = data_manager.report_domain(user_id, domain, reason)
    return jsonify({'ok': True, 'result': result})

@app.route('/admin/reports')
def admin_reports():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin.html',
        pending_reports=data_manager.get_pending_reports(),
        domain_reports=data_manager.get_pending_domain_reports(),
        verified_sites=data_manager.get_verified_sites(),
        submitted_sites=data_manager.get_submitted_sites(),
        blacklist=data_manager.get_blacklist(),
        stats=data_manager.get_stats(),
        announcement=data_manager.get_announcement(),
    )

@app.route('/admin/report/resolve', methods=['POST'])
def admin_resolve_report():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain', '').strip()
    action = request.form.get('action', '').strip()
    if domain and action in ('approved', 'dismissed'):
        data_manager.resolve_domain_report(domain, action)
    return redirect(url_for('admin_reports'))


@app.route('/admin/submission/approve', methods=['POST'])
def admin_approve_submission():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain', '').strip()
    data_manager.approve_submission(domain)
    return redirect(url_for('admin_reports'))


@app.route('/admin/accounts')
def admin_accounts():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = data_manager.get_all_users()
    user_list = []
    for u in users:
        user_list.append({
            'username': u['username'],
            'user_id': u['user_id'],
            'email': u.get('email', ''),
            'created_at': u.get('created_at', '')[:10],
            'last_active': u.get('last_active', '')[:10],
        })
    return render_template('admin_accounts.html', users=user_list)

@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = request.form.get('user_id', '').strip()
    if user_id:
        data_manager.delete_user(user_id)
    return redirect(url_for('admin_accounts'))


@app.route('/admin/collections')
def admin_collections():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    flagged = data_manager.get_flagged_collections()
    all_cols, _ = data_manager.get_collections(sort='new', page=1, per_page=100)
    return render_template('admin_collections.html', flagged=flagged, collections=all_cols)


@app.route('/admin/collections/<collection_id>/approve', methods=['POST'])
def admin_approve_collection(collection_id):
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    data_manager.approve_collection(collection_id, True)
    return redirect(url_for('admin_collections'))


@app.route('/admin/collections/<collection_id>/reject', methods=['POST'])
def admin_reject_collection(collection_id):
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    data_manager.approve_collection(collection_id, False)
    return redirect(url_for('admin_collections'))


@app.template_filter('urlencode')
def urlencode_filter(s):
    import urllib.parse
    return urllib.parse.quote(s or '')


# ── Explore / Collections routes ──

def strip_markdown(text):
    if not text:
        return ''
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    text = re.sub(r'\[([^\]]*)\]\(.*?\)', r'\1', text)
    text = re.sub(r'(?<!\*)\*{1,3}(?!\*)(.+?)(?<!\*)\*{1,3}(?!\*)', r'\1', text)
    text = re.sub(r'(?<!_)_{1,3}(?!_)(.+?)(?<!_)_{1,3}(?!_)', r'\1', text)
    text = re.sub(r'~~(.+?)~~', r'\1', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^>\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^[-*_]{3,}\s*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^[\s]*[-*+]\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'^[\s]*\d+\.\s+', '', text, flags=re.MULTILINE)
    return text.strip()



@app.route('/explore')
def explore():
    sort = request.args.get('sort', 'new')
    page = int(request.args.get('page', 1))
    threshold = data_manager.QUALITY_THRESHOLD
    all_cols, _ = data_manager.get_collections(sort='new', page=1, per_page=9999)
    quality_cols = [c for c in all_cols if c.get('quality_score', 0) >= threshold or (c.get('is_listed') and c.get('is_approved'))]
    if sort == 'new':
        quality_cols.sort(key=lambda c: c.get('created_at', ''), reverse=True)
    elif sort == 'popular':
        quality_cols.sort(key=lambda c: c.get('upvote_count', 0) + len(c.get('websites', [])), reverse=True)
    elif sort == 'updated':
        quality_cols.sort(key=lambda c: c.get('updated_at', ''), reverse=True)
    elif sort == 'top':
        quality_cols.sort(key=lambda c: c.get('quality_score', 0), reverse=True)
    total = len(quality_cols)
    per_page = 20
    start = (page - 1) * per_page
    collections = quality_cols[start:start + per_page]
    for c in collections:
        raw = c.get('description', '') or c.get('content', '')
        c['_excerpt'] = strip_markdown(raw)[:200]
    return render_template('explore.html', collections=collections, sort=sort, page=page, total=total)


@app.route('/explore/<collection_id>')
def explore_collection(collection_id):
    collection = data_manager.get_collection(collection_id)
    if not collection:
        return render_template('explore.html', error='Collection not found'), 404
    data_manager.increment_collection_views(collection_id)
    uid = session.get('user_id')
    is_owner = uid is not None and uid == collection.get('creator_id')
    content_md = collection.get('content', '')
    content_html = markdown.markdown(content_md, extensions=['fenced_code', 'codehilite', 'tables'])
    content_html = re.sub(r'@([a-zA-Z0-9_-]+)', r'<a href="/u/\1">@\1</a>', content_html)
    return render_template('collection_detail.html', collection=collection, is_owner=is_owner, content_html=content_html)


@app.route('/api/collections', methods=['GET', 'POST'])
def api_collections():
    user_id = session.get('user_id')
    if request.method == 'POST':
        if not user_id:
            return jsonify({'ok': False, 'error': 'Login required'}), 403
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        content = request.form.get('content', '').strip()
        pin_color = request.form.get('pin_color', '#800000').strip()
        transparent = request.form.get('transparent', 'false').lower() == 'true'
        bg_image = request.form.get('background_image', '').strip()
        bg_style = request.form.get('background_style', 'cover').strip()
        theme = request.form.get('theme', '').strip()
        thumbnail = request.form.get('thumbnail', '').strip()
        if not name or len(name) < 2:
            return jsonify({'ok': False, 'error': 'Name at least 2 characters'}), 400
        username = session.get('username', 'Anonymous')
        c = data_manager.create_collection(user_id, username, name, desc, content, pin_color, transparent, bg_image, bg_style, theme, thumbnail)
        return jsonify({'ok': True, 'collection': c})
    if user_id:
        cols = data_manager.get_user_collections(user_id)
    else:
        cols, _ = data_manager.get_collections(sort='new', page=1, per_page=50)
        cols = cols[:50]
    return jsonify({'ok': True, 'collections': cols})


@app.route('/api/link-meta')
def api_link_meta():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'}), 400
    try:
        import httpx
        resp = httpx.get(url, follow_redirects=True, timeout=8,
                         headers={'User-Agent': 'Mozilla/5.0 (compatible; arlong-bot/1.0)'})
        if resp.status_code != 200:
            return jsonify({'ok': False, 'error': 'Failed to fetch'}), 400
        html = resp.text
        title = url
        desc = ''
        image = ''
        import re
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if m:
            title = m.group(1).strip()[:200]
        m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            title = m.group(1).strip()[:200]
        m = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            desc = m.group(1).strip()[:300]
        m = re.search(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            image = m.group(1).strip()[:500]
        # Fallback: first large image
        if not image:
            m = re.search(r'<img[^>]+src=["\']([^"\']+\.(?:jpg|jpeg|png|webp)[^"\']*)["\']', html, re.IGNORECASE)
            if m:
                image = m.group(1).strip()[:500]
        # Get favicon
        favicon = ''
        m = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            favicon = m.group(1).strip()
        if not favicon:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            favicon = f'{parsed.scheme}://{parsed.netloc}/favicon.ico'
        return jsonify({'ok': True, 'title': title, 'description': desc, 'image': image, 'favicon': favicon})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def api_upload():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file provided'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'ok': False, 'error': 'Empty filename'}), 400
    import mimetypes
    allowed = ('image/jpeg', 'image/png', 'image/webp', 'image/gif')
    if f.mimetype not in allowed:
        ct = f.mimetype or mimetypes.guess_type(f.filename)[0] or ''
        if ct not in allowed:
            return jsonify({'ok': False, 'error': 'Only JPEG, PNG, WebP, GIF allowed'}), 400
    ext = {'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif'}.get(f.mimetype, '.jpg')
    import uuid
    filename = str(uuid.uuid4()) + ext
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    f.save(os.path.join(upload_dir, filename))
    url = f'/static/uploads/{filename}'
    return jsonify({'ok': True, 'url': url})


@app.route('/api/collections/<collection_id>', methods=['PUT', 'DELETE'])
def api_collection(collection_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    if request.method == 'PUT':
        kwargs = {}
        for k in ['name','description','content','pin_color','background_image','background_style','theme','thumbnail']:
            v = request.form.get(k)
            if v is not None:
                kwargs[k] = v.strip() if isinstance(v, str) else v
        pinned_links = request.form.get('pinned_links')
        if pinned_links is not None:
            import json as _json
            try:
                kwargs['pinned_links'] = _json.loads(pinned_links)
            except: pass
        transparent = request.form.get('transparent')
        if transparent is not None:
            kwargs['transparent'] = transparent.lower() == 'true'
        is_public = request.form.get('is_public')
        if is_public is not None:
            kwargs['is_public'] = is_public.lower() == 'true'
        c = data_manager.update_collection(collection_id, user_id, **kwargs)
        if not c:
            return jsonify({'ok': False, 'error': 'Not found or not yours'}), 404
        return jsonify({'ok': True, 'collection': c})
    if request.method == 'DELETE':
        data_manager.delete_collection(collection_id, user_id)
        return jsonify({'ok': True})


@app.route('/api/collections/<collection_id>/websites', methods=['POST'])
def api_collection_add_website(collection_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    url = request.form.get('url', '').strip()
    title = request.form.get('title', '').strip()
    note = request.form.get('note', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'}), 400
    if not note or len(note) < 10:
        return jsonify({'ok': False, 'error': 'Explanation required (min 10 characters) — tell why this link is valuable'}), 400
    w, err = data_manager.add_website_to_collection(collection_id, user_id, url, title, note)
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True, 'website': w})


@app.route('/api/collections/<collection_id>/websites/<website_id>', methods=['DELETE'])
def api_collection_remove_website(collection_id, website_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    ok = data_manager.remove_website_from_collection(collection_id, user_id, website_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    return jsonify({'ok': True})


@app.route('/api/collections/<collection_id>/flag', methods=['POST'])
def api_flag_collection(collection_id):
    ok = data_manager.flag_collection(collection_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    return jsonify({'ok': True})


@app.route('/api/collections/<collection_id>/upvote', methods=['POST'])
def api_upvote_collection(collection_id):
    ok = data_manager.upvote_collection(collection_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    return jsonify({'ok': True, 'msg': 'Upvoted'})


@app.route('/api/collections/<collection_id>/pin-link', methods=['POST'])
def api_pin_link(collection_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    website_id = request.form.get('website_id', '').strip()
    if not website_id:
        return jsonify({'ok': False, 'error': 'Website ID required'}), 400
    ok, action = data_manager.toggle_pin_link(collection_id, user_id, website_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    return jsonify({'ok': True, 'action': action})


@app.route('/api/collections/<collection_id>/reorder', methods=['POST'])
def api_reorder_links(collection_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    import json as _json
    try:
        website_ids = _json.loads(request.form.get('website_ids', '[]'))
    except:
        return jsonify({'ok': False, 'error': 'Invalid website_ids'}), 400
    if not isinstance(website_ids, list):
        return jsonify({'ok': False, 'error': 'website_ids must be a list'}), 400
    ok = data_manager.reorder_websites(collection_id, user_id, website_ids)
    if not ok:
        return jsonify({'ok': False, 'error': 'Not found or not yours'}), 404
    return jsonify({'ok': True})





@app.route('/collections')
def user_collections():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    cols = data_manager.get_user_collections(user_id)
    return render_template('explore.html', collections=cols, sort='mine', total=len(cols))

# ── User profile ──

@app.route('/u/<username>')
def user_profile(username):
    profile = data_manager.get_user_profile(username)
    if not profile:
        return render_template('user_profile.html', profile=None, error='User not found'), 404
    profile['is_owner'] = session.get('username') == username
    if profile['is_owner']:
        user = data_manager.get_user_by_id(session.get('user_id'))
        profile['email'] = user.get('email', '') if user else ''
    else:
        profile['email'] = ''
    return render_template('user_profile.html', profile=profile)


@app.route('/api/user/update-settings', methods=['POST'])
def api_user_update_settings():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    action = request.form.get('action', '')
    if action == 'email':
        email = request.form.get('email', '').strip()
        current = request.form.get('current_password', '')
        if not email or '@' not in email:
            return jsonify({'ok': False, 'error': 'Valid email required'}), 400
        if not current:
            return jsonify({'ok': False, 'error': 'Current password required'}), 400
        user = data_manager.get_user_by_id(user_id)
        if not user or not data_manager.check_password(current, user['password_hash']):
            return jsonify({'ok': False, 'error': 'Current password is incorrect'}), 403
        ok, err = data_manager.update_user_email(user_id, email)
        return jsonify({'ok': ok, 'error': err})
    elif action == 'password':
        current = request.form.get('current_password', '')
        newpass = request.form.get('new_password', '')
        if not current or not newpass:
            return jsonify({'ok': False, 'error': 'Both passwords required'}), 400
        ok, err = data_manager.update_user_password(user_id, current, newpass)
        return jsonify({'ok': ok, 'error': err})
    elif action == 'weather_location':
        wl = request.form.get('weather_location', '').strip()
        ok = data_manager.update_user_weather_location(user_id, wl)
        return jsonify({'ok': ok, 'error': None if ok else 'Failed to update'})
    elif action == 'bio':
        bio = request.form.get('bio', '').strip()
        ok = data_manager.update_user_bio(user_id, bio)
        return jsonify({'ok': ok, 'error': None if ok else 'Failed to update'})
    elif action == 'delete_account':
        current = request.form.get('current_password', '')
        if not current:
            return jsonify({'ok': False, 'error': 'Password required to delete account'}), 400
        user = data_manager.get_user_by_id(user_id)
        if not user or not data_manager.check_password(current, user['password_hash']):
            return jsonify({'ok': False, 'error': 'Incorrect password'}), 403
        data_manager.delete_user(user_id)
        session.clear()
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Unknown action'}), 400


@app.route('/api/user/preferences', methods=['GET', 'POST'])
def api_user_preferences():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    if request.method == 'GET':
        prefs = data_manager.get_user_preferences(user_id)
        return jsonify({'ok': True, 'preferences': prefs})
    prefs = request.get_json(silent=True) or {}
    allowed_keys = {'ai_summary', 'trending_country'}
    filtered = {k: v for k, v in prefs.items() if k in allowed_keys}
    ok = data_manager.update_user_preferences(user_id, filtered)
    return jsonify({'ok': ok})


# ── Premium ──

if scheduler_available:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        _create_backup,
        IntervalTrigger(hours=24),
        id='daily_backup',
        name='Daily data backup',
        replace_existing=True,
    )
    scheduler.start()
    app.logger.info("Scheduler started: daily backup")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
