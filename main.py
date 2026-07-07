from flask import Flask, render_template, request, jsonify, abort, session, redirect, url_for
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
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import boto3
    from botocore.exceptions import ClientError
    s3_available = True
except ImportError:
    s3_available = False
from datetime import datetime, timedelta
import hashlib
import secrets
import uuid
import re
import threading
import os
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

app.secret_key = os.environ.get('SECRET_KEY', 'arlong-secret-key-change-in-prod')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
AMAZON_ASSOCIATE_TAG = os.environ.get('AMAZON_ASSOCIATE_TAG', '')

@app.after_request
def add_cors_headers(response):
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
    def __init__(self, title, url, snippet, category='general', date=None, favicon=None, domain=None):
        self.title = title
        self.url = url
        self.snippet = snippet
        self.category = category
        self.date = date
        self.favicon = favicon or f"https://www.google.com/s2/favicons?domain={url}"
        self.score = 0
        self.domain = domain or urlparse(url).netloc if url else ''

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
            'domain': self.domain
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

def detect_user_country():
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

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.json')

def _load_json():
    if S3_ENABLED and s3_client:
        try:
            resp = s3_client.get_object(Bucket=S3_BUCKET, Key=S3_DATA_KEY)
            return json.loads(resp['Body'].read().decode('utf-8'))
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return None
            app.logger.error(f"S3 load error: {e}")
            return None
        except Exception as e:
            app.logger.error(f"S3 load error: {e}")
            return None
    else:
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, 'r') as f:
                    return json.load(f)
            except:
                return None
        return None

def _save_json(data):
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

class DataManager:
    def __init__(self):
        self._lock = threading.Lock()
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
                'crawl_status': 'pending', 'pages_crawled': 0
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

    def update_crawl_status(self, domain, status, pages_crawled=None):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for site in self.data.get('submitted_sites', []):
                if site['domain'] == domain:
                    site['crawl_status'] = status
                    if pages_crawled is not None:
                        site['pages_crawled'] = pages_crawled
                    _save_json(self.data)
                    return True
            return False

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
                    s['crawl_status'] = 'approved'
                    _save_json(self.data)
                    return True
            return False

    def store_crawled_pages(self, domain, pages):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('crawled_pages', [])
            self.data['crawled_pages'] = [p for p in self.data['crawled_pages'] if p['domain'] != domain]
            for page in pages:
                entry = {
                    'domain': domain,
                    'url': page.get('url', ''),
                    'title': page.get('title', '')[:300],
                    'description': page.get('description', '')[:500],
                    'text': page.get('text', '')[:5000],
                    'indexed_at': datetime.now().isoformat(),
                }
                self.data['crawled_pages'].append(entry)
            _save_json(self.data)

    def get_all_crawled_pages(self):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            return list(self.data.get('crawled_pages', []))

    def search_crawled_pages(self, query):
        pages = self.get_all_crawled_pages()
        if not pages or not query:
            return []
        query_terms = query.lower().split()
        scored = []
        for p in pages:
            text = (p.get('title', '') + ' ' + p.get('description', '') + ' ' + p.get('text', '')).lower()
            matches = sum(1 for t in query_terms if t in text)
            if matches:
                title = p.get('title', '')
                snippet = p.get('description', '')[:200]
                if not snippet:
                    idx = text.find(query_terms[0])
                    if idx > 0:
                        snippet = p.get('text', '')[max(0, idx-50):idx+150]
                scored.append({
                    'title': title or p.get('url', ''),
                    'url': p.get('url', ''),
                    'snippet': snippet,
                    'domain': p.get('domain', ''),
                    'score': matches / len(query_terms) * 15,
                    'engine': 'kumo',
                    'category': 'general',
                })
        scored.sort(key=lambda x: x['score'], reverse=True)
        return scored[:5]

    # ── Community system: users, votes, domain reports ──

    def hash_password(self, password):
        salt = secrets.token_hex(8)
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{salt}:{h}"

    def check_password(self, password, stored):
        try:
            salt, h = stored.split(':', 1)
            return hashlib.sha256((salt + password).encode()).hexdigest() == h
        except:
            return False

    def hash_ip(self, ip):
        return hashlib.sha256(ip.encode()).hexdigest()[:16]

    def create_user(self, username, password, security_question, security_answer, ip):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('users', [])
            if any(u['username'] == username for u in self.data['users']):
                return None, 'Username taken'
            user = {
                'user_id': str(uuid.uuid4()),
                'username': username,
                'password_hash': self.hash_password(password),
                'security_question': security_question,
                'security_answer_hash': self.hash_password(security_answer),
                'ip_hashes': [self.hash_ip(ip)],
                'created_at': datetime.now().isoformat(),
                'last_action_at': None,
            }
            self.data['users'].append(user)
            _save_json(self.data)
            return user, None

    def authenticate_user(self, username, password):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        users = self.data.get('users', [])
        for u in users:
            if u['username'] == username:
                if self.check_password(password, u['password_hash']):
                    return u
        return None

    def get_user_by_id(self, user_id):
        for u in self.data.get('users', []):
            if u['user_id'] == user_id:
                return u
        return None

    def record_user_action(self, user_id, ip):
        with self._lock:
            users = self.data.get('users', [])
            for u in users:
                if u['user_id'] == user_id:
                    u['last_action_at'] = datetime.now().isoformat()
                    ip_h = self.hash_ip(ip)
                    if ip_h not in u['ip_hashes']:
                        u['ip_hashes'].append(ip_h)
                    _save_json(self.data)
                    return

    def get_user_cooldown(self, user_id):
        for u in self.data.get('users', []):
            if u['user_id'] == user_id:
                last = u.get('last_action_at')
                if not last:
                    return 0, 'ok'
                elapsed = (datetime.now() - datetime.fromisoformat(last)).total_seconds()
                if elapsed < 11:
                    return 11 - elapsed, 'initial wait'
                if elapsed < 70:
                    return 70 - elapsed, 'post cooldown'
                return 0, 'ok'
        return 0, 'ok'

    def cast_vote(self, user_id, url, vote):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('votes', [])
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            for v in self.data['votes']:
                if v['user_id'] == user_id and v['url_hash'] == url_hash:
                    if v['vote'] == vote:
                        return 'same'
                    v['vote'] = vote
                    v['updated_at'] = datetime.now().isoformat()
                    _save_json(self.data)
                    return 'updated'
            self.data['votes'].append({
                'user_id': user_id,
                'url': url,
                'url_hash': url_hash,
                'vote': vote,
                'created_at': datetime.now().isoformat(),
            })
            _save_json(self.data)
            return 'cast'

    def get_vote_score(self, url):
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        up = sum(1 for v in self.data.get('votes', []) if v['url_hash'] == url_hash and v['vote'] == 1)
        down = sum(1 for v in self.data.get('votes', []) if v['url_hash'] == url_hash and v['vote'] == -1)
        return up - down, up, down

    def get_user_vote(self, user_id, url):
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        for v in self.data.get('votes', []):
            if v['user_id'] == user_id and v['url_hash'] == url_hash:
                return v['vote']
        return 0

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

    def create_collection(self, user_id, username, name, description):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data.setdefault('collections', [])
            c = {
                'id': str(uuid.uuid4()),
                'name': name[:100],
                'description': description[:500] if description else '',
                'creator_id': user_id,
                'creator_name': username,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'websites': [],
            }
            self.data['collections'].append(c)
            _save_json(self.data)
            return c

    def get_collections(self, sort='new', page=1, per_page=20):
        cols = list(self.data.get('collections', []))
        if sort == 'new':
            cols.sort(key=lambda c: c.get('created_at', ''), reverse=True)
        elif sort == 'popular':
            cols.sort(key=lambda c: len(c.get('websites', [])), reverse=True)
        elif sort == 'updated':
            cols.sort(key=lambda c: c.get('updated_at', ''), reverse=True)
        total = len(cols)
        start = (page - 1) * per_page
        return cols[start:start + per_page], total

    def get_collection(self, collection_id):
        for c in self.data.get('collections', []):
            if c['id'] == collection_id:
                return c
        return None

    def get_user_collections(self, user_id):
        return [c for c in self.data.get('collections', []) if c['creator_id'] == user_id]

    def update_collection(self, collection_id, user_id, name, description):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id and c['creator_id'] == user_id:
                    if name:
                        c['name'] = name[:100]
                    if description is not None:
                        c['description'] = description[:500]
                    c['updated_at'] = datetime.now().isoformat()
                    _save_json(self.data)
                    return c
            return None

    def delete_collection(self, collection_id, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            self.data['collections'] = [c for c in self.data.get('collections', [])
                                        if not (c['id'] == collection_id and c['creator_id'] == user_id)]
            _save_json(self.data)
            return True

    def add_website_to_collection(self, collection_id, user_id, url, title, note):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
            for c in self.data.get('collections', []):
                if c['id'] == collection_id:
                    if any(w['url'] == url for w in c.get('websites', [])):
                        return None, 'Already in collection'
                    w = {
                        'id': str(uuid.uuid4()),
                        'url': url,
                        'title': title[:200] if title else url,
                        'note': note[:300] if note else '',
                        'added_by': user_id,
                        'added_at': datetime.now().isoformat(),
                    }
                    c.setdefault('websites', []).append(w)
                    c['updated_at'] = datetime.now().isoformat()
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
                    _save_json(self.data)
                    return True
            return False

    # ── User stats / profile ──

    def get_user_points(self, user_id):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        collections = [c for c in self.data.get('collections', []) if c['creator_id'] == user_id]
        collections_count = len(collections)
        pins_count = sum(len(c.get('websites', [])) for c in collections)
        submissions_count = sum(1 for s in self.data.get('submitted_sites', []) if s.get('submitted_by') == user_id and s.get('crawl_status') in ('approved', 'completed'))
        upvotes_count = sum(1 for v in self.data.get('votes', []) if v['user_id'] == user_id and v['vote'] == 1)
        return collections_count * 2 + pins_count * 2 + submissions_count * 4 + upvotes_count * 3

    def get_leaderboard(self, limit=50):
        with self._lock:
            loaded = _load_json()
            if loaded:
                self.data = loaded
        users = self.data.get('users', [])
        scored = []
        for u in users:
            uid = u['user_id']
            pts = self.get_user_points(uid)
            if pts > 0:
                scored.append((pts, u['username'], u.get('created_at', '')))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{'rank': i+1, 'username': s[1], 'score': s[0], 'joined': s[2][:10]} for i, s in enumerate(scored[:limit])]

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
        pins_count = sum(len(c.get('websites', [])) for c in self.data.get('collections', []) if c['creator_id'] == user_id)
        votes_given = sum(1 for v in self.data.get('votes', []) if v['user_id'] == user_id and v['vote'] == 1)
        submissions_count = sum(1 for s in self.data.get('submitted_sites', []) if s.get('submitted_by') == user_id and s.get('crawl_status') in ('approved', 'completed'))
        reports_approved = sum(1 for r in self.data.get('domain_reports', []) if user_id in r.get('reported_by', []) and r.get('status') == 'approved')
        points = collections_count * 2 + pins_count * 2 + submissions_count * 4 + votes_given * 3

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

        return {
            'username': username,
            'created_at': user.get('created_at', ''),
            'points': points,
            'collections_count': collections_count,
            'pins_count': pins_count,
            'submissions_count': submissions_count,
            'reports_approved': reports_approved,
            'votes_given': votes_given,
            'recent': recent,
        }


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

    def crawl_page(self, url):
        try:
            resp = self.session.get(url, timeout=8)
            if resp.status_code != 200:
                return None
            soup = BeautifulSoup(resp.text, 'html.parser')
            title = soup.title.get_text(strip=True) if soup.title else ''
            desc = ''
            meta = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
            if meta:
                desc = meta.get('content', '')[:300]
            text = soup.get_text(separator=' ', strip=True)[:5000]
            return {'title': title, 'description': desc, 'text': text, 'url': url}
        except Exception:
            return None

    def crawl_site(self, domain, sitemap_url=None):
        result = {'domain': domain, 'pages': [], 'sitemap_url': None, 'error': None}
        if sitemap_url:
            urls, err = self.fetch_sitemap(sitemap_url)
            if err:
                result['error'] = f"Sitemap error: {err}"
            elif urls:
                result['sitemap_url'] = sitemap_url
                for url in urls[:50]:
                    page = self.crawl_page(url)
                    if page:
                        result['pages'].append(page)
            else:
                result['error'] = "No URLs found in sitemap"
        if not result['pages']:
            homepage = self.crawl_page(f'https://{domain}')
            if homepage:
                result['pages'].append(homepage)
        return result


kumo = KumoCrawler()

# Entity detection for cross-entity penalty in ranking (deprecated, kept for reference)
BANK_ENTITIES = {
}

def _detect_query_entity(query):
    return None

def _detect_domain_entity(domain):
    return None


def _search_google(query, max_results=5, region=None):
    return []


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
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.search_urls = []
        if ddgs_available:
            self.ddgs = DDGS()
            self.search_urls.append("ddgs://text")
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

    def _fetch_with_retry(self, url, params, max_retries=2, backoff_factor=0.3):
        """Enhanced fetch with exponential backoff"""
        last_exception = None

        for attempt in range(max_retries):
            try:
                # Add jitter to avoid detection
                delay = (backoff_factor * (2 ** attempt)) + random.uniform(0.1, 0.3)
                time.sleep(delay)

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
                    time.sleep(delay * 2)  # Additional delay for rate limits
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
            exact_match_bonus = 40
            title_start_ratio = title_lower.find(query_lower) / max(len(title_lower), 1)
            if title_start_ratio < 0.3:
                exact_match_bonus += 15

        phrase_in_title = 0
        for i in range(len(query_terms)):
            for j in range(i + 2, min(i + 5, len(query_terms) + 1)):
                phrase = ' '.join(query_terms[i:j])
                if len(phrase) > 4 and phrase in title_lower:
                    phrase_in_title = max(phrase_in_title, len(phrase.split()))

        matching_terms = sum(1 for t in query_terms if t in title_lower)
        term_ratio = matching_terms / max(len(query_terms), 1)

        score = exact_match_bonus
        score += phrase_in_title * 8

        if matching_terms == len(query_terms) and not exact_match_bonus:
            score += 20

        short_title_penalty = max(0, 8 - len(result.title.split())) * 1.5
        score -= short_title_penalty

        title_is_list = bool(re.search(r'^\d+\s', title_lower))
        if title_is_list:
            score -= 5

        # Age/year number detection — boost when query mentions age and title matches
        age_nums = re.findall(r'\b(\d{1,2})\b', query_lower)
        if age_nums and ('year' in query_lower or 'yr' in query_lower or 'old' in query_lower):
            for num in age_nums:
                if num in title_lower:
                    score += 15
                if f'{num} year' in title_lower or f'{num} yr' in title_lower:
                    score += 25

        return max(0, score)

    def _score_domain_authority(self, url):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)

        # Check hardcoded domain authority first (authoritative overrides)
        for known_domain, authority in DOMAIN_AUTHORITY.items():
            if known_domain in domain or domain.endswith('.' + known_domain):
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

        return max(0, score)

    def _score_freshness(self, result):
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

        for term in query_terms:
            if len(term) <= 2:
                continue
            if any(term == part for part in domain_parts):
                return 80
            if any(term in part for part in domain_parts):
                return 40
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

    def _rank_results(self, query, results, filter_type='general'):
        intent = SearchIntent(query)
        blacklist = data_manager.get_blacklist()

        scored = []
        for result in results:
            s = 0

            s += self._score_title_match(query, intent, result) * 0.22
            s += self._score_snippet_relevance(query, intent, result) * 0.16
            s += self._score_domain_authority(result.url) * 0.14
            s += self._score_exact_domain_match(query, result) * 0.10
            s += self._score_url_quality(query, result.url) * 0.06
            s += self._score_freshness(result) * 0.08
            s += self._score_category_relevance(query, intent, result) * 0.06
            s += self._score_content_quality(result) * 0.11
            s += self._score_reddit_boost(query, intent, result) * 0.07
            s += self._score_navigational_domain_boost(query, result)
            s += self._score_answer_quality(query, result.snippet) * 0.08
            s += self._score_snippet_substance(result.snippet) * 0.07
            s += self._score_clickbait_penalty(result.title)
            s += self._score_title_naturalness(result.title)
            s += self._score_url_depth_penalty(result.url)
            s += self._score_academic_boost(query, intent, result)

            domain = urlparse(result.url).netloc.lower()
            domain = re.sub(r'^www\.', '', domain)
            for bl_domain, bl_penalty in blacklist.items():
                if bl_domain in domain:
                    s += bl_penalty

            s = max(0, s)

            if filter_type == 'shopping':
                if any(d in domain for d in ['amazon.', 'bestbuy.', 'walmart.', 'newegg.', 'target.', 'etsy.', 'ebay.', 'shop.', 'store.', 'costco.']):
                    s += 30
                if result.category == 'shopping':
                    s += 20
            elif filter_type == 'official':
                if any(d in domain for d in ['.org', '.gov', '.edu']) or any(d in domain for d in ['apple.com', 'microsoft.com', 'google.com', 'github.com']):
                    s += 30
                if result.category == 'official':
                    s += 20
            elif filter_type == 'tutorials':
                title_lower = result.title.lower() if result.title else ''
                if result.category == 'tutorial' or 'tutorial' in title_lower or 'guide' in title_lower or 'how to' in title_lower or 'documentation' in title_lower or 'docs' in title_lower:
                    s += 25
                if any(d in title_lower for d in ['learn', 'course', 'example', 'reference']):
                    s += 15
            elif filter_type == 'discussions':
                url_lower = result.url.lower() if result.url else ''
                title_lower = result.title.lower() if result.title else ''
                if 'reddit' in url_lower or 'forum' in url_lower or 'stackexchange' in url_lower or 'discuss' in url_lower or result.category == 'discussion' or result.category == 'social':
                    s += 30
                if any(d in title_lower for d in ['vs', 'review', 'recommend', 'opinion', 'best', 'thoughts', 'experience']):
                    s += 15
            elif filter_type == 'academic':
                url_lower = result.url.lower() if result.url else ''
                title_lower = result.title.lower() if result.title else ''
                snippet_lower = result.snippet.lower() if result.snippet else ''
                if '.edu' in url_lower or '.ac.' in url_lower or result.category == 'academic':
                    s += 40
                if any(d in title_lower + snippet_lower for d in ['research', 'study', 'paper', 'journal', 'scholar', 'arxiv', 'pubmed', 'doi', 'citation', 'peer review']):
                    s += 30

            result.score = round(s, 2)
            scored.append(result)

        # Neural network evaluation: score non-discussion sites with ML model
        try:
            from ml_ranking import get_ranker
            ranker = get_ranker()
            if ranker.available:
                discussion_results = []
                neural_results = []
                for r in scored:
                    if self._is_discussion_site(r.url):
                        discussion_results.append(r)
                    else:
                        neural_results.append(r)

                if neural_results:
                    docs = [{'title': r.title or '', 'snippet': r.snippet or '', 'url': r.url or ''} for r in neural_results]
                    ml_scores = ranker.predict(query, docs)
                    min_m, max_m = min(ml_scores), max(ml_scores)
                    m_range = max_m - min_m if max_m > min_m else 1
                    for i, r in enumerate(neural_results):
                        ml = ml_scores[i] if i < len(ml_scores) else 0.0
                        r.score = ((ml - min_m) / m_range) * 100  # Normalize ML score to 0-100

                for r in discussion_results:
                    r.score = min(r.score, 10)  # Cap discussion/heuristic scores
        except Exception as e:
            app.logger.error(f"Neural ranking error: {e}")

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
                domain = '.'.join(parts[-2:]) if len(parts[-1]) <= 3 and len(parts) > 2 else '.'.join(parts[-2:])
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
            threshold = deduplicated[0].score * 0.08
            deduplicated = [r for r in deduplicated if r.score >= threshold]

        return deduplicated[:50]

    def _parse_duckduckgo_results(self, html):
        results = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for div in soup.find_all('div', class_='result'):
                try:
                    title_elem = div.select_one('.result__a')
                    if not title_elem:
                        continue
                    title = title_elem.get_text(strip=True)

                    url = title_elem.get('href', '')
                    if not url:
                        continue

                    if SearchBlocker.is_ad(url, title, ''):
                        continue

                    snippet_elem = div.select_one('.result__snippet')
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''

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

    def _search_single_engine(self, search_url, query, page, region=None):
        try:
            if search_url == 'ddgs://text':
                if not self.ddgs:
                    return []
                try:
                    ddgs_kwargs = dict(query=query, max_results=30, backend='auto', safesearch='on')
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
            elif 'duckduckgo' in search_url:
                all_results = []
                offsets = [0, 30, 60]
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

        # 2. Wikipedia API (free, no key needed)
        if len(results) < 10:
            try:
                r = self.session.get('https://en.wikipedia.org/w/api.php', params={
                    'action': 'query', 'list': 'search', 'srsearch': query,
                    'format': 'json', 'srlimit': 15
                }, headers=self._get_headers(), timeout=8)
                if r and r.status_code == 200:
                    data = r.json()
                    for item in data.get('query', {}).get('search', []):
                        title = item.get('title', '')
                        url = f'https://en.wikipedia.org/wiki/{quote_plus(title.replace(" ", "_"))}'
                        if url in seen:
                            continue
                        seen.add(url)
                        raw = item.get('snippet', '')
                        snippet = BeautifulSoup(raw, 'html.parser').get_text(strip=True)[:200]
                        results.append(SearchResult(
                            title=title, url=url, snippet=snippet,
                            category='general', domain='en.wikipedia.org'
                        ))
                        if len(results) >= 25:
                            break
            except Exception as e:
                app.logger.error(f"Fallback Wikipedia error: {e}")

        # 3. Wayback Machine as last resort
        if len(results) < 5:
            try:
                r = self.session.get('https://archive.org/advancedsearch.php', params={
                    'q': query, 'output': 'json', 'rows': 10,
                    'fl': 'identifier,title,description,url'
                }, headers=self._get_headers(), timeout=15)
                if r and r.status_code == 200:
                    data = r.json()
                    for item in data.get('response', {}).get('docs', []):
                        id_ = item.get('identifier', '')
                        title = item.get('title', '') or id_
                        if not id_:
                            continue
                        url = f'https://archive.org/details/{id_}'
                        if url in seen:
                            continue
                        seen.add(url)
                        desc_raw = item.get('description', '') or ''
                        if isinstance(desc_raw, list):
                            desc_raw = ' '.join(str(s) for s in desc_raw)
                        results.append(SearchResult(
                            title=title, url=url, snippet=str(desc_raw)[:200],
                            category='general', domain='archive.org'
                        ))
            except Exception as e:
                app.logger.error(f"Fallback Wayback error: {e}")

        return results

    def search(self, query, page=1, filter_type='general', region=None):
        """Main search method with pagination and fallback"""
        self._current_region = region
        per_page = 10
        cache_key = self._get_cache_key(f"{query}_{filter_type}_{region or 'all'}", 1)
        cached_all = self._get_from_cache(cache_key)
        all_results = None

        if cached_all:
            all_results = cached_all
        else:
            results = []
            errors = []

            futures = []
            for search_url in self.search_urls:
                future = self.executor.submit(self._search_single_engine, search_url, query, page, region)
                futures.append(future)

            try:
                for future in as_completed(futures, timeout=10):
                    try:
                        current_results = future.result()
                        results.extend(current_results)
                        if len(results) >= 30:
                            break
                    except Exception as e:
                        errors.append(str(e))
                        continue
            except TimeoutError:
                app.logger.warning(f"Search timed out for query: {query[:50]}")

            if not results:
                app.logger.warning("Primary search failed, trying fallback sources...")
                results = self._search_fallback(query, region)

            if results:
                ranked_results = self._rank_results(query, results, filter_type)
                all_results = [result.to_dict() for result in ranked_results]
                self._save_to_cache(cache_key, all_results)

        # Merge locally indexed crawled pages into results
        if data_manager:
            try:
                crawled = data_manager.search_crawled_pages(query)
                for c in crawled:
                    c['type'] = 'regular'
                    c['favicon'] = f"https://www.google.com/s2/favicons?domain={c.get('domain', '')}"
                    c['display_url'] = c['url'][:60] + '...' if len(c['url']) > 60 else c['url']
                    all_results.append(c)
            except Exception as e:
                app.logger.error(f"Crawled pages search error: {e}")

        if not all_results:
            return [], 0

        total = len(all_results)
        start = (page - 1) * per_page
        end = start + per_page
        page_results = all_results[start:end]

        return page_results, total

    def ml_rerank(self, query, results, mode='blend_light'):
        try:
            from ml_ranking import get_ranker
            ranker = get_ranker()
            if not ranker.available:
                return results
            top = [r for r in results[:20]]
            if not top:
                return results
            docs = []
            for r in top:
                title = r.get('title', '') or ''
                snippet = r.get('snippet', '') or ''
                url = r.get('url', '') or ''
                docs.append({'title': title, 'snippet': snippet, 'url': url})
            scores = ranker.predict(query, docs)

            heur_scores = [r.get('score', 0) for r in top]
            min_h, max_h = min(heur_scores), max(heur_scores)
            min_m, max_m = min(scores), max(scores)
            h_range = max_h - min_h if max_h > min_h else 1
            m_range = max_m - min_m if max_m > min_m else 1

            for i, r in enumerate(top):
                ml_score = scores[i] if i < len(scores) else 0.0
                old_score = r.get('score', 0)

                if mode == 'blend_strong':
                    new_score = old_score + ml_score
                elif mode == 'pure_ml':
                    ml_norm = (ml_score - min_m) / m_range
                    new_score = ml_norm * 100
                elif mode == 'norm_50':
                    h_norm = (old_score - min_h) / h_range
                    m_norm = (ml_score - min_m) / m_range
                    new_score = (h_norm * 50 + m_norm * 50)
                else:
                    new_score = old_score + ml_score * 0.15

                r['score'] = round(new_score, 2)
                r['ml_score'] = round(ml_score, 4)
            results.sort(key=lambda x: x.get('score', 0), reverse=True)
        except Exception as e:
            app.logger.error(f"ML rerank error: {e}")
        return results

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
                    images.append({'thumbnail': thumb, 'title': title or dom or query, 'source_url': src, 'source_domain': dom or 'image'})
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
                            images.append({'thumbnail': turl, 'title': title[:100] or dom or query, 'source_url': purl or '#', 'source_domain': dom or 'image'})
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
                                images.append({'thumbnail': thumb, 'title': title or dom or query, 'source_url': src, 'source_domain': dom or 'image'})
                                if len(images) >= 50:
                                    break
                            except:
                                continue
            except Exception as e:
                app.logger.error(f"DDG images fallback: {e}")

        return images[:50]

    def search_videos(self, query):
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

        return videos

    def get_suggestions(self, query):
        """Get search suggestions with error handling"""
        if not query or len(query) < 2:
            return []

        cache_key = f"suggest_{query}"
        cached_suggestions = self._get_from_cache(cache_key)

        if cached_suggestions:
            return cached_suggestions

        # 1. DuckDuckGo suggest API (may be blocked on some hosts)
        try:
            r = self.session.get(
                'https://duckduckgo.com/ac/',
                params={'q': query, 'type': 'list'},
                timeout=3
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

        # 2. Google suggest API (fallback, works on most hosts)
        try:
            r = self.session.get(
                'https://suggestqueries.google.com/complete/search',
                params={'q': query, 'client': 'firefox', 'hl': 'en'},
                timeout=3
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

        return []

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
            'prop': 'extracts|pageimages|info',
            'exintro': 1,
            'explaintext': 1,
            'pithumbsize': 300,
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
        extract = page.get('extract', '')[:400]
        thumb_url = None
        thumb = page.get('thumbnail')
        if thumb:
            thumb_url = thumb.get('source')
        page_url = page.get('fullurl', f'https://en.wikipedia.org/wiki/{title.replace(" ", "_")}')
        panel = {
            'title': title,
            'image': thumb_url,
            'type': 'Wikipedia article',
            'description': extract,
            'facts': [
                ('Source', 'Wikipedia'),
                ('Read more', page_url),
            ],
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
    weather = get_weather_panel(query)
    if weather:
        return weather
    definition = get_definition_panel(query)
    if definition:
        return definition
    if results:
        wiki_panel = get_wiki_panel_from_results(results)
        if wiki_panel:
            return wiki_panel
    query_lower = query.lower().strip()
    for key, panel in KNOWLEDGE_PANELS.items():
        if key in query_lower:
            return panel
    media = get_media_panel(query)
    if media:
        return media
    wiki_panel = get_wikipedia_panel(query)
    if wiki_panel:
        return wiki_panel
    return None

def detect_news(query):
    q = query.lower().strip()
    if q.startswith('news '):
        return {'topic': q[5:].strip(), 'intent': 'news'}
    if q.startswith('latest news '):
        return {'topic': q[12:].strip(), 'intent': 'news'}
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

@app.route('/')
def home():
    announcement = data_manager.get_announcement()
    ml_val = request.args.get('ml', '')
    if 'user_country' not in session:
        country_code, raw_cc = detect_user_country()
        session['user_country'] = country_code or ''
    return render_template('search.html', celebration=data_manager.get_celebration(), announcement=announcement, ml_rank=bool(ml_val) and ml_val != '0', blocked_count=BLOCKLIST_COUNT, user_country=session.get('user_country', ''), country_name=COUNTRY_NAMES.get(session.get('user_country', ''), ''))

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    filter_type = request.args.get('filter', 'general')
    if filter_type not in ('general', 'shopping', 'official', 'tutorials', 'discussions', 'academic'):
        filter_type = 'general'
    ml_rank = request.args.get('ml', '')
    region = request.args.get('region', session.get('region', ''))

    if 'user_country' not in session:
        country_code, raw_cc = detect_user_country()
        session['user_country'] = country_code or ''
    user_country = session.get('user_country', '')

    announcement = data_manager.get_announcement()
    if not query:
        return render_template('search.html', celebration=data_manager.get_celebration(), announcement=announcement, blocked_count=BLOCKLIST_COUNT, user_country=user_country, country_name=COUNTRY_NAMES.get(user_country, ''))

    crisis = detect_crisis(query)

    if crisis and crisis['type'] in ('harmful', 'crisis'):
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
            country_name=COUNTRY_NAMES.get(user_country, '')
        )

    notice = detect_notice(query)
    if notice and notice['type'] == 'redirect':
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
            country_name=COUNTRY_NAMES.get(user_country, '')
        )

    bang_url = get_bang_redirect(query)
    if bang_url:
        return redirect(bang_url)

    try:
        if region:
            session['region'] = region
        results, total_results = search_engine.search(query, page, filter_type, region or None)

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

        search_stats.record()
        data_manager.increment_total_searches()

        safety_info = crisis if crisis and crisis['type'] == 'disaster' else None

        news_box = None
        news_intent = detect_news(query)
        if news_intent:
            news_items = [r for r in results if r.get('category') == 'news'][:6]
            if news_items:
                news_box = {
                    'topic': news_intent['topic'] or query,
                    'items': news_items
                }

        return render_template(
            'search.html',
            query=query,
            filter=filter_type,
            results=results,
            verified_info=verified_info,
            safety_info=safety_info,
            news_box=news_box,
            notice=notice,
            ml_rank=ml_rank,
            page=page,
            total_results=total_results,
            info_box=get_info_box(query, results),
            shopping_products=get_shopping_panel(query, results),
            region=region or session.get('region', ''),
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name=COUNTRY_NAMES.get(user_country, '')
        )

    except Exception as e:
        import traceback
        app.logger.error(f"Search route error: {str(e)}\n{traceback.format_exc()}")
        return render_template(
            'search.html',
            query=query,
            notice=notice,
            error="An error occurred while processing your search. Please try again.",
            shopping_products=None,
            announcement=announcement,
            blocked_count=BLOCKLIST_COUNT,
            user_country=user_country,
            country_name=COUNTRY_NAMES.get(user_country, '')
        )

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
    return render_template('blog.html')

@app.route('/about')
def about():
    comparisons = [
        {
            "id": "cmp-vscode-vim",
            "label": "vs code vs vim",
            "engines": {
                "Google": {"cls": "g", "results": [
                    {"title": "VS Code vs Vim: Which Editor Should You Use?", "domain": "dev.to", "badge": "community", "bc": "good"},
                    {"title": "Vim vs Visual Studio Code", "domain": "stackshare.io", "badge": "comparison", "bc": "ok"},
                    {"title": "VS Code vs Vim for Programming", "domain": "freecodecamp.org", "badge": "tutorial", "bc": "good"},
                    {"title": "Vim vs VS Code: Honest Comparison", "domain": "medium.com", "badge": "blog", "bc": "ok"},
                    {"title": "What are your reasons to use vim?", "domain": "reddit.com", "badge": "discussion", "bc": "good"},
                    {"title": "Visual Studio Code vs Vim", "domain": "toolradar.com", "badge": "review", "bc": "ok"},
                    {"title": "Vim vs VSCode: Which Code Editor?", "domain": "blog.logrocket.com", "badge": "blog", "bc": "ok"},
                    {"title": "VS Code vs Vim Comparison 2026", "domain": "tech.co", "badge": "tech site", "bc": "ok"},
                ]},
                "DuckDuckGo": {"cls": "d", "results": [
                    {"title": "VS Code vs Vim: Which Editor Should You Use?", "domain": "dev.to", "badge": "community", "bc": "good"},
                    {"title": "What are your reasons to use vim?", "domain": "reddit.com", "badge": "discussion", "bc": "good"},
                    {"title": "VS Code vs. Vim", "domain": "thisvsthat.io", "badge": "comparison", "bc": "ok"},
                    {"title": "Visual Studio Code vs Vim", "domain": "toolradar.com", "badge": "review", "bc": "ok"},
                    {"title": "Vim vs. VS Code", "domain": "aimadetools.com", "badge": "review", "bc": "ok"},
                    {"title": "Vim vs VS Code: Honest Comparison", "domain": "devplaybook.cc", "badge": "blog", "bc": "ok"},
                    {"title": "Vim vs Visual Studio Code", "domain": "stackshare.io", "badge": "comparison", "bc": "ok"},
                    {"title": "VSCode vs. Vim", "domain": "thisvsthat.io", "badge": "comparison", "bc": "ok"},
                ]},
                "Our Engine": {"cls": "o", "results": [
                    {"title": "VS Code vs Vim: Which Editor Should You Use?", "domain": "dev.to \u00b7 36.8", "badge": "community", "bc": "good"},
                    {"title": "What are your reasons to use vim?", "domain": "reddit.com \u00b7 30.5", "badge": "Reddit boost +7%", "bc": "good"},
                    {"title": "VS Code vs. Vim", "domain": "thisvsthat.io \u00b7 25.6", "badge": "comparison", "bc": "ok"},
                    {"title": "Visual Studio Code vs Vim", "domain": "toolradar.com \u00b7 24.4", "badge": "review", "bc": "ok"},
                    {"title": "Vim vs. VS Code", "domain": "aimadetools.com \u00b7 24.3", "badge": "review", "bc": "ok"},
                    {"title": "Vim vs VS Code: Honest Comparison", "domain": "devplaybook.cc \u00b7 22.6", "badge": "blog", "bc": "ok"},
                    {"title": "Vim vs Visual Studio Code", "domain": "stackshare.io \u00b7 21.6", "badge": "comparison", "bc": "ok"},
                    {"title": "VSCode vs. Vim", "domain": "thisvsthat.io \u00b7 20.2", "badge": "comparison", "bc": "ok"},
                ]},
            },
            "stats": [
                {"label": "Google relevance", "val": "87%", "best": False},
                {"label": "DuckDuckGo relevance", "val": "83%", "best": False},
                {"label": "Our relevance", "val": "92%", "best": True},
                {"label": "Google spam blocked", "val": "88%", "best": False},
                {"label": "DuckDuckGo spam blocked", "val": "83%", "worst": True},
                {"label": "Our spam blocked", "val": "89%", "best": True},
            ],
            "takeaway": "For discussion queries like editor comparisons, Reddit boost is a game changer. Google buries Reddit at #5 behind corporate blogs and generic comparisons. DuckDuckGo surfaces Reddit at #2 but leaves it buried behind meta comparison sites. Our engine pushes Reddit to #2 with the boost and keeps dev.to (real community content) at #1 where it belongs. When you want actual developer opinions, not SEO-optimized fluff, our engine delivers. We beat both Google and DuckDuckGo on relevance."
        },
        {
            "id": "cmp-tailwind",
            "label": "tailwind css vs bootstrap",
            "engines": {
                "Google": {"cls": "g", "results": [
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "dev.to", "badge": "community", "bc": "good"},
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "geeksforgeeks.org", "badge": "tutorial", "bc": "ok"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "blog.logrocket.com", "badge": "blog", "bc": "ok"},
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "freecodecamp.org", "badge": "tutorial", "bc": "good"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "strapi.io", "badge": "tech site", "bc": "ok"},
                    {"title": "Tailwind vs Bootstrap", "domain": "designrevision.com", "badge": "review", "bc": "ok"},
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "stackshare.io", "badge": "comparison", "bc": "ok"},
                    {"title": "Comparing Tailwind CSS to Bootstrap", "domain": "blog.logrocket.com", "badge": "blog", "bc": "ok"},
                ]},
                "DuckDuckGo": {"cls": "d", "results": [
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "dev.to", "badge": "community", "bc": "good"},
                    {"title": "Tailwind CSS vs Bootstrap 2026", "domain": "toolshref.com", "badge": "SEO site", "bc": "ok"},
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "geeksforgeeks.org", "badge": "content farm", "bc": "bad"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "strapi.io", "badge": "tech site", "bc": "ok"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "itpathsolutions.com", "badge": "SEO site", "bc": "ok"},
                    {"title": "Tailwind vs Bootstrap", "domain": "designrevision.com", "badge": "review", "bc": "ok"},
                    {"title": "Tailwind vs Bootstrap 2026", "domain": "tech-insider.org", "badge": "blog", "bc": "ok"},
                    {"title": "Comparing Tailwind CSS to Bootstrap", "domain": "blog.logrocket.com", "badge": "blog", "bc": "ok"},
                ]},
                "Our Engine": {"cls": "o", "results": [
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "dev.to \u00b7 35.1", "badge": "community", "bc": "good"},
                    {"title": "Tailwind CSS vs Bootstrap 2026", "domain": "toolshref.com \u00b7 32.0", "badge": "comparison", "bc": "ok"},
                    {"title": "Tailwind CSS vs Bootstrap", "domain": "geeksforgeeks.org \u00b7 30.3", "badge": "penalized -20", "bc": "bad"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "strapi.io \u00b7 24.8", "badge": "tech site", "bc": "ok"},
                    {"title": "Bootstrap vs Tailwind CSS", "domain": "itpathsolutions.com \u00b7 24.2", "badge": "SEO site", "bc": "ok"},
                    {"title": "Tailwind vs Bootstrap", "domain": "designrevision.com \u00b7 22.9", "badge": "review", "bc": "ok"},
                    {"title": "Tailwind vs Bootstrap 2026", "domain": "tech-insider.org \u00b7 22.3", "badge": "blog", "bc": "ok"},
                    {"title": "Comparing Tailwind CSS to Bootstrap", "domain": "blog.logrocket.com \u00b7 19.8", "badge": "blog", "bc": "ok"},
                ]},
            },
            "stats": [
                {"label": "Google relevance", "val": "89%", "best": False},
                {"label": "DuckDuckGo relevance", "val": "76%", "worst": True},
                {"label": "Our relevance", "val": "90%", "best": True},
                {"label": "Google spam blocked", "val": "86%", "best": False},
                {"label": "DuckDuckGo spam blocked", "val": "73%", "worst": True},
                {"label": "Our spam blocked", "val": "87%", "best": True},
            ],
            "takeaway": "For technical comparisons, our content quality penalty makes the difference. Google leaves GeeksforGeeks at #2 despite being a known content farm. DuckDuckGo lets it into the top 3 and also surfaces SEO-optimized comparison sites (toolshref, itpathsolutions). Our engine penalizes GeeksforGeeks with \u221220 (drops it to #3) and keeps dev.to\u2019s community-written comparison at #1. We beat DuckDuckGo by 14% on relevance and 14% on spam blocking. On developer queries, community voices win over SEO spam."
        },
        {
            "id": "cmp-headphones",
            "label": "best noise cancelling headphones 2026",
            "engines": {
                "Google": {"cls": "g", "results": [
                    {"title": "Best Noise-Cancelling Headphones 2026", "domain": "nytimes.com/wirecutter", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "rtings.com", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "pcmag.com", "badge": "expert tested", "bc": "good"},
                    {"title": "Best noise-cancelling headphones 2026", "domain": "whathifi.com", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise-Canceling Headphones", "domain": "tomsguide.com", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise Cancelling Headphones", "domain": "cnet.com", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Canceling Headphones", "domain": "soundguys.com", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "techradar.com", "badge": "review", "bc": "ok"},
                ]},
                "DuckDuckGo": {"cls": "d", "results": [
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "recordingnow.com", "badge": "unknown domain", "bc": "ok"},
                    {"title": "Best Noise-Cancelling Headphones 2026", "domain": "nytimes.com/wirecutter", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "rtings.com", "badge": "expert tested", "bc": "good"},
                    {"title": "Best noise-cancelling headphones 2026", "domain": "whathifi.com", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise-Cancelling Headphones 2026", "domain": "pcmag.com", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Canceling Headphones 2026", "domain": "audiophileon.com", "badge": "review", "bc": "ok"},
                    {"title": "Best noise-canceling headphones 2026", "domain": "tomsguide.com", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise-Canceling Headphones 2026", "domain": "people.com", "badge": "general", "bc": "ok"},
                ]},
                "Our Engine": {"cls": "o", "results": [
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "recordingnow.com \u00b7 31.3", "badge": "title match", "bc": "good"},
                    {"title": "Best Noise-Cancelling Headphones 2026", "domain": "nytimes.com/wirecutter \u00b7 27.7", "badge": "authoritative", "bc": "good"},
                    {"title": "Best Noise Cancelling Headphones 2026", "domain": "rtings.com \u00b7 25.3", "badge": "expert tested", "bc": "good"},
                    {"title": "Best noise-cancelling headphones 2026", "domain": "whathifi.com \u00b7 25.0", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise-Cancelling Headphones 2026", "domain": "pcmag.com \u00b7 24.1", "badge": "expert tested", "bc": "good"},
                    {"title": "Best Noise Canceling Headphones 2026", "domain": "audiophileon.com \u00b7 19.9", "badge": "review", "bc": "ok"},
                    {"title": "Best noise-canceling headphones 2026", "domain": "tomsguide.com \u00b7 19.8", "badge": "review", "bc": "ok"},
                    {"title": "Best Noise-Canceling Headphones 2026", "domain": "people.com \u00b7 18.8", "badge": "general", "bc": "ok"},
                ]},
            },
            "stats": [
                {"label": "Google relevance", "val": "93%", "best": True},
                {"label": "DuckDuckGo relevance", "val": "81%", "worst": True},
                {"label": "Our relevance", "val": "84%", "best": False},
                {"label": "Google spam blocked", "val": "91%", "best": True},
                {"label": "DuckDuckGo spam blocked", "val": "72%", "worst": True},
                {"label": "Our spam blocked", "val": "82%", "best": False},
            ],
            "takeaway": "Google dominates shopping queries with authoritative review sites (Wirecutter, RTINGS, PCMag) at the top. DuckDuckGo lets an unknown SEO domain (recordingnow.com) grab #1 despite being less authoritative. Our engine keeps recordingnow.com at #1 on strong title match, but promotes Wirecutter to #2 and RTINGS to #3 \u2014 ahead of where DuckDuckGo places them. We beat DuckDuckGo by 3% on relevance and 10% on spam blocking. For product research, our domain authority scoring elevates trusted reviewers above SEO-first sites."
        }
    ]
    return render_template('about.html', comparisons=comparisons)

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


@app.route('/faq')
def faq():
    return render_template('faq.html')


@app.route('/changelogs')
def changelogs():
    return render_template('changelogs.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')


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
    return render_template('search.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {str(error)}")
    return render_template('search.html', error="An internal error occurred. Please try again."), 500

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
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Incorrect password'
    return render_template('admin.html', login=True, error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
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

@app.route('/admin/crawl/<domain>', methods=['POST'])
def admin_crawl_site(domain):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    site = data_manager.get_submitted_site(domain)
    if site:
        data_manager.update_crawl_status(domain, 'crawling')
        result = kumo.crawl_site(domain, site.get('sitemap_url'))
        pages = len(result.get('pages', []))
        data_manager.update_crawl_status(domain, 'completed' if pages > 0 else 'failed', pages)
        if result.get('pages'):
            data_manager.store_crawled_pages(domain, result['pages'])
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/announcement', methods=['POST'])
def admin_announcement():
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    values = request.form.getlist('announcement')
    text = values[-1].strip() if values else ''
    data_manager.set_announcement(text)
    return redirect(url_for('admin_dashboard'))

@app.route('/benchmark')
def benchmark():
    query = request.args.get('q', '').strip()
    results_data = None
    metrics = None
    conclusion = None

    if query:
        try:
            search_engine = ImprovedSearch()
            modes = ['none', 'blend_light', 'blend_strong', 'pure_ml', 'norm_50']
            mode_labels = {
                'none': 'arlong (no ML)',
                'blend_light': 'Blend (subtle)',
                'blend_strong': 'Blend (strong)',
                'pure_ml': 'Pure ML',
                'norm_50': 'Normalized 50/50',
            }

            raw_results, _ = search_engine.search(query, page=1)
            if not raw_results:
                raw_results = []

            mode_results = {}
            timings = {}
            for mode in modes:
                t0 = time.time()
                if mode == 'none':
                    mode_results['none'] = [dict(r) for r in raw_results[:10]]
                else:
                    ranked = search_engine.ml_rerank(query, [dict(r) for r in raw_results], mode)
                    mode_results[mode] = ranked[:10]
                timings[mode] = round(time.time() - t0, 3)

            ddg_results = []
            ddg_time = 0
            if ddgs_available:
                try:
                    t0 = time.time()
                    raw_ddg = DDGS(timeout=8).text(query, max_results=10, backend='auto', safesearch='on')
                    ddg_time = round(time.time() - t0, 3)
                    for i, r in enumerate(raw_ddg):
                        href = r.get('href', '') or ''
                        if not href or href.startswith('//') or not href.startswith('http'):
                            continue
                        parsed = urlparse(href)
                        if not parsed.netloc:
                            continue
                        ddg_results.append({
                            'title': r.get('title', ''),
                            'url': href,
                            'display_url': href[:60] + ('...' if len(href) > 60 else ''),
                            'snippet': r.get('body', ''),
                            'domain': parsed.netloc,
                            'score': round(100.0 - len(ddg_results) * 8, 2),
                        })
                        if len(ddg_results) >= 10:
                            break
                except Exception as e:
                    app.logger.error(f"Benchmark DDG error: {e}")

            baseline_pos = {r['url']: i for i, r in enumerate(mode_results['none'])}

            def with_rank_info(results, baseline_pos_map):
                enriched = []
                for i, r in enumerate(results):
                    url = r['url']
                    if url in baseline_pos_map:
                        r['pos_change'] = baseline_pos_map[url] - i
                    else:
                        r['pos_change'] = None
                    if not r.get('domain'):
                        r['domain'] = urlparse(url).netloc
                    enriched.append(r)
                return enriched

            def rbo_score(a, b, p=0.9):
                urls_a = [r['url'] for r in a]
                urls_b = [r['url'] for r in b]
                if not urls_a or not urls_b:
                    return 0
                sa, sb = set(), set()
                overlap = 0
                weighted = 0
                min_len = min(len(urls_a), len(urls_b))
                for k in range(min_len):
                    sa.add(urls_a[k])
                    sb.add(urls_b[k])
                    overlap = len(sa & sb)
                    weighted += overlap * (p ** (k + 1))
                return round((1 - p) / p * weighted, 3)

            def jaccard(a, b):
                urls_a = {r['url'] for r in a}
                urls_b = {r['url'] for r in b}
                if not urls_a or not urls_b:
                    return 0
                return round(len(urls_a & urls_b) / len(urls_a | urls_b), 3)

            def avg_pos_shift(a, b):
                pos_a = {r['url']: i for i, r in enumerate(a)}
                pos_b = {r['url']: i for i, r in enumerate(b)}
                shifts = [abs(pos_a[u] - pos_b[u]) for u in pos_a if u in pos_b]
                return round(sum(shifts) / max(len(shifts), 1), 2)

            def avg_score_diff(a, b):
                scores_a = {r['url']: r.get('score', 0) for r in a}
                scores_b = {r['url']: r.get('score', 0) for r in b}
                common = set(scores_a.keys()) & set(scores_b.keys())
                if not common:
                    return 0
                diffs = [scores_b[u] - scores_a[u] for u in common]
                return round(sum(diffs) / len(diffs), 2)

            def pos_changes(results, baseline_pos_map):
                changes = []
                for i, r in enumerate(results):
                    url = r['url']
                    if url in baseline_pos_map:
                        changes.append(baseline_pos_map[url] - i)
                return changes

            def _score_stats(results):
                scores = [r.get('score', 0) for r in results if r.get('score') is not None]
                if not scores:
                    return {'min': 0, 'max': 0, 'mean': 0, 'std': 0}
                n = len(scores)
                mean_s = sum(scores) / n
                std_s = (sum((s - mean_s) ** 2 for s in scores) / n) ** 0.5
                return {'min': round(min(scores), 2), 'max': round(max(scores), 2), 'mean': round(mean_s, 2), 'std': round(std_s, 2)}

            def _build_entry(key, label, results_list, timing):
                r = results_list
                changes = pos_changes(r, baseline_pos)
                n_up = sum(1 for c in changes if c and c > 0)
                n_down = sum(1 for c in changes if c and c < 0)
                n_new = sum(1 for i, rr in enumerate(r) if rr['url'] not in baseline_pos)
                return {
                    'label': label,
                    'key': key,
                    'results': with_rank_info(r, baseline_pos),
                    'timing': timing,
                    'jaccard_vs_none': jaccard(r, mode_results['none']),
                    'rbo_vs_none': rbo_score(r, mode_results['none']),
                    'avg_pos_shift_vs_none': avg_pos_shift(r, mode_results['none']),
                    'avg_score_diff_vs_none': avg_score_diff(mode_results['none'], r) if r else None,
                    'changed_positions': len(changes),
                    'moved_up': n_up,
                    'moved_down': n_down,
                    'new_results': n_new,
                    'score_stats': _score_stats(r),
                    'scores': [r2.get('score', 0) for r2 in r],
                }

            comparison = []
            for mode in modes:
                comparison.append(_build_entry(mode, mode_labels[mode], mode_results[mode], timings[mode]))
            comparison.append(_build_entry('ddg', 'DuckDuckGo', ddg_results, ddg_time))

            results_data = comparison

            all_results_map = {}
            for mode in modes:
                all_results_map[mode] = mode_results[mode]
            all_results_map['ddg'] = ddg_results

            all_labels = [m['label'] for m in comparison]
            all_keys = [m['key'] for m in comparison]
            pairwise = []
            pairwise_rbo = []
            for i, k1 in enumerate(all_keys):
                r1 = all_results_map.get(k1, [])
                jrow = []
                rborow = []
                for j, k2 in enumerate(all_keys):
                    r2 = all_results_map.get(k2, [])
                    jrow.append(jaccard(r1, r2))
                    rborow.append(rbo_score(r1, r2))
                pairwise.append({'label': all_labels[i], 'row': jrow})
                pairwise_rbo.append({'label': all_labels[i], 'row': rborow})

            def _find_best_mode(metric_key, higher=True):
                valid = [(m, m.get(metric_key, 0)) for m in comparison if m.get(metric_key) is not None]
                if not valid:
                    return None, 0
                sorted_m = sorted(valid, key=lambda x: x[1], reverse=higher)
                return sorted_m[0]

            best_jaccard_mode, best_jaccard = _find_best_mode('jaccard_vs_none', higher=True)
            best_rbo_mode, best_rbo = _find_best_mode('rbo_vs_none', higher=True)
            most_aggressive, most_changes = _find_best_mode('changed_positions', higher=True)
            fastest_ml = min([m for m in comparison if m['key'] not in ('none', 'ddg')], key=lambda m: m['timing'])

            conclusion_parts = []
            if best_rbo_mode and best_rbo_mode['key'] not in ('none',):
                conclusion_parts.append(
                    f"{best_rbo_mode['label']} preserves ranking closest to the baseline (RBO={best_rbo_mode['rbo_vs_none']}), "
                    f"meaning it makes the most conservative changes to the original order."
                )
            if most_aggressive and most_aggressive['key'] not in ('none',):
                conclusion_parts.append(
                    f"{most_aggressive['label']} is the most aggressive — it changes the most positions "
                    f"({most_aggressive['changed_positions']} of 10) vs baseline."
                )
            fastest_ml_label = fastest_ml['label'] if fastest_ml else 'blend modes'
            conclusion_parts.append(
                f"{fastest_ml_label} is the fastest ML mode at {fastest_ml['timing']}s."
            )

            for m in comparison:
                if m['key'] == 'ddg':
                    j = m['jaccard_vs_none']
                    rbo = m['rbo_vs_none']
                    if j is not None and rbo is not None:
                        conclusion_parts.append(
                            f"DuckDuckGo shares only {int(j*100)}% URL overlap (RBO={rbo}) with arlong's baseline, "
                            f"confirming that different engines return fundamentally different sets of results."
                        )

            conclusion = ' '.join(conclusion_parts)

            metrics = {
                'total_raw': len(raw_results),
                'modes_tested': len(comparison),
                'has_ddg': len(ddg_results) > 0,
                'pairwise_jaccard': pairwise,
                'pairwise_rbo': pairwise_rbo,
                'scores_chart': {
                    'labels': [m['label'] for m in comparison],
                    'means': [m['score_stats']['mean'] for m in comparison],
                    'maxs': [m['score_stats']['max'] for m in comparison],
                    'mins': [m['score_stats']['min'] for m in comparison],
                },
            }

            for m in comparison:
                m['results'] = m['results'][:10]

        except Exception as e:
            import traceback
            app.logger.error(f"Benchmark error: {e}\n{traceback.format_exc()}")

    return render_template('benchmark.html', query=query, results=results_data, metrics=metrics, conclusion=conclusion)

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
                result = kumo.crawl_site(domain, sitemap_url)
                pages = len(result.get('pages', []))
                data_manager.update_crawl_status(domain, 'completed' if pages > 0 else 'failed', pages)
                if result.get('pages'):
                    data_manager.store_crawled_pages(domain, result['pages'])
                success = f"Crawled {domain} — found {pages} page(s)."
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        sq = request.form.get('security_question', '').strip()
        sa = request.form.get('security_answer', '').strip()
        if not username or not password or not sq or not sa:
            return render_template('signup.html', error='All fields required')
        if len(username) < 3 or len(username) > 24:
            return render_template('signup.html', error='Username 3-24 characters')
        if len(password) < 6:
            return render_template('signup.html', error='Password at least 6 characters')
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
        user, err = data_manager.create_user(username, password, sq, sa, ip)
        if err:
            return render_template('signup.html', error=err)
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = data_manager.authenticate_user(username, password)
        if not user:
            return render_template('signup.html', login_error='Invalid credentials')
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        return redirect(url_for('home'))
    return redirect(url_for('signup', mode='login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('home'))

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

def rate_limit_check(user_id):
    wait, reason = data_manager.get_user_cooldown(user_id)
    if wait > 0:
        return False, int(wait) + 1
    return True, 0

@app.route('/api/vote', methods=['POST'])
def api_vote():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    url = request.form.get('url', '').strip()
    title = request.form.get('title', url).strip()[:300]
    vote = int(request.form.get('vote', '0'))
    if vote not in (-1, 1):
        return jsonify({'ok': False, 'error': 'Invalid vote'}), 400
    ok, wait = rate_limit_check(user_id)
    if not ok:
        return jsonify({'ok': False, 'error': f'Please wait {wait}s', 'wait': wait}), 429
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
    data_manager.cast_vote(user_id, url, vote)
    data_manager.record_user_action(user_id, ip)
    score, up, down = data_manager.get_vote_score(url)
    return jsonify({'ok': True, 'score': score, 'up': up, 'down': down})



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


@app.template_filter('urlencode')
def urlencode_filter(s):
    import urllib.parse
    return urllib.parse.quote(s or '')


# ── Explore / Collections routes ──

@app.route('/explore')
def explore():
    sort = request.args.get('sort', 'new')
    page = int(request.args.get('page', 1))
    collections, total = data_manager.get_collections(sort=sort, page=page)
    return render_template('explore.html', collections=collections, sort=sort, page=page, total=total)


@app.route('/explore/<collection_id>')
def explore_collection(collection_id):
    collection = data_manager.get_collection(collection_id)
    if not collection:
        return render_template('explore.html', error='Collection not found'), 404
    return render_template('collection_detail.html', collection=collection)


@app.route('/api/collections', methods=['GET', 'POST'])
def api_collections():
    user_id = session.get('user_id')
    if request.method == 'POST':
        if not user_id:
            return jsonify({'ok': False, 'error': 'Login required'}), 403
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        if not name or len(name) < 2:
            return jsonify({'ok': False, 'error': 'Name at least 2 characters'}), 400
        username = session.get('username', 'Anonymous')
        c = data_manager.create_collection(user_id, username, name, desc)
        return jsonify({'ok': True, 'collection': c})
    if user_id:
        cols = data_manager.get_user_collections(user_id)
    else:
        cols, _ = data_manager.get_collections(sort='new', page=1, per_page=50)
        cols = cols[:50]
    return jsonify({'ok': True, 'collections': cols})


@app.route('/api/collections/<collection_id>', methods=['PUT', 'DELETE'])
def api_collection(collection_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Login required'}), 403
    if request.method == 'PUT':
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        c = data_manager.update_collection(collection_id, user_id, name, desc)
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





@app.route('/collections')
def user_collections():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    cols = data_manager.get_user_collections(user_id)
    return render_template('explore.html', collections=cols, sort='mine', total=len(cols))


# ── Feed routes ──

# ── Leaderboard ──

@app.route('/leaderboard')
def leaderboard():
    lb = data_manager.get_leaderboard()
    return render_template('leaderboard.html', leaderboard=lb)


@app.route('/api/leaderboard')
def api_leaderboard():
    lb = data_manager.get_leaderboard()
    return jsonify({'ok': True, 'leaderboard': lb})


# ── User profile ──

@app.route('/u/<username>')
def user_profile(username):
    profile = data_manager.get_user_profile(username)
    if not profile:
        return render_template('user_profile.html', error='User not found'), 404
    return render_template('user_profile.html', profile=profile)


def weekly_crawl_job():
    with app.app_context():
        sites = data_manager.get_submitted_sites()
        if not sites:
            app.logger.info("Weekly crawl: no submitted sites to crawl")
            return
        for site in sites:
            domain = site['domain']
            try:
                data_manager.update_crawl_status(domain, 'crawling')
                result = kumo.crawl_site(domain, site.get('sitemap_url'))
                pages = len(result.get('pages', []))
                data_manager.update_crawl_status(domain, 'completed' if pages > 0 else 'failed', pages)
                if result.get('pages'):
                    data_manager.store_crawled_pages(domain, result['pages'])
                app.logger.info(f"Weekly crawl: {domain} — {pages} page(s)")
            except Exception as e:
                app.logger.error(f"Weekly crawl error for {domain}: {e}")
                data_manager.update_crawl_status(domain, 'failed')


if scheduler_available:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        weekly_crawl_job,
        IntervalTrigger(weeks=1),
        id='weekly_kumo_crawl',
        name='Crawl all submitted sites weekly',
        replace_existing=True,
    )
    scheduler.start()
    app.logger.info("Weekly Kumo Crawler scheduler started")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
