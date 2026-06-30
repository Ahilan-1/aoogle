from flask import Flask, render_template, request, jsonify, abort, session, redirect, url_for
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import logging
from logging.handlers import RotatingFileHandler
import time
import random
import json
from urllib.parse import urlparse, quote_plus
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
import re
import threading
import os

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

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@123')

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
    except:
        app.logger.warning("Redis not available, falling back to in-memory cache")

class SearchResult:
    def __init__(self, title, url, snippet, category='general', date=None, favicon=None):
        self.title = title
        self.url = url
        self.snippet = snippet
        self.category = category
        self.date = date
        self.favicon = favicon or f"https://www.google.com/s2/favicons?domain={url}"
        self.score = 0

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
            'type': 'regular'
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
            self.data = {"reports": [], "blacklist": {}, "total_searches": 0}
            _save_json(self.data)

    def add_report(self, url, title, query, domain):
        with self._lock:
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
            return [r for r in self.data['reports'] if r['status'] == 'pending']

    def get_all_reports(self):
        with self._lock:
            return list(self.data['reports'])

    def approve_report(self, report_id, penalty=-30):
        with self._lock:
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
            for report in self.data['reports']:
                if report['id'] == report_id and report['status'] == 'pending':
                    report['status'] = 'denied'
                    _save_json(self.data)
                    return True
            return False

    def get_blacklist(self):
        with self._lock:
            return dict(self.data.get('blacklist', {}))

    def remove_from_blacklist(self, domain):
        with self._lock:
            if domain in self.data['blacklist']:
                del self.data['blacklist'][domain]
                _save_json(self.data)
                return True
            return False

    def get_stats(self):
        with self._lock:
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
                'total_searches': self.data.get('total_searches', 0)
            }

    def get_total_searches(self):
        with self._lock:
            return self.data.get('total_searches', 0)

    def increment_total_searches(self):
        with self._lock:
            self.data['total_searches'] = self.data.get('total_searches', 0) + 1

    def flush(self):
        with self._lock:
            _save_json(self.data)

data_manager = DataManager()

class ImprovedSearch:
    def __init__(self):
        self.session = requests.Session()
        try:
            self.user_agent = UserAgent(fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        except:
            self.user_agent = type('SimpleUA',(),{'random':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','__getitem__':lambda s,k:s.random})()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.search_urls = [
            "https://html.duckduckgo.com/html/",
        ]
        if not redis_client:
            self.in_memory_cache = {}
            self.cache_lock = threading.Lock()

    def _get_cache_key(self, query, page):
        """Generate unique cache key for query"""
        return hashlib.md5(f"{query}_{page}".encode()).hexdigest()

    def _get_from_cache(self, key):
        """Retrieve results from cache"""
        if redis_client:
            cached = redis_client.get(key)
            if cached:
                return json.loads(cached)
        else:
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
            redis_client.setex(key, expire_time, json.dumps(data))
        else:
            with self.cache_lock:
                self.in_memory_cache[key] = (data, time.time() + expire_time)

    def _get_headers(self):
        """Generate random headers for requests"""
        return {
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
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
            exact_match_bonus = 35
            title_start_ratio = title_lower.find(query_lower) / max(len(title_lower), 1)
            if title_start_ratio < 0.3:
                exact_match_bonus += 10

        phrase_in_title = 0
        for i in range(len(query_terms)):
            for j in range(i + 1, min(i + 4, len(query_terms) + 1)):
                phrase = ' '.join(query_terms[i:j])
                if len(phrase) > 2 and phrase in title_lower:
                    phrase_in_title = max(phrase_in_title, len(phrase.split()))

        matching_terms = sum(1 for t in query_terms if t in title_lower)
        term_ratio = matching_terms / max(len(query_terms), 1)

        score = exact_match_bonus
        score += phrase_in_title * 7

        if matching_terms == len(query_terms) and not exact_match_bonus:
            score += 15

        short_title_penalty = max(0, 8 - len(result.title.split())) * 1.5
        score -= short_title_penalty

        title_is_list = bool(re.search(r'^\d+\s', title_lower))
        if title_is_list:
            score -= 5

        return max(0, score)

    def _score_domain_authority(self, url):
        domain = urlparse(url).netloc.lower()
        domain = re.sub(r'^www\.', '', domain)

        for known_domain, authority in DOMAIN_AUTHORITY.items():
            if known_domain in domain or domain.endswith('.' + known_domain):
                return authority

        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        tld_scores = {'edu': 80, 'gov': 80, 'mil': 75, 'org': 60, 'io': 55,
                      'int': 70, 'ac': 60, 'co': 45, 'com': 50, 'net': 45}
        return tld_scores.get(tld, 40)

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
        score += term_ratio * 20

        if query_lower in snippet_lower:
            score += 15

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
                score += 10
            elif proximity < 100:
                score += 5

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

        scored.sort(key=lambda x: x.score, reverse=True)

        deduplicated = []
        seen_titles = set()
        domain_count = {}

        for r in scored:
            if SearchBlocker.is_ad(r.url, r.title, r.snippet):
                continue

            domain = urlparse(r.url).netloc.lower()
            domain = re.sub(r'^www\.', '', domain)
            title_norm = r.title.lower().strip()

            if title_norm in seen_titles:
                continue
            seen_titles.add(title_norm)

            if domain not in domain_count:
                domain_count[domain] = 0
            domain_count[domain] += 1

            if domain_count[domain] > 3:
                r.score *= 0.5
            elif domain_count[domain] > 2:
                r.score *= 0.7
            elif domain_count[domain] > 1:
                r.score *= 0.85

            deduplicated.append(r)

        deduplicated.sort(key=lambda x: x.score, reverse=True)

        return deduplicated[:25]

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

    def _parse_google_results(self, html):
        results = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for div in soup.find_all(['div', 'article'], {'class': ['g', 'result']}):
                try:
                    title_elem = div.find(['h3', 'h2', 'h1'])
                    if not title_elem:
                        continue
                    title = title_elem.get_text(strip=True)

                    link = div.find('a')
                    if not link or not link.get('href'):
                        continue
                    url = link['href']
                    if url.startswith('/url?q='):
                        url = url.split('/url?q=')[1].split('&')[0]

                    snippet_elem = div.find(['div', 'span'], {'class': ['VwiC3b', 'snippet', 'description']})
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''

                    if title and url and snippet:
                        date = self._extract_date(snippet)
                        category = self._categorize_result(url, title, snippet)
                        result = SearchResult(title, url, snippet, category, date)
                        results.append(result)

                except Exception as e:
                    app.logger.error(f"Error parsing Google result: {str(e)}")
                    continue
        except Exception as e:
            app.logger.error(f"Error parsing Google HTML: {str(e)}")
        return results

    def _parse_bing_results(self, html):
        results = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for li in soup.find_all('li', class_='b_algo'):
                try:
                    title_elem = li.find('h2')
                    if not title_elem:
                        continue
                    title = title_elem.get_text(strip=True)

                    link = title_elem.find('a')
                    if not link or not link.get('href'):
                        continue
                    url = link['href']

                    snippet_elem = li.find(['p', 'div'], class_=['b_caption', 'b_lineclamp2'])
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''

                    if title and url and snippet:
                        date = self._extract_date(snippet)
                        category = self._categorize_result(url, title, snippet)
                        result = SearchResult(title, url, snippet, category, date)
                        results.append(result)

                except Exception as e:
                    app.logger.error(f"Error parsing Bing result: {str(e)}")
                    continue
        except Exception as e:
            app.logger.error(f"Error parsing Bing HTML: {str(e)}")
        return results

    def _search_single_engine(self, search_url, query, page):
        try:
            if 'duckduckgo' in search_url:
                response = self.session.post(
                    search_url,
                    data={'q': query},
                    headers=self._get_headers(),
                    timeout=10,
                    allow_redirects=True
                )
                if response and response.text:
                    return self._parse_duckduckgo_results(response.text)
            else:
                params = {
                    'q': query,
                    'start': (page - 1) * 10,
                    'num': 10,
                    'hl': 'en',
                    'safe': 'active'
                }
                response = self._fetch_with_retry(search_url, params)
                if response and response.text:
                    if 'bing' in search_url:
                        return self._parse_bing_results(response.text)
                    else:
                        return self._parse_google_results(response.text)
        except Exception as e:
            app.logger.error(f"Search error on {search_url}: {str(e)}")
            return []
        return []

    def search(self, query, page=1, filter_type='general'):
        """Main search method with fallback and error handling"""
        cache_key = self._get_cache_key(query, page)
        cached_results = self._get_from_cache(cache_key)

        if cached_results:
            return cached_results

        results = []
        errors = []

        # Submit tasks to the executor
        futures = []
        for search_url in self.search_urls:
            future = self.executor.submit(self._search_single_engine, search_url, query, page)
            futures.append(future)

        # Collect results as they complete
        for future in as_completed(futures):
            try:
                current_results = future.result()
                results.extend(current_results)
                if len(results) >= 5:  # We have enough results
                    break
            except Exception as e:
                errors.append(str(e))
                continue

        if not results and errors:
            app.logger.error("\n".join(errors))
            return []

        ranked_results = self._rank_results(query, results, filter_type)
        serialized_results = [result.to_dict() for result in ranked_results]

        # Cache the results
        self._save_to_cache(cache_key, serialized_results)

        return serialized_results

    def search_images(self, query):
        images = []
        seen_urls = set()

        def extract_vqd(html):
            for p in [r'vqd=([\d-]+)&', r'vqd=([\d-]+)', r'"vqd":"([\d-]+)"', r"'vqd':\s*'([\d-]+)'"]:
                m = re.search(p, html)
                if m:
                    return m.group(1)
            return None

        try:
            r = self.session.get('https://duckduckgo.com/', params={'q': query, 'iax': 'images', 'ia': 'images'}, headers=self._get_headers(), timeout=10)
            vqd = extract_vqd(r.text) if r and r.status_code == 200 else None
            if vqd:
                api_resp = self.session.get('https://duckduckgo.com/i.js', params={'q': query, 'o': 'json', 'vqd': vqd, 'f': ',,,'}, headers={**self._get_headers(), 'Referer': 'https://duckduckgo.com/'}, timeout=10)
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
                            images.append({'thumbnail': thumb, 'title': title or dom or query, 'source_url': src, 'source_domain': dom or 'image'})
                            if len(images) >= 50:
                                break
                        except:
                            continue
        except Exception as e:
            app.logger.error(f"DDG images: {e}")

        if len(images) < 6:
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
                            images.append({'thumbnail': turl, 'title': title[:100] or dom or query, 'source_url': purl or '#', 'source_domain': dom or 'image'})
                            if len(images) >= 50:
                                break
                        except:
                            continue
            except Exception as e:
                app.logger.error(f"Bing images: {e}")

        return images[:50]

    def search_videos(self, query):
        videos = []

        def extract_json(text, marker):
            idx = text.find(marker)
            if idx == -1:
                return None
            brace_start = text.find('{', idx)
            if brace_start == -1:
                return None
            depth = 0
            for i in range(brace_start, len(text)):
                ch = text[i]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return text[brace_start:i+1]
            return None

        try:
            r = self.session.get('https://www.youtube.com/results', params={'search_query': query}, headers={**self._get_headers(), 'Accept-Language': 'en-US,en;q=0.5'}, timeout=15)
            if not r or r.status_code != 200:
                return videos
            raw = extract_json(r.text, 'ytInitialData')
            if not raw:
                raw = extract_json(r.text, 'window["ytInitialData"]')
            if not raw:
                return videos
            data = json.loads(raw)
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
                    if not vid:
                        continue
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
                    if len(videos) >= 20:
                        break
                if len(videos) >= 20:
                    break
        except Exception as e:
            app.logger.error(f"YouTube search error: {e}")
        return videos

    def get_suggestions(self, query):
        """Get search suggestions with error handling"""
        if not query or len(query) < 2:
            return []

        cache_key = f"suggest_{query}"
        cached_suggestions = self._get_from_cache(cache_key)

        if cached_suggestions:
            return cached_suggestions

        try:
            params = {
                'client': 'chrome',
                'q': query
            }
            response = self._fetch_with_retry(
                'https://suggestqueries.google.com/complete/search',
                params
            )

            if response and response.status_code == 200:
                suggestions = json.loads(response.text)[1]
                self._save_to_cache(cache_key, suggestions, expire_time=1800)
                return suggestions

        except Exception as e:
            app.logger.error(f"Suggestion error: {str(e)}")

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

def get_info_box(query):
    query_lower = query.lower().strip()
    for key, panel in KNOWLEDGE_PANELS.items():
        if key in query_lower:
            return panel
    return None

def detect_news(query):
    q = query.lower().strip()
    if q.startswith('news '):
        return {'topic': q[5:].strip(), 'intent': 'news'}
    if q.startswith('latest news '):
        return {'topic': q[12:].strip(), 'intent': 'news'}
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
    return render_template('search.html')

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    filter_type = request.args.get('filter', 'general')
    if filter_type not in ('general', 'shopping', 'official', 'tutorials', 'discussions', 'academic'):
        filter_type = 'general'

    if not query:
        return render_template('search.html')

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
            info_box=None
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
            info_box=None
        )

    try:
        results = search_engine.search(query, page, filter_type)
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
            safety_info=safety_info,
            news_box=news_box,
            notice=notice,
            page=page,
            total_results=len(results),
            info_box=get_info_box(query)
        )

    except Exception as e:
        import traceback
        app.logger.error(f"Search route error: {str(e)}\n{traceback.format_exc()}")
        return render_template(
            'search.html',
            query=query,
            notice=notice,
            error="An error occurred while processing your search. Please try again."
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
        results = search_engine.search(query, page)
        search_stats.record()
        data_manager.increment_total_searches()

        data = {
            "query": query,
            "page": page,
            "total_results": len(results),
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
    return render_template('admin.html', login=False, stats=stats, reports=reports, blacklist=blacklist, total_searches=total_searches)

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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
