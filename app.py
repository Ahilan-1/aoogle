from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import logging
import time
import random
import json
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='apple_search.log',
    level=logging.DEBUG,  # Set to DEBUG for more detailed logging
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AppleSearch:
    def __init__(self):
        self.user_agent = UserAgent()
        self.session = requests.Session()
        self.base_url = "https://html.duckduckgo.com/html/"
        self.suggest_base_url = "https://suggestqueries.google.com/complete/search"
        self.cache = {}
        self.executor = ThreadPoolExecutor(max_workers=5)  # Increased worker count for better concurrency

    def _get_headers(self):
        return {
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://www.apple.com/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _extract_info_box(self, soup):
        """Extract information box content if available"""
        try:
            # Update selector to match Google's latest info box structure
            info_box = soup.find('div', {'class': 'kp-wholepage'})
            if not info_box:
                return None
            
            title = info_box.find('h2', {'class': 'qrShPb'}) or info_box.find('div', {'class': 'kno-ecr-pt'})  # Alternate selector
            description = info_box.find('div', {'class': 'LGOjhe'}) or info_box.find('div', {'class': 'kno-rdesc'})
            image = info_box.find('g-img') or info_box.find('img', {'class': 'kno-fb-ctx'})

            return {
                'title': title.get_text(strip=True) if title else '',
                'description': description.get_text(strip=True) if description else '',
                'image_url': image['src'] if image and image.get('src') else None,
                'type': 'info_box'
            }
        except Exception as e:
            logging.error(f"Error parsing info box: {e}")
        return None


    def _categorize_result(self, url, title):
        """Categorize search result based on URL and title"""
        domain = urlparse(url).netloc.lower()
        
        categories = {
            'news': ['news', 'article', 'blog', 'press'],
            'shopping': ['shop', 'store', 'buy', 'price'],
            'social': ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com'],
            'video': ['youtube.com', 'vimeo.com', 'watch', 'video'],
            'academic': ['edu', 'academic', 'research', 'study'],
            'official': ['gov', 'official', 'organization'],
            'forums': ['reddit.com', 'quora.com', 'forum', 'discussion'],
            'tech': ['tech', 'gadget', 'review']
        }
        
        for category, keywords in categories.items():
            if any(keyword in domain for keyword in keywords) or \
               any(keyword in title.lower() for keyword in keywords):
                return category
        
        return 'general'

    def _parse_results(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        results = []

        for div in soup.find_all('div', class_='result'):
            try:
                title_elem = div.select_one('.result__a')
                if not title_elem:
                    continue
                url = title_elem.get('href', '')
                title = title_elem.get_text(strip=True)

                snippet_elem = div.select_one('.result__snippet')
                snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''

                if not url or not title:
                    continue

                result = {
                    'title': title,
                    'url': url,
                    'display_url': url[:60] + '...' if len(url) > 60 else url,
                    'snippet': snippet,
                    'favicon': f"https://www.google.com/s2/favicons?domain={url}",
                    'category': self._categorize_result(url, title),
                    'type': 'regular',
                    'score': 0
                }

                results.append(result)
            except Exception as e:
                logging.error(f"Error parsing result: {e}")
                continue

        return results

    def _fetch_with_retry(self, url, params, max_retries=5, method='GET'):
        """Fetch URL with retry mechanism"""
        for attempt in range(max_retries):
            try:
                time.sleep(random.uniform(0.5, 1.5))
                if method == 'POST':
                    response = self.session.post(
                        url,
                        data=params,
                        headers=self._get_headers(),
                        timeout=10
                    )
                else:
                    response = self.session.get(
                        url,
                        params=params,
                        headers=self._get_headers(),
                        timeout=10
                    )
                if response.status_code == 200:
                    return response
                else:
                    logging.debug(f"Received status code {response.status_code} for URL: {response.url}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    raise
        return None

    def search(self, query, page=1):
        cache_key = f"{query}_{page}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            params = {'q': query}
            
            response = self._fetch_with_retry(self.base_url, params, method='POST')
            if not response:
                return []

            results = self._parse_results(response.text)
            ranked_results = self._rank_results(query, results)
            self.cache[cache_key] = ranked_results
            return ranked_results

        except Exception as e:
            logging.error(f"Search error: {e}")
            return []

    def _rank_results(self, query, results):
        keywords = query.lower().split()
        
        for result in results:
            if result['type'] == 'info_box':
                result['score'] = 50  # High priority for info boxes
                continue

            score = 0
            title_lower = result['title'].lower()
            snippet_lower = result['snippet'].lower()

            # Exact phrase matches for relevance
            if query.lower() in title_lower:
                score += 20
            if query.lower() in snippet_lower:
                score += 10

            # Keyword matches in title and snippet
            title_keywords = sum(1 for word in keywords if word in title_lower)
            snippet_keywords = sum(1 for word in keywords if word in snippet_lower)
            score += title_keywords * 3 + snippet_keywords * 2

            # Authority and freshness boosts
            if '2024' in result.get('date', ''):
                score += 10  # Freshness bonus for recent content
            domain = urlparse(result['url']).netloc
            if any(tld in domain for tld in ['.edu', '.gov', '.org']):
                score += 8  # Authority bonus for reputable domains

            # Intent-based scoring for context-relevant categories
            if result['category'] in ['news', 'official', 'tech']:
                score += 5  # Higher priority for relevant categories

            # Final score assignment
            result['score'] = score

        # Sort results by score, prioritizing info boxes
        info_boxes = [r for r in results if r['type'] == 'info_box']
        regular_results = sorted(
            [r for r in results if r['type'] == 'regular'],
            key=lambda x: x['score'],
            reverse=True
        )
        
        return info_boxes + regular_results


    def get_suggestions(self, query):
        try:
            params = {
                'client': 'firefox',
                'q': query
            }
            response = self._fetch_with_retry(self.suggest_base_url, params)
            if response and response.status_code == 200:
                return response.json()[1]
        except Exception as e:
            logging.error(f"Suggestion fetch error: {e}")
        return []

# Initialize search engine
search_engine = AppleSearch()

@app.route('/')
def home():
    return render_template('apple_search.html')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    page = int(request.args.get('page', 1))
    
    if not query:
        return render_template('apple_search.html')
    
    try:
        results = search_engine.search(query, page)
        
        # Group results by category
        categorized_results = {}
        for result in results:
            if result['type'] == 'info_box':
                continue
            category = result['category']
            if category not in categorized_results:
                categorized_results[category] = []
            categorized_results[category].append(result)
        
        info_box = next((r for r in results if r['type'] == 'info_box'), None)
        
        return render_template(
            'apple_search.html',
            query=query,
            results=results,
            categorized_results=categorized_results,
            info_box=info_box,
            page=page,
            total_results=len(results)
        )
    except Exception as e:
        logging.error(f"Search route error: {e}")
        return render_template(
            'apple_search.html',
            query=query,
            error="An error occurred. Please try again."
        )

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/suggest')
def suggest():
    query = request.args.get('q', '')
    suggestions = search_engine.get_suggestions(query)
    return jsonify(suggestions)

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)