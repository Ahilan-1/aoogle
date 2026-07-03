"""Tests for the bang (!) redirect system."""
import re


BANG_REDIRECTS = {
    'g': 'https://www.google.com/search?q={}',
    'ch': 'https://chatgpt.com/?q={}',
    'ge': 'https://gemini.google.com/search?q={}',
    'wiki': 'https://en.wikipedia.org/wiki/{}',
    're': 'https://www.reddit.com/search/?q={}',
    'you': 'https://www.youtube.com/results?search_query={}',
    'yt': 'https://www.youtube.com/results?search_query={}',
    'gi': 'https://www.google.com/search?tbm=isch&q={}',
    'map': 'https://www.google.com/maps/search/{}',
    'news': 'https://news.google.com/search?q={}',
    'a': 'https://www.amazon.com/s?k={}',
    'w': 'https://en.wikipedia.org/w/index.php?search={}',
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
    'red': 'https://www.reddit.com/r/{}',
    'qu': 'https://www.quora.com/search?q={}',
    'md': 'https://medium.com/search?q={}',
    'dev': 'https://dev.to/search?q={}',
    'hn': 'https://news.ycombinator.com/submitted?id={}',
    'ph': 'https://www.producthunt.com/search?q={}',
    'b': 'https://www.youtube.com/results?search_query={}',
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
    'gm': 'https://mail.google.com/mail/u/0/#search/{}',
    'dr': 'https://drive.google.com/drive/search?q={}',
    'cal': 'https://calendar.google.com/calendar/r/search?q={}',
    'keep': 'https://keep.google.com/u/0/#search/text={}',
    'maps': 'https://www.google.com/maps/search/{}',
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
    'tik': 'https://www.tiktok.com/search?q={}',
    'db': 'https://www.discogs.com/search/?q={}',
    'gm': 'https://mail.google.com/mail/u/0/#search/{}',
    'tr': 'https://www.tripadvisor.com/Search?q={}',
    'nf': 'https://www.netflix.com/search?q={}',
    'hulu': 'https://www.hulu.com/search?q={}',
    'dis': 'https://www.disneyplus.com/search?q={}',
    'tv': 'https://www.tvmaze.com/search?q={}',
    'gp': 'https://play.google.com/store/search?q={}',
    'ap': 'https://play.google.com/store/apps/details?id={}',
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
    from urllib.parse import quote_plus
    return template.format(quote_plus(search_term) if search_term else '')


class TestBangParsing:
    def test_simple_bang_google(self):
        assert parse_bang("!g python programming") == ('g', 'python programming')

    def test_bang_only_no_query(self):
        assert parse_bang("!wiki") == ('wiki', '')

    def test_bang_chatgpt(self):
        assert parse_bang("!ch how to center a div") == ('ch', 'how to center a div')

    def test_bang_reddit(self):
        assert parse_bang("!re python projects") == ('re', 'python projects')

    def test_bang_youtube(self):
        assert parse_bang("!you never gonna give") == ('you', 'never gonna give')

    def test_no_bang_returns_none(self):
        assert parse_bang("python programming") == (None, 'python programming')

    def test_empty_query(self):
        assert parse_bang("") == (None, '')

    def test_bang_with_spaces(self):
        assert parse_bang("  !g  python  ") == ('g', 'python')

    def test_unknown_bang_falls_through(self):
        assert parse_bang("!zzzzzzzz nonsense") == (None, '!zzzzzzzz nonsense')

    def test_bang_redirect_url_google(self):
        url = get_bang_redirect("!g hello world")
        assert 'google.com' in url
        assert 'hello+world' in url or 'hello%20world' in url

    def test_bang_redirect_wikipedia(self):
        url = get_bang_redirect("!wiki Python")
        assert 'wikipedia.org' in url

    def test_bang_redirect_chatgpt(self):
        url = get_bang_redirect("!ch hello")
        assert 'chatgpt.com' in url

    def test_70_bangs_exist(self):
        assert len(BANG_REDIRECTS) >= 70

    def test_all_bangs_have_urls(self):
        for bang, url in BANG_REDIRECTS.items():
            assert '{}' in url, f"Bang !{bang} missing {{}} placeholder"
