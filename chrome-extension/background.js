const API_BASE = 'https://aoogle-production.up.railway.app';

var SEARCH_URLS = {
  google:   'https://www.google.com/search?q=',
  bing:     'https://www.bing.com/search?q=',
  duckduckgo: 'https://duckduckgo.com/?q=',
  yahoo:    'https://search.yahoo.com/search?p=',
  brave:    'https://search.brave.com/search?q=',
  ecosia:   'https://www.ecosia.org/search?q=',
  qwant:    'https://www.qwant.com/?q=',
  baidu:    'https://www.baidu.com/s?wd=',
  yandex:   'https://yandex.com/search/?text=',
  searx:    'https://searx.be/search?q='
};

/* ---- Message handler ---- */
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (request.type === 'arlongSearch') {
    var url = API_BASE + '/api/search?q=' + encodeURIComponent(request.query);
    fetch(url)
      .then(function (resp) {
        if (!resp.ok) throw new Error('API error: ' + resp.status);
        return resp.json();
      })
      .then(function (data) {
        sendResponse({ ok: true, data: data });
        if (request.openFallback) {
          openFallbackTab(request.query);
        }
      })
      .catch(function (err) {
        sendResponse({ ok: false, error: err.message });
      });
    return true;
  }

  if (request.type === 'arlongOpenFallback') {
    openFallbackTab(request.query);
    return false;
  }
});

function openFallbackTab(query) {
  chrome.storage.sync.get('fallbackEngine', function (data) {
    var engine = data.fallbackEngine || 'google';
    var url = (SEARCH_URLS[engine] || SEARCH_URLS.google) + encodeURIComponent(query);
    chrome.tabs.create({ url: url });
  });
}

/* ---- Omnibox ---- */
chrome.omnibox.onInputEntered.addListener(function (text) {
  var q = text.trim();
  if (!q) return;
  chrome.tabs.update({ url: API_BASE + '/search?q=' + encodeURIComponent(q) });
  openFallbackTab(q);
});

chrome.omnibox.onInputChanged.addListener(function (text, suggest) {
  if (text.length < 2) { suggest([]); return; }
  fetch(API_BASE + '/suggest?q=' + encodeURIComponent(text))
    .then(function (r) { return r.json(); })
    .then(function (data) {
      var suggestions = (data || []).map(function (s) {
        return { content: s, description: s };
      });
      suggest(suggestions);
    })
    .catch(function () { suggest([]); });
});

/* ---- Init ---- */
chrome.runtime.onInstalled.addListener(function () {
  chrome.storage.sync.get('fallbackEngine', function (data) {
    if (!data.fallbackEngine) {
      chrome.storage.sync.set({ fallbackEngine: 'google' });
    }
  });
});
