(function () {
  var SEARCH_ENGINES = {
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

  var fallbackSelect = document.getElementById('fallbackEngine');
  var statusDot = document.getElementById('statusDot');
  var statusText = document.getElementById('statusText');

  function loadSettings() {
    chrome.storage.sync.get('fallbackEngine', function (data) {
      if (data.fallbackEngine && SEARCH_ENGINES[data.fallbackEngine]) {
        fallbackSelect.value = data.fallbackEngine;
      } else {
        fallbackSelect.value = 'google';
        chrome.storage.sync.set({ fallbackEngine: 'google' });
      }
    });
  }

  function saveSettings() {
    chrome.storage.sync.set({
      fallbackEngine: fallbackSelect.value
    });
  }

  fallbackSelect.addEventListener('change', saveSettings);

  function checkStatus() {
    fetch('https://aoogle-production.up.railway.app/health')
      .then(function (r) {
        if (r.ok) {
          statusDot.className = 'status-dot online';
          statusText.textContent = 'arlong online';
        } else {
          statusDot.className = 'status-dot offline';
          statusText.textContent = 'arlong unreachable';
        }
      })
      .catch(function () {
        statusDot.className = 'status-dot offline';
        statusText.textContent = 'arlong offline';
      });
  }

  loadSettings();
  checkStatus();
})();
