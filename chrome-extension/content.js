(function () {
  'use strict';

  function getSearchQuery() {
    var url = new URL(window.location.href);
    var h = url.hostname;
    var p = url.pathname;
    if (h.includes('google') && (p.includes('/search') || p.includes('/'))) return url.searchParams.get('q');
    if (h.includes('bing') && p.includes('/search')) return url.searchParams.get('q');
    if (h.includes('duckduckgo') && p.includes('/')) return url.searchParams.get('q');
    if (h.includes('yahoo') && p.includes('/search')) return url.searchParams.get('p');
    if (h.includes('yandex') && p.includes('/search')) return url.searchParams.get('text');
    if (h.includes('baidu') && p.includes('/s')) return url.searchParams.get('wd');
    if (h.includes('brave') && p.includes('/search')) return url.searchParams.get('q');
    if (h.includes('ecosia') && p.includes('/search')) return url.searchParams.get('q');
    if (h.includes('qwant') && p.includes('/')) return url.searchParams.get('q');
    if (h.includes('searx') && p.includes('/search')) return url.searchParams.get('q');
    return null;
  }

  var lastSearchUrl = '';

  function listenForUrlChanges() {
    var pushState = history.pushState;
    var replaceState = history.replaceState;
    history.pushState = function() {
      pushState.apply(this, arguments);
      checkUrlChange();
    };
    history.replaceState = function() {
      replaceState.apply(this, arguments);
      checkUrlChange();
    };
    window.addEventListener('popstate', checkUrlChange);
    window.addEventListener('hashchange', checkUrlChange);
  }

  function checkUrlChange() {
    var url = window.location.href;
    if (url === lastSearchUrl) return;
    lastSearchUrl = url;
    var q = getSearchQuery();
    if (q && queryInput) {
      queryInput.value = q;
      fetchResults(q);
    }
  }

  function esc(t) {
    var d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
  }

  function getDomain(url) {
    try { return new URL(url).hostname; } catch(e) { return ''; }
  }

  function isDarkMode() {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return true;
    var el = document.querySelector('html, body');
    if (!el) return false;
    var c = getComputedStyle(el).backgroundColor;
    var rgb = c.match(/\d+/g);
    if (!rgb) return false;
    return +rgb[0] < 50 && +rgb[1] < 50 && +rgb[2] < 50;
  }

  var sidebar, resultsContainer, statusEl, queryInput;

  function createSidebar() {
    if (document.getElementById('aoogle-sidebar')) return;

    var dark = isDarkMode();
    if (dark) {
      document.documentElement.style.setProperty('--a-bg', '#202124');
      document.documentElement.style.setProperty('--a-bg2', '#303134');
      document.documentElement.style.setProperty('--a-bg3', '#3c4043');
      document.documentElement.style.setProperty('--a-text', '#e8eaed');
      document.documentElement.style.setProperty('--a-text2', '#bdc1c6');
      document.documentElement.style.setProperty('--a-text3', '#9aa0a6');
      document.documentElement.style.setProperty('--a-border', '#5f6368');
      document.documentElement.style.setProperty('--a-border2', '#3c4043');
      document.documentElement.style.setProperty('--a-shadow', 'rgba(0,0,0,0.4)');
      document.documentElement.style.setProperty('--a-shadow-hover', 'rgba(0,0,0,0.5)');
      document.documentElement.style.setProperty('--a-hover', '#3c4043');
      document.documentElement.style.setProperty('--a-card-hover', '#303134');
      document.documentElement.style.setProperty('--a-link', '#8ab4f8');
      document.documentElement.style.setProperty('--a-link-v', '#c58af9');
      document.documentElement.style.setProperty('--a-green', '#81c995');
      document.documentElement.style.setProperty('--a-blue', '#8ab4f8');
      document.documentElement.style.setProperty('--a-red', '#f28b82');
      document.documentElement.style.setProperty('--a-blue-bg', '#1e3a5f');
    }

    sidebar = document.createElement('div');
    sidebar.id = 'aoogle-sidebar';

    sidebar.innerHTML =
      '<div class="aoogle-resize-handle" id="aoogle-resize-handle"></div>' +
      '<div class="aoogle-header">' +
        '<div class="aoogle-header-title" id="aoogle-toggle-btn">' +
          '<span class="aoogle-logo"><span>a</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></span>' +
          '<span style="margin-left:2px">aoogle</span>' +
        '</div>' +
        '<div class="aoogle-header-actions">' +
          '<button class="aoogle-icon-btn" id="aoogle-toggle-btn2" title="Collapse">\u2192</button>' +
          '<button class="aoogle-icon-btn" id="aoogle-close-btn" title="Close">\u00D7</button>' +
        '</div>' +
      '</div>' +
      '<div class="aoogle-query-bar">' +
        '<input type="text" id="aoogle-query-input" placeholder="Search aoogle..." autocomplete="off">' +
        '<button id="aoogle-search-btn">Search</button>' +
      '</div>' +
      '<div id="aoogle-sidebar-status" class="aoogle-status"><span class="aoogle-status-dot"></span> Ready</div>' +
      '<div id="aoogle-sidebar-results" class="aoogle-results-container"></div>';

    document.body.appendChild(sidebar);
    resultsContainer = document.getElementById('aoogle-sidebar-results');
    statusEl = document.getElementById('aoogle-sidebar-status');
    queryInput = document.getElementById('aoogle-query-input');

    /* resize */
    var handle = document.getElementById('aoogle-resize-handle');
    var resizing = false;
    handle.addEventListener('mousedown', function (e) {
      resizing = true;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
      var startX = e.clientX;
      var startW = sidebar.offsetWidth;
      function onMove(ev) {
        if (!resizing) return;
        var w = Math.max(280, Math.min(600, startW - (ev.clientX - startX)));
        sidebar.style.width = w + 'px';
      }
      function onUp() {
        resizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });

    /* events */
    document.getElementById('aoogle-close-btn').addEventListener('click', closeSidebar);
    document.getElementById('aoogle-toggle-btn').addEventListener('click', toggleSidebar);
    document.getElementById('aoogle-toggle-btn2').addEventListener('click', toggleSidebar);

    document.getElementById('aoogle-search-btn').addEventListener('click', function () {
      var q = queryInput.value.trim();
      if (q) fetchResults(q);
    });
    queryInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var q = queryInput.value.trim();
        if (q) fetchResults(q);
      }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !sidebar.classList.contains('aoogle-collapsed')) {
        closeSidebar();
      }
    });

    var width = parseInt(localStorage.getItem('aoogle_sidebar_width') || '380');
    width = Math.max(280, Math.min(600, width));
    sidebar.style.width = width + 'px';
  }

  function toggleSidebar() {
    sidebar.classList.toggle('aoogle-collapsed');
  }

  function closeSidebar() {
    sidebar.classList.add('aoogle-collapsed');
  }

  function setStatus(msg, dot) {
    if (!statusEl) return;
    var dotEl = statusEl.querySelector('.aoogle-status-dot');
    if (dotEl) dotEl.style.background = dot || '#34a853';
    var textNode = null;
    statusEl.childNodes.forEach(function (n) {
      if (n.nodeType === 3) textNode = n;
    });
    if (textNode) textNode.textContent = ' ' + msg;
  }

  function showSkeleton() {
    if (!resultsContainer) return;
    var h = '';
    for (var i = 0; i < 5; i++) {
      h += '<div class="aoogle-skeleton">' +
        '<div class="aoogle-shimmer-line"></div>' +
        '<div class="aoogle-shimmer-line"></div>' +
        '<div class="aoogle-shimmer-line"></div>' +
        '<div class="aoogle-shimmer-line"></div>' +
        '</div>';
    }
    resultsContainer.innerHTML = h;
    setStatus('Searching...', '#fbbc05');
  }

  function showError(msg) {
    if (!resultsContainer) return;
    resultsContainer.innerHTML = '<div class="aoogle-error">' + esc(msg) + '</div>';
    setStatus('Error', '#c5221f');
  }

  function showEmpty() {
    if (!resultsContainer) return;
    resultsContainer.innerHTML = '<div class="aoogle-empty">No results from aoogle</div>';
    setStatus('0 results', '#9aa0a6');
  }

  function renderResults(data) {
    if (!resultsContainer) return;

    var items = data.results || [];
    if (items.length === 0) { showEmpty(); return; }

    setStatus(items.length + ' result' + (items.length > 1 ? 's' : ''), '#34a853');

    var html = '';

    if (data.info_box) {
      html += '<div class="aoogle-info-box aoogle-fade-in">';
      if (data.info_box.title) html += '<div class="aoogle-info-box-title">' + esc(data.info_box.title) + '</div>';
      if (data.info_box.type) html += '<div class="aoogle-info-box-type">' + esc(data.info_box.type) + '</div>';
      if (data.info_box.description) html += '<div class="aoogle-info-box-desc">' + esc(data.info_box.description) + '</div>';
      if (data.info_box.facts && data.info_box.facts.length) {
        html += '<dl class="aoogle-info-box-facts">';
        for (var fi = 0; fi < data.info_box.facts.length; fi++) {
          var f = data.info_box.facts[fi];
          html += '<dt>' + esc(f[0]) + '</dt><dd>' + esc(f[1]) + '</dd>';
        }
        html += '</dl>';
      }
      html += '</div>';
    }

    for (var i = 0; i < items.length; i++) {
      var r = items[i];
      var domain = r.display_url || r.url;
      var cat = r.category || '';
      var score = r.score !== undefined ? Math.round(r.score) : null;
      html += '<div class="aoogle-result aoogle-fade-in">' +
        '<div class="aoogle-result-header">' +
        '<img class="aoogle-result-favicon" src="https://icons.duckduckgo.com/ip3/' + getDomain(r.url) + '.ico" alt="" loading="lazy" onerror="this.style.display=\'none\'">' +
        '<div class="aoogle-result-body">' +
        '<a class="aoogle-result-title" href="' + esc(r.url) + '" target="_blank" rel="noopener" title="' + esc(r.title) + '">' + esc(r.title) + '</a>' +
        '<div class="aoogle-result-url" title="' + esc(domain) + '">' + esc(domain) + '</div>' +
        '<div class="aoogle-result-snippet">' + esc(r.snippet) + '</div>' +
        '<div class="aoogle-result-footer">' +
        (cat ? '<span class="aoogle-result-category">' + esc(cat) + '</span>' : '') +
        (score !== null ? '<span class="aoogle-result-score">Score ' + score + '</span>' : '') +
        '</div>' +
        '</div>' +
        '</div>' +
        '</div>';
    }

    resultsContainer.innerHTML = html;
  }

  function fetchResults(query) {
    if (!query) return;
    showSkeleton();

    chrome.runtime.sendMessage(
      { type: 'aoogleSearch', query: query },
      function (response) {
        if (chrome.runtime.lastError) {
          showError('Connection error. Try reloading the page.');
          return;
        }
        if (response && response.ok) {
          renderResults(response.data);
        } else {
          showError((response && response.error) || 'Failed to fetch results');
        }
      }
    );
  }

  function doSearch() {
    var q = getSearchQuery();
    if (!q) return;
    if (queryInput) queryInput.value = q;
    fetchResults(q);
  }

  function init() {
    createSidebar();
    doSearch();
    listenForUrlChanges();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
