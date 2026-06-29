const API_BASE = 'https://aoogle-production.up.railway.app';

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'aoogleSearch') {
    const url = `${API_BASE}/api/search?q=${encodeURIComponent(request.query)}`;
    fetch(url)
      .then(resp => {
        if (!resp.ok) {
          throw new Error(`API error: ${resp.status}`);
        }
        return resp.json();
      })
      .then(data => sendResponse({ ok: true, data }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});
