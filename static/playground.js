(() => {
  'use strict';

  const byId = (id) => document.getElementById(id);
  const queryInput = byId('query');
  const runButton = byId('run');
  const output = byId('output');
  const status = byId('status');
  const copyButton = byId('copy-json');
  const modeStatus = byId('mode-status');
  const modeDescription = byId('mode-description');
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const modeButtons = [...document.querySelectorAll('.mode')];

  if (!queryInput || !runButton || !output || !status || !copyButton ||
      !modeStatus || !modeDescription || !csrfMeta || modeButtons.length !== 2) {
    console.error('Arlong playground could not initialize: required controls are missing.');
    return;
  }

  let mode = new URLSearchParams(window.location.search).get('mode') === 'agent'
    ? 'agent'
    : 'search';
  let latest = null;
  const csrf = csrfMeta.content;

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);

  const inlineMarkdown = (value) => escapeHtml(value)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  function renderMarkdown(value) {
    const lines = String(value ?? '').replace(/\r/g, '').split('\n');
    const html = [];
    let list = '';
    const closeList = () => {
      if (list) html.push(`</${list}>`);
      list = '';
    };

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (/^\s*\|?\s*:?-{3,}/.test(line) && line.includes('|')) continue;
      if (/^\s*\|.*\|\s*$/.test(line) && index + 1 < lines.length &&
          /^\s*\|?\s*:?-{3,}/.test(lines[index + 1])) {
        closeList();
        html.push(`<table><thead><tr>${line.replace(/^\s*\||\|\s*$/g, '')
          .split('|').map((cell) => `<th>${inlineMarkdown(cell.trim())}</th>`).join('')}</tr></thead><tbody>`);
        index += 1;
        while (index + 1 < lines.length && /^\s*\|.*\|\s*$/.test(lines[index + 1])) {
          index += 1;
          html.push(`<tr>${lines[index].replace(/^\s*\||\|\s*$/g, '')
            .split('|').map((cell) => `<td>${inlineMarkdown(cell.trim())}</td>`).join('')}</tr>`);
        }
        html.push('</tbody></table>');
        continue;
      }
      if (/^\s*---+\s*$/.test(line)) {
        closeList();
        html.push('<hr>');
        continue;
      }
      let match = line.match(/^(#{1,3})\s+(.+)$/);
      if (match) {
        closeList();
        html.push(`<h${match[1].length}>${inlineMarkdown(match[2])}</h${match[1].length}>`);
        continue;
      }
      match = line.match(/^\s*[-*+]\s+(.+)$/) || line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (match) {
        const nextList = /^\s*\d/.test(line) ? 'ol' : 'ul';
        if (list && list !== nextList) closeList();
        if (!list) {
          list = nextList;
          html.push(`<${list}>`);
        }
        html.push(`<li>${inlineMarkdown(match[1])}</li>`);
        continue;
      }
      closeList();
      if (line.trim()) html.push(`<p>${inlineMarkdown(line)}</p>`);
    }
    closeList();
    return html.join('') || '<p>No written answer was returned.</p>';
  }

  function setMode(nextMode) {
    mode = nextMode === 'agent' ? 'agent' : 'search';
    const isAgent = mode === 'agent';
    modeButtons.forEach((button) => {
      const buttonIsAgent = button.dataset.mode === 'agent';
      button.type = 'button';
      button.classList.toggle('active', buttonIsAgent === isAgent);
      button.querySelector('b').textContent = buttonIsAgent ? 'Agentic Search' : 'Normal Search';
      button.querySelector('small').textContent = buttonIsAgent
        ? 'Multi-pass evidence and synthesis'
        : 'One focused retrieval pass';
    });
    document.querySelectorAll('.nav a[href*="/playground?mode="]').forEach((link) => {
      const linkMode = new URL(link.href, window.location.origin).searchParams.get('mode');
      link.classList.toggle('active', linkMode === mode);
    });
    modeStatus.textContent = isAgent ? 'AGENTIC SEARCH' : 'NORMAL SEARCH';
    modeDescription.textContent = isAgent
      ? 'Plans independent evidence lanes and produces a grounded report.'
      : 'Uses one focused retrieval pass and returns screened sources.';
    runButton.textContent = isAgent ? 'Run agentic search ↗' : 'Run normal search ↗';
    const url = new URL(window.location.href);
    url.searchParams.set('mode', mode);
    window.history.replaceState({}, '', url);
  }

  function renderSources(results) {
    return (results ?? []).slice(0, 12).map((result) => `
      <a class="result" href="${escapeHtml(result.url)}" target="_blank" rel="noopener noreferrer">
        <h3>${escapeHtml(result.title || 'Untitled source')}</h3>
        <small>${escapeHtml(result.domain || result.url || '')}</small>
        <p>${escapeHtml(result.snippet || result.content || '')}</p>
      </a>`).join('');
  }

  async function streamAnswer(payload) {
    const response = await fetch('/api/ai/stream', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.message || detail.error || 'Answer generation failed');
    }
    if (!response.body) throw new Error('Streaming is unavailable in this browser.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let answer = '';
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      answer += decoder.decode(value, {stream: true});
      byId('answer').textContent = answer;
    }
    answer += decoder.decode();
    byId('answer').innerHTML = renderMarkdown(answer);
    latest.answer = answer;
  }

  async function submit() {
    const query = queryInput.value.trim();
    if (query.length < 2 || runButton.disabled) {
      queryInput.focus();
      return;
    }
    const isAgent = mode === 'agent';
    runButton.disabled = true;
    copyButton.disabled = true;
    status.className = 'mode-status';
    status.textContent = isAgent ? 'AGENTIC SEARCHING' : 'NORMAL SEARCHING';
    output.innerHTML = '<div class="loading">Gathering source evidence…</div>';

    try {
      const response = await fetch('/api/ai/search', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({query, deep: isAgent, skip: true}),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.message || data.error || `Search failed (${response.status})`);
      }

      latest = {
        query, mode,
        results: data.results ?? [],
        research_trace: data.groups ?? [],
        usage: {
          kind: data.usage_kind || (isAgent ? 'deep' : 'standard'),
          allowance_consumed: data.allowance_consumed ?? 1,
          remaining: data.msg_remaining,
          limit: data.msg_limit,
          charged_usd: Number(data.charged_usd || 0),
        },
      };
      const trace = (data.groups ?? []).map((group) =>
        `<span>${escapeHtml(group.label || 'Research pass')} · ${(group.results ?? []).length} sources</span>`
      ).join('');
      const autopilot = isAgent
        ? '<div class="autopilot"><span>Autopilot mode is on.</span><span>Checking coverage across independent sources.</span></div>'
        : '';
      const productName = isAgent ? 'Agentic Search' : 'Normal Search';
      output.innerHTML = `
        <div class="trace">${trace}</div>${autopilot}
        <div class="answer-label">${isAgent ? 'RESEARCH REPORT' : 'GROUNDED ANSWER'}</div>
        <div id="answer" class="answer">Preparing synthesis…</div>
        <div class="answer-label">SOURCES</div>${renderSources(data.results)}
        <div class="usage">1 ${productName} allowance used · ${data.msg_remaining ?? '—'} remaining</div>
        <div class="cost-breakdown">Customer charge: <b>$${Number(data.charged_usd || 0).toFixed(2)} USD</b> · included allowance</div>`;

      await streamAnswer({
        query,
        chat_id: data.chat_id,
        results: data.results,
        multitask: Boolean(data.multitask),
        report: isAgent,
      });
      status.className = 'mode-status ok';
      status.textContent = 'COMPLETE';
      copyButton.disabled = false;
    } catch (error) {
      output.innerHTML = `<div class="empty"><div><strong>Request unavailable.</strong>${escapeHtml(error.message)}</div></div>`;
      status.className = 'mode-status error';
      status.textContent = 'ERROR';
    } finally {
      runButton.disabled = false;
      setMode(mode);
    }
  }

  async function loadHistory() {
    try {
      const response = await fetch('/api/ai/chats');
      if (!response.ok) return;
      const data = await response.json();
      const chats = (data.chats ?? []).map((chat) => ({
        ...chat,
        meter: (chat.messages ?? []).filter((message) =>
          message.role === 'assistant' && message.allowance_consumed
        ).at(-1),
      })).filter((chat) => chat.meter).slice(0, 8);
      if (!chats.length) return;
      const panel = document.createElement('section');
      panel.className = 'history';
      panel.innerHTML = '<h3>Recent playground history</h3>' + chats.map((chat) => {
        const product = chat.meter.deep ? 'Agentic Search' : 'Normal Search';
        const stamp = String(chat.updated_at || '').replace('T', ' ').slice(0, 16);
        const params = new URLSearchParams({
          mode: chat.meter.deep ? 'agent' : 'search',
          q: chat.title || '',
        });
        return `<a href="/playground?${params}">${escapeHtml(chat.title || 'Untitled request')}
          <small>${product} · 1 included allowance · $${Number(chat.meter.charged_usd || 0).toFixed(2)} billed · ${escapeHtml(stamp)}</small></a>`;
      }).join('');
      document.querySelector('.inside')?.appendChild(panel);
    } catch (_) {
      // History is supplementary and must never disable the playground.
    }
  }

  const wordmark = document.querySelector('.brand .wave');
  if (wordmark) {
    wordmark.setAttribute('aria-label', 'arlong');
    wordmark.innerHTML = '<i>a</i><i>r</i><i>l</i><i>o</i><i>n</i><i>g</i>';
  }
  document.querySelectorAll('.nav a').forEach((link) => {
    if (link.textContent.includes('Research Agent')) link.childNodes[0].nodeValue = '✦ Agentic Search ';
    if (link.textContent.trim() === '⌕ Search') link.childNodes[0].nodeValue = '⌕ Normal Search';
  });
  const extractNav = [...document.querySelectorAll('.nav a')].find((link) =>
    link.textContent.includes('Extract')
  );
  if (extractNav && !document.querySelector('.nav a[href="/people"]')) {
    const people = document.createElement('a');
    people.href = '/people';
    people.textContent = '◎ People Search';
    extractNav.before(people);
  }

  runButton.type = 'button';
  copyButton.type = 'button';
  modeButtons.forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));
  runButton.addEventListener('click', submit);
  copyButton.addEventListener('click', async () => {
    if (!latest) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(latest, null, 2));
      copyButton.textContent = 'Copied';
      window.setTimeout(() => { copyButton.textContent = 'Copy JSON'; }, 1400);
    } catch (_) {
      copyButton.textContent = 'Copy failed';
    }
  });
  queryInput.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') submit();
  });

  setMode(mode);
  loadHistory();
})();
