import { escapeHtml } from '../util.js';
import { getChatMessages } from '../chatState.js';

const DEFAULT_QUICK = [
  'List all USB devices connected to this machine',
  'Show failed login attempts after midnight',
  'Summarize the key findings of this investigation',
];

function pillLabel(question) {
  const s = String(question || '');
  return s.length > 20 ? `${s.slice(0, 18)}…` : s;
}

function getGreeting() {
  const h = new Date().getHours();
  if (h < 12) return 'Good morning';
  if (h < 17) return 'Good afternoon';
  return 'Good evening';
}

const TYPE_META = {
  REGISTRY: { cls: 'type-registry', color: 'var(--type-registry)' },
  'EVENT LOG': { cls: 'type-event', color: 'var(--type-event)' },
  BROWSER: { cls: 'type-browser', color: 'var(--type-browser)' },
  PREFETCH: { cls: 'type-prefetch', color: 'var(--type-prefetch)' },
  THREAT: { cls: 'type-threat', color: 'var(--type-threat)' },
};

function truncate(str, n) {
  const s = String(str ?? '');
  if (!s) return '';
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function relativeTime(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return String(iso).slice(0, 19);
  const diff = Math.max(0, Date.now() - t);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  return `${days}d ago`;
}

function formatTime(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function buildCompactCards(arts, threats) {
  const flaggedIds = new Set((threats.flagged || []).map((t) => t.id).filter(Boolean));
  const cards = [];
  const push = (type, items, mapper) => {
    for (const item of items || []) cards.push(mapper(type, item));
  };

  push('REGISTRY', arts.registry, (type, r) => ({
    type,
    detail: `${r.hive || ''} ${r.key_path || ''}`.trim() || 'Registry entry',
    ts: r.timestamp,
    flagged: false,
  }));
  push('EVENT LOG', arts.events, (type, r) => ({
    type,
    detail: `Event ${r.event_id || ''} · ${r.channel || ''}`.trim(),
    ts: r.timestamp,
    flagged: false,
  }));
  push('BROWSER', arts.browser, (type, r) => ({
    type,
    detail: r.title || r.url || 'Visit',
    ts: r.visit_time,
    flagged: false,
  }));
  push('PREFETCH', arts.prefetch, (type, r) => {
    const amber = !!String(r.executable || '').toLowerCase().match(/cain|ethereal/);
    return {
      type,
      detail: r.executable || r.path || 'Prefetch',
      ts: r.last_run,
      flagged: amber,
      amber,
    };
  });
  push('THREAT', threats.threats || arts.scored, (type, r) => ({
    type,
    detail: r.reason || r.summary || r.artifact_type || 'Threat',
    ts: null,
    score: r.xgboost_score,
    flagged: !!(r.flagged || flaggedIds.has(r.id) || (r.xgboost_score != null && Number(r.xgboost_score) > 0.7)),
  }));

  return cards;
}

/** Pick up to 2 from each core type first (8 total), then fill leftovers; threats last if space. */
function pickMixedRows(cards, limit = 8) {
  const core = ['REGISTRY', 'EVENT LOG', 'BROWSER', 'PREFETCH'];
  const picked = [];
  const used = new Set();

  for (const type of core) {
    let n = 0;
    for (let i = 0; i < cards.length && n < 2 && picked.length < limit; i++) {
      if (cards[i].type === type && !used.has(i)) {
        picked.push(cards[i]);
        used.add(i);
        n++;
      }
    }
  }

  for (let i = 0; i < cards.length && picked.length < limit; i++) {
    if (used.has(i)) continue;
    if (cards[i].type === 'THREAT') continue;
    picked.push(cards[i]);
    used.add(i);
  }

  for (let i = 0; i < cards.length && picked.length < limit; i++) {
    if (used.has(i)) continue;
    if (cards[i].type === 'THREAT') {
      picked.push(cards[i]);
      used.add(i);
    }
  }

  return picked;
}

function threatSummary(threats) {
  const list = threats.threats || threats.flagged || [];
  const first = list[0] || {};
  const xgb =
    first.xgboost_score ??
    threats.xgboost_score ??
    list.find((t) => t.xgboost_score != null)?.xgboost_score;
  const flagged =
    (threats.flagged || []).length > 0 || list.some((t) => t.flagged) || (xgb != null && Number(xgb) > 0.7);
  return { xgb: xgb != null ? Number(xgb) : null, flagged };
}

let dashRenderGen = 0;

export async function renderDashboard(root, ctx) {
  const gen = ++dashRenderGen;
  const stillActive = () =>
    gen === dashRenderGen && (typeof ctx.isNavCurrent !== 'function' || ctx.isNavCurrent());
  const { navigate, toast, setSelectedCase, caseBadge, state } = ctx;
  const cfg = ctx.config || state.config || {};
  const ai = ctx.aiInfo || state.aiInfo || {};
  const queries = (cfg.chat?.quickQueries?.length
    ? cfg.chat.quickQueries
    : DEFAULT_QUICK
  ).slice(0, 3);
  const DASH_QUICK = queries.map((q) => ({
    label: pillLabel(q),
    question: q,
  }));
  const modelLabel = ai.model || '—';
  const orgName = cfg.branding?.orgName || 'Agentic Blockchain Forensics';

  let cases = [];
  try {
    const data = await window.api.fetchAPI('/cases');
    cases = data.cases || [];
  } catch (err) {
    if (!stillActive()) return { cleanup() { dashRenderGen++; } };
    root.innerHTML = `<div class="panel empty">Backend unreachable: ${escapeHtml(err.message)}. Start the Node service on port 3000.</div>`;
    return {
      cleanup() {
        dashRenderGen++;
      },
    };
  }

  if (!stillActive()) {
    return {
      cleanup() {
        dashRenderGen++;
      },
    };
  }

  const active = cases.filter((c) =>
    ['analysing', 'queued', 'pending', 'mounting'].includes(String(c.status || '').toLowerCase())
  ).length;

  let evidenceItems = 0;
  let queriesToday = 0;
  const today = new Date().toISOString().slice(0, 10);

  const sample = cases.slice(0, 5);
  await Promise.all(
    sample.map(async (c) => {
      try {
        const arts = await window.api.fetchAPI(`/cases/${encodeURIComponent(c.case_id)}/artifacts`);
        const counts = arts.counts || {};
        evidenceItems +=
          (counts.registry || 0) +
          (counts.events || 0) +
          (counts.browser || 0) +
          (counts.prefetch || 0) +
          (counts.scored || 0);
      } catch { /* ignore */ }
      try {
        const audit = await window.api.fetchAPI(`/cases/${encodeURIComponent(c.case_id)}/audit`);
        const trail = audit.trail || [];
        queriesToday += trail.filter(
          (t) => t.action === 'QUERY' && String(t.timestamp || '').startsWith(today)
        ).length;
      } catch { /* ignore */ }
    })
  );

  if (!stillActive()) {
    return {
      cleanup() {
        dashRenderGen++;
      },
    };
  }

  const verifyEntries = Object.values(state.verifyCache || {});
  let integrityLabel;
  let integrityClass;
  let integritySub;
  if (verifyEntries.length === 0) {
    integrityLabel = '—';
    integrityClass = '';
    integritySub = 'No verifications yet';
  } else {
    const tampered = verifyEntries.filter((e) => e.tampered).length;
    const total = verifyEntries.length;
    if (tampered === 0) {
      integrityLabel = `${total}/${total} OK`;
      integrityClass = 'green';
      integritySub = 'All verified cases intact';
    } else {
      integrityLabel = `${tampered} Tampered`;
      integrityClass = 'red';
      integritySub = 'Integrity mismatch detected';
    }
  }

  const recent = cases.slice(0, 8);
  let selectedId = state.selectedCaseId || null;
  let selectedName = state.selectedCaseName || null;

  function paintShell() {
    root.innerHTML = `
      <div class="page-header">
        <h2>Investigator Dashboard</h2>
        <button class="btn primary" id="dash-new">+ New Case</button>
      </div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-label">Active Cases</div>
          <div class="stat-value">${active}</div>
          <div class="stat-sub">${cases.length} total on file</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Evidence Items</div>
          <div class="stat-value">${evidenceItems}</div>
          <div class="stat-sub">Artifacts across recent cases</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">AI Queries Today</div>
          <div class="stat-value">${queriesToday}</div>
          <div class="stat-sub">Logged on-chain QUERY actions</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Chain Integrity</div>
          <div class="stat-value ${integrityClass}">${escapeHtml(integrityLabel)}</div>
          <div class="stat-sub">${escapeHtml(integritySub)}</div>
        </div>
      </div>

      <div class="dashboard-3col">
        <div class="dashboard-col">
          <div class="panel">
            <h2 class="dash-panel-title">Recent Cases</h2>
            <div class="panel-scroll" id="dash-cases">
              ${
                recent.length
                  ? recent
                      .map((c) => {
                        const b = caseBadge(c.status);
                        const isActive = selectedId && c.case_id === selectedId;
                        return `<div class="dash-case-row ${isActive ? 'active' : ''}" data-id="${escapeHtml(c.case_id)}" data-name="${escapeHtml(c.name || c.case_id)}">
                          <div class="dash-case-name">${escapeHtml(c.name || c.case_id)}</div>
                          <div class="dash-case-meta">
                            <div class="muted mono dash-case-id" title="${escapeHtml(c.case_id)}">${escapeHtml(c.case_id)}</div>
                            <div class="dash-case-actions">
                              <span class="badge ${b.cls}">${escapeHtml(b.label)}</span>
                              <button type="button" class="btn ghost sm btn-open" data-id="${escapeHtml(c.case_id)}" data-name="${escapeHtml(c.name || c.case_id)}" title="Open evidence">→</button>
                            </div>
                          </div>
                        </div>`;
                      })
                      .join('')
                  : `<div class="empty">
                      <div>No cases yet.</div>
                      <button class="btn primary mt-1" id="dash-empty-new">+ New Case</button>
                    </div>`
              }
            </div>
          </div>
        </div>

        <div class="dashboard-col">
          <div class="panel">
            <div class="panel-scroll" id="dash-evidence"></div>
          </div>
        </div>

        <div class="dash-chat-panel">
          <div class="dash-chat-header">
            <span class="dash-chat-label">AI Forensic Assistant</span>
            <span class="dash-model-chip">${escapeHtml(String(modelLabel))}</span>
          </div>
          <div class="dash-chat-case" id="dash-chat-case"></div>
          <div class="dash-chat-messages" id="dash-chat-messages"></div>
          <div class="dash-chat-footer">
            <div class="dash-quick-queries">
              ${DASH_QUICK.map(
                (q, i) => `<button type="button" class="dash-quick-pill" data-q="${i}">${escapeHtml(q.label)}</button>`
              ).join('')}
            </div>
            <div class="dash-input-row">
              <textarea id="dash-chat-input" rows="1" placeholder="Ask about the evidence…"></textarea>
              <button type="button" class="dash-send-btn" id="dash-chat-send" title="Send">→</button>
            </div>
          </div>
        </div>
      </div>
    `;

    bindShell();
    paintChatCase();
    paintChatMessages();
    refreshEvidence();
  }

  function bindShell() {
    const goNew = () => navigate('cases', { openNew: true });
    root.querySelector('#dash-new')?.addEventListener('click', goNew);
    root.querySelector('#dash-empty-new')?.addEventListener('click', goNew);

    root.querySelectorAll('.dash-case-row').forEach((row) => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('.btn-open')) return;
        selectCase(row.dataset.id, row.dataset.name);
      });
    });
    root.querySelectorAll('.btn-open').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        navigate('evidence', { caseId: btn.dataset.id, caseName: btn.dataset.name });
      });
    });

    root.querySelectorAll('.dash-quick-queries button').forEach((btn) => {
      btn.addEventListener('click', () => {
        const q = DASH_QUICK[Number(btn.dataset.q)];
        if (q) sendDashboardMessage(q.question);
      });
    });
    root.querySelector('#dash-chat-send')?.addEventListener('click', () => {
      const input = root.querySelector('#dash-chat-input');
      sendDashboardMessage(input?.value);
      if (input) {
        input.value = '';
        input.style.height = '36px';
      }
    });
    const input = root.querySelector('#dash-chat-input');
    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendDashboardMessage(input.value);
        input.value = '';
        input.style.height = '36px';
      }
    });
    input?.addEventListener('input', () => {
      input.style.height = '36px';
      input.style.height = `${Math.min(80, Math.max(36, input.scrollHeight))}px`;
    });
  }

  function selectCase(caseId, caseName) {
    selectedId = caseId;
    selectedName = caseName;
    setSelectedCase(caseId, caseName);
    root.querySelectorAll('.dash-case-row').forEach((row) => {
      row.classList.toggle('active', row.dataset.id === caseId);
    });
    paintChatCase();
    paintChatMessages();
    refreshEvidence();
  }

  function paintChatCase() {
    const el = root.querySelector('#dash-chat-case');
    if (!el) return;
    if (selectedId) {
      el.textContent = selectedName || selectedId;
      el.hidden = false;
    } else {
      el.textContent = '';
      el.hidden = true;
    }
  }

  function paintChatMessages() {
    const log = root.querySelector('#dash-chat-messages');
    if (!log) return;

    if (!selectedId) {
      log.innerHTML = `<div class="dash-chat-empty">No case selected — open a case from the list on the left</div>`;
      return;
    }

    const chatMessages = getChatMessages(selectedId);
    if (!chatMessages.length) {
      log.innerHTML = `<div class="dash-chat-empty">${escapeHtml(getGreeting())}, Investigator. Select a case and ask about the evidence.</div>`;
      return;
    }

    log.innerHTML = chatMessages
      .map((m) => {
        if (m.role === 'typing') {
          return `<div class="typing" aria-label="thinking">
            <span class="typing-dot"></span>
            <span class="typing-dot"></span>
            <span class="typing-dot"></span>
          </div>`;
        }
        if (m.role === 'user') {
          return `<div class="dash-bubble-user">
            ${escapeHtml(m.text)}
            <div class="dash-bubble-time">${escapeHtml(formatTime(m.ts))}</div>
          </div>`;
        }
        const srcList = m.sources || [];
        const sourcesHtml = srcList.length
          ? `<div class="sources">
              <div class="sources-label">Evidence via RAG</div>
              ${srcList
                .slice(0, 4)
                .map((s) => {
                  let text;
                  if (typeof s === 'string') text = s;
                  else text = s.document || s.text || s.id || JSON.stringify(s).slice(0, 120);
                  const short = String(text).length > 48 ? `${String(text).slice(0, 46)}…` : text;
                  return `<span class="source-chip">${escapeHtml(short)}</span>`;
                })
                .join('')}
            </div>`
          : '';
        return `<div class="dash-bubble-ai">
          <div class="dash-bubble-ai-header">
            <span class="dash-bubble-ai-label">${escapeHtml(orgName)}</span>
            <span class="dash-bubble-ai-model">${escapeHtml(String(modelLabel))}</span>
          </div>
          <div class="dash-bubble-ai-body">${escapeHtml(m.text)}</div>
          ${sourcesHtml}
        </div>`;
      })
      .join('');
    log.scrollTop = log.scrollHeight;
  }

  async function refreshEvidence() {
    if (!stillActive()) return;
    const el = root.querySelector('#dash-evidence');
    if (!el) return;

    if (!selectedId) {
      el.innerHTML = `<div class="dash-evidence-empty">Select a case from the list to view its artifacts</div>`;
      return;
    }

    el.innerHTML = `<div class="muted dash-loading">Loading artifacts…</div>`;
    const caseMeta = cases.find((c) => c.case_id === selectedId);
    const b = caseBadge(caseMeta?.status);
    const name = selectedName || caseMeta?.name || selectedId;

    try {
      const [arts, threats] = await Promise.all([
        window.api.fetchAPI(`/cases/${encodeURIComponent(selectedId)}/artifacts`),
        window.api.fetchAPI(`/cases/${encodeURIComponent(selectedId)}/threats`).catch(() => ({})),
      ]);
      if (!stillActive()) return;
      const cards = pickMixedRows(buildCompactCards(arts, threats || {}), 8);
      const thr = threatSummary(threats || {});

      const cardsHtml = cards.length
        ? cards
            .map((c) => {
              const meta = TYPE_META[c.type] || TYPE_META.REGISTRY;
              const border = meta.color;
              return `<div class="dash-artifact-row" style="border-left-color:${border}">
                <span class="badge ${meta.cls}">${escapeHtml(c.type)}</span>
                <span class="artifact-text" title="${escapeHtml(c.detail || '')}">${escapeHtml(c.detail || '')}</span>
                <span class="artifact-time">${escapeHtml((c.ts || '').toString().slice(0, 19) || '')}</span>
              </div>`;
            })
            .join('')
        : `<div class="muted dash-empty-artifacts">No artifacts yet for this case.</div>`;

      const threatHtml =
        thr.flagged && thr.xgb != null
          ? `<div class="dash-threat-row">
              <span class="${thr.xgb > 0.7 ? 'xgb-high' : 'mono'}">XGBoost: ${escapeHtml(thr.xgb.toFixed(3))}</span>
              <span class="badge error">FLAGGED</span>
            </div>`
          : thr.flagged
            ? `<div class="dash-threat-row"><span class="badge error">FLAGGED</span></div>`
            : '';

      el.innerHTML = `
        <div class="dash-evidence-head">
          <span class="dash-case-title">${escapeHtml(name)}</span>
          <span class="badge ${b.cls}">${escapeHtml(b.label)}</span>
          <button type="button" class="dash-view-full" id="dash-view-full">View Full →</button>
        </div>
        ${cardsHtml}
        ${threatHtml}
      `;
      el.querySelector('#dash-view-full')?.addEventListener('click', () => {
        navigate('evidence', { caseId: selectedId, caseName: name });
      });
    } catch (err) {
      if (!stillActive()) return;
      el.innerHTML = `
        <div class="dash-evidence-head">
          <span class="dash-case-title">${escapeHtml(name)}</span>
          <span class="badge ${b.cls}">${escapeHtml(b.label)}</span>
          <button type="button" class="dash-view-full" id="dash-view-full">View Full →</button>
        </div>
        <div class="muted">Could not load artifacts: ${escapeHtml(err.message)}</div>`;
      el.querySelector('#dash-view-full')?.addEventListener('click', () => {
        navigate('evidence', { caseId: selectedId, caseName: name });
      });
    }
  }

  async function sendDashboardMessage(question) {
    const q = String(question || '').trim();
    if (!q) return;
    if (!selectedId) {
      toast('Select a case first', true);
      return;
    }
    if (!stillActive()) return;
    const chatMessages = getChatMessages(selectedId);
    chatMessages.push({ role: 'user', text: q, ts: Date.now() });
    chatMessages.push({ role: 'typing' });
    paintChatMessages();
    try {
      const res = await window.api.fetchAPI(`/cases/${encodeURIComponent(selectedId)}/chat`, {
        method: 'POST',
        body: { question: q },
      });
      if (!stillActive()) return;
      const msgs = getChatMessages(selectedId);
      if (msgs.length && msgs[msgs.length - 1].role === 'typing') {
        msgs.pop();
      }
      msgs.push({
        role: 'ai',
        text: res.answer || res.error || JSON.stringify(res),
        sources: res.sources || [],
      });
      paintChatMessages();
    } catch (err) {
      if (!stillActive()) return;
      const msgs = getChatMessages(selectedId);
      if (msgs.length && msgs[msgs.length - 1].role === 'typing') {
        msgs.pop();
      }
      msgs.push({ role: 'ai', text: `Error: ${err.message}`, sources: [] });
      paintChatMessages();
      toast(err.message, true);
    }
  }

  if (!stillActive()) {
    return {
      cleanup() {
        dashRenderGen++;
      },
    };
  }

  paintShell();

  return {
    cleanup() {
      dashRenderGen++;
    },
  };
}
