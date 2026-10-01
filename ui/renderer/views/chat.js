import { escapeHtml } from '../util.js';
import { getChatMessages } from '../chatState.js';

const DEFAULT_QUICK_QUERIES = [
  'List all USB devices connected to this machine',
  'Show failed login attempts after midnight',
  'What programs were executed?',
  'Are there any suspicious scheduled tasks?',
  'Summarize the key findings of this investigation',
];

function formatTime(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

export async function renderChat(root, ctx) {
  const { state, navigate, toast, setSelectedCase } = ctx;
  const isNavCurrent = typeof ctx.isNavCurrent === 'function' ? ctx.isNavCurrent : () => true;

  const cfg = ctx.config || state.config || {};
  const ai = ctx.aiInfo || state.aiInfo || {};
  const QUICK_QUERIES = cfg.chat?.quickQueries?.length
    ? cfg.chat.quickQueries
    : DEFAULT_QUICK_QUERIES;
  const modelLabel = ai.model || '—';
  const orgName = cfg.branding?.orgName || 'Agentic Blockchain Forensics';
  const temp = ai.temperature ?? '—';
  const rag = ai.vectorDb || 'ChromaDB';
  const mode = cfg.system?.mode || 'Offline';

  let caseId = state.selectedCaseId;
  let caseName = state.selectedCaseName;

  function activeCase() {
    const id = state.selectedCaseId || caseId;
    const name = state.selectedCaseName || caseName || id;
    return { id, name };
  }

  function messagesForCase() {
    const { id } = activeCase();
    if (!id) return [];
    return getChatMessages(id);
  }

  if (!caseId) {
    try {
      const data = await window.api.fetchAPI('/cases');
      if (!isNavCurrent()) return { cleanup() {} };
      const cases = data.cases || [];
      if (cases.length) {
        caseId = cases[0].case_id;
        caseName = cases[0].name;
        setSelectedCase(caseId, caseName);
      }
    } catch { /* ignore */ }
  } else if (!state.selectedCaseName) {
    setSelectedCase(caseId, caseName || caseId);
  }

  if (!isNavCurrent()) return { cleanup() {} };

  if (!caseId) {
    root.innerHTML = `
      <div class="panel empty">
        <p>Select a case before chatting with the AI agents.</p>
        <button class="btn" id="chat-cases">Open Cases</button>
      </div>`;
    root.querySelector('#chat-cases').onclick = () => navigate('cases');
    return;
  }

  function paint() {
    if (!isNavCurrent()) return;
    const current = activeCase();
    caseId = current.id;
    caseName = current.name;
    if (!caseId) return;
    const messages = messagesForCase();
    root.innerHTML = `
      <div class="chat-layout">
        <div class="chat-main">
          <div class="chat-log" id="chat-log"></div>
        </div>
        <aside class="chat-context" id="chat-context">
          <div class="chat-section">
            <div class="chat-section-label">Active Case</div>
            <div class="chat-case-name">${escapeHtml(caseName || caseId)}</div>
            <div class="mono muted chat-case-id">${escapeHtml(caseId)}</div>
            <button type="button" class="chat-link" id="chat-switch">Switch case</button>
            <button type="button" class="btn ghost sm chat-context-toggle" id="chat-ctx-close" style="margin-top:8px">Hide panel</button>
          </div>
          <div class="chat-divider"></div>
          <div class="chat-section">
            <div class="chat-section-label">Quick Queries</div>
            <div class="quick-queries">
              ${QUICK_QUERIES.map(
                (q, i) => `<button type="button" data-q="${i}"><span class="qq-prefix">▸</span> ${escapeHtml(q)}</button>`
              ).join('')}
            </div>
          </div>
          <div class="chat-divider"></div>
          <div class="chat-section">
            <div class="chat-section-label">Model</div>
            <div class="chat-model-name">${escapeHtml(String(modelLabel))}</div>
            <div class="muted chat-model-meta">Temp: ${escapeHtml(String(temp))}</div>
            <div class="muted chat-model-meta">RAG: ${escapeHtml(String(rag))}</div>
            <div class="muted chat-model-meta">Mode: ${escapeHtml(String(mode))}</div>
          </div>
        </aside>
        <div class="chat-input-row">
          <button class="btn secondary sm chat-context-toggle" id="chat-ctx-toggle" title="Context">◎</button>
          <textarea id="chat-input" placeholder="Ask a grounded forensic question…" rows="1"></textarea>
          <button class="btn btn-send" id="chat-send" title="Send">→</button>
        </div>
      </div>
    `;

    const log = root.querySelector('#chat-log');
    if (!messages.length) {
      log.innerHTML = `
        <div class="chat-empty">
          <strong>Ask about the evidence</strong>
          <div>Use a quick query on the right — or type your own question</div>
        </div>`;
    } else {
      log.innerHTML = messages
        .map((m) => {
          if (m.role === 'typing') {
            return `<div class="typing" aria-label="thinking">
              <span class="typing-dot"></span>
              <span class="typing-dot"></span>
              <span class="typing-dot"></span>
            </div>`;
          }
          if (m.role === 'user') {
            return `<div class="bubble-wrap user">
              <div class="bubble user">${escapeHtml(m.text)}</div>
              <div class="bubble-time">${escapeHtml(formatTime(m.ts))}</div>
            </div>`;
          }
          const srcList = m.sources || [];
          const sourcesHtml = srcList.length
            ? `<div class="sources">
                <div class="sources-label">Evidence retrieved via RAG</div>
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
          return `<div class="bubble ai">
            <div class="ai-head">
              <span class="ai-name">${escapeHtml(orgName)}</span>
              <span class="model-chip">${escapeHtml(String(modelLabel))}</span>
            </div>
            <div class="ai-body">${escapeHtml(m.text)}</div>
            ${sourcesHtml}
          </div>`;
        })
        .join('');
      log.scrollTop = log.scrollHeight;
    }

    root.querySelector('#chat-switch').onclick = () => navigate('cases');
    root.querySelectorAll('.quick-queries button').forEach((btn) => {
      btn.onclick = () => send(QUICK_QUERIES[Number(btn.dataset.q)]);
    });
    root.querySelector('#chat-send').onclick = () => {
      const input = root.querySelector('#chat-input');
      send(input.value);
      input.value = '';
      input.style.height = 'auto';
    };
    const input = root.querySelector('#chat-input');
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        send(input.value);
        input.value = '';
        input.style.height = 'auto';
      }
    });
    input.addEventListener('input', () => {
      input.style.height = 'auto';
      input.style.height = `${Math.min(100, input.scrollHeight)}px`;
    });

    const ctxEl = root.querySelector('#chat-context');
    root.querySelector('#chat-ctx-toggle')?.addEventListener('click', () => {
      ctxEl.classList.toggle('open');
    });
    root.querySelector('#chat-ctx-close')?.addEventListener('click', () => {
      ctxEl.classList.remove('open');
    });
  }

  async function send(question) {
    const q = String(question || '').trim();
    if (!q) return;
    const id = activeCase().id;
    if (!id) {
      toast('Select a case first', true);
      return;
    }
    const messages = getChatMessages(id);
    messages.push({ role: 'user', text: q, ts: Date.now() });
    messages.push({ role: 'typing' });
    if (isNavCurrent()) paint();
    try {
      const res = await window.api.fetchAPI(`/cases/${encodeURIComponent(id)}/chat`, {
        method: 'POST',
        body: { question: q },
      });
      const msgs = getChatMessages(id);
      if (msgs.length && msgs[msgs.length - 1].role === 'typing') {
        msgs.pop();
      }
      msgs.push({
        role: 'ai',
        text: res.answer || res.error || JSON.stringify(res),
        sources: res.sources || [],
      });
      if (isNavCurrent()) paint();
    } catch (err) {
      const msgs = getChatMessages(id);
      if (msgs.length && msgs[msgs.length - 1].role === 'typing') {
        msgs.pop();
      }
      msgs.push({ role: 'ai', text: `Error: ${err.message}`, sources: [] });
      if (isNavCurrent()) paint();
      toast(err.message, true);
    }
  }

  paint();
  return { cleanup() {} };
}
