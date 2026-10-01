import { escapeHtml } from '../util.js';

export async function renderSettings(root, ctx) {
  const { toast, state } = ctx;
  let health = { status: 'unknown' };
  try {
    health = await window.api.healthCheck();
  } catch {
    health = { status: 'down' };
  }

  if (health.aiInfo) {
    state.aiInfo = health.aiInfo;
  }

  const online = health.status === 'ok';
  const apiBase = escapeHtml(window.api.API_BASE || 'http://localhost:3000/api');
  const aiService = escapeHtml(health.ai_service || 'http://127.0.0.1:8000');

  const ai = state.aiInfo || ctx.aiInfo || {};
  const cfg = state.config || ctx.config || {};
  const sys = cfg.system || {};
  const inv = cfg.investigator || {};

  const llm = ai.model || 'qwen2.5:3b';
  const temperature = ai.temperature ?? 0.1;
  const vectorDb = ai.vectorDb || 'ChromaDB';
  const embedding = ai.embeddingModel || '—';
  const channel = sys.channelName || 'forensicchannel';
  const mode = sys.mode || '—';
  const fabricLabel = sys.useRealFabric
    ? `Hyperledger Fabric · ${channel}`
    : `Mock Chain · ${channel}`;

  root.innerHTML = `
    <div class="settings-grid">
      <div class="panel panel-flush-top">
        <h2>Connection</h2>
        <table class="table">
          <tbody>
            <tr>
              <td>Backend API</td>
              <td>
                <span class="api-mono">${apiBase}</span>
                <span class="badge badge-inline ${online ? 'active' : 'error'}" id="set-status-badge">${online ? 'ONLINE' : 'OFFLINE'}</span>
              </td>
            </tr>
            <tr>
              <td>AI Service</td>
              <td class="mono" id="set-ai-service">${aiService}</td>
            </tr>
          </tbody>
        </table>
        <button class="btn secondary sm btn-gap-top" id="set-ping">Ping</button>
      </div>
      <div class="panel panel-flush-top">
        <h2>System Info</h2>
        <table class="table">
          <tbody>
            <tr><td>LLM</td><td>${escapeHtml(String(llm))}</td></tr>
            <tr><td>Temperature</td><td>${escapeHtml(String(temperature))}</td></tr>
            <tr><td>Vector DB</td><td>${escapeHtml(String(vectorDb))}</td></tr>
            <tr><td>Embedding Model</td><td>${escapeHtml(String(embedding))}</td></tr>
            <tr><td>Blockchain</td><td>${escapeHtml(fabricLabel)}</td></tr>
            <tr><td>Mode</td><td>${escapeHtml(String(mode))}</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel panel-flush-top panel-stack">
      <h2>Investigator Profile</h2>
      <div class="field">
        <label for="inv-name">Name</label>
        <input id="inv-name" type="text" value="${escapeHtml(inv.name || '')}" />
      </div>
      <div class="field">
        <label for="inv-initials">Initials</label>
        <input id="inv-initials" type="text" value="${escapeHtml(inv.initials || '')}" />
      </div>
      <div class="field">
        <label for="inv-role">Role</label>
        <input id="inv-role" type="text" value="${escapeHtml(inv.role || '')}" />
      </div>
      <div class="field">
        <label for="inv-chain">Chain ID</label>
        <input id="inv-chain" type="text" value="${escapeHtml(inv.chainId || '')}" />
      </div>
      <div class="field">
        <label for="inv-workspace">Workspace</label>
        <input id="inv-workspace" type="text" value="${escapeHtml(inv.workspace || '')}" />
      </div>
      <div class="field">
        <label for="inv-gpu">GPU</label>
        <input id="inv-gpu" type="text" value="${escapeHtml(inv.gpu || '')}" />
      </div>
      <button class="btn primary btn-gap-sm" id="inv-save">Save Profile</button>
    </div>

    <div class="privacy-note">
      <span aria-hidden="true">🔒</span>
      <div>All processing is fully offline. Evidence never leaves this machine.</div>
    </div>
  `;

  root.querySelector('#set-ping').onclick = async () => {
    const btn = root.querySelector('#set-ping');
    const badge = root.querySelector('#set-status-badge');
    const aiEl = root.querySelector('#set-ai-service');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner dark"></span>Pinging…';
    const h = await window.api.healthCheck();
    const ok = h.status === 'ok';
    if (h.aiInfo) state.aiInfo = h.aiInfo;
    toast(ok ? 'Backend online ✓' : 'Backend offline ✗', !ok);
    if (badge) {
      badge.className = `badge ${ok ? 'active' : 'error'}`;
      badge.textContent = ok ? 'ONLINE' : 'OFFLINE';
    }
    if (aiEl && h.ai_service) aiEl.textContent = h.ai_service;
    btn.disabled = false;
    btn.textContent = 'Ping';
  };

  root.querySelector('#inv-save').onclick = async () => {
    const investigator = {
      name: root.querySelector('#inv-name').value.trim(),
      initials: root.querySelector('#inv-initials').value.trim(),
      role: root.querySelector('#inv-role').value.trim(),
      chainId: root.querySelector('#inv-chain').value.trim(),
      workspace: root.querySelector('#inv-workspace').value.trim(),
      gpu: root.querySelector('#inv-gpu').value.trim(),
    };
    const btn = root.querySelector('#inv-save');
    btn.disabled = true;
    try {
      const res = await window.api.fetchAPI('/config', {
        method: 'PUT',
        body: { investigator },
      });
      if (res.config) {
        state.config = { ...(state.config || {}), ...res.config };
        if (res.config.investigator) {
          state.config.investigator = res.config.investigator;
        }
      } else {
        state.config = state.config || {};
        state.config.investigator = investigator;
      }
      toast('Profile saved');
    } catch (err) {
      toast(err.message || String(err), true);
    } finally {
      btn.disabled = false;
    }
  };
}
