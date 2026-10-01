import { escapeHtml } from '../util.js';

export async function renderInvestigators(root, cfgCtx) {
  const ctx = cfgCtx || {};
  const inv = ctx.config?.investigator || ctx.state?.config?.investigator || {};
  const sys = ctx.config?.system || ctx.state?.config?.system || {};
  const ai = ctx.aiInfo || ctx.state?.aiInfo || {};
  const br = ctx.config?.branding || ctx.state?.config?.branding || {};

  const name = inv.name || '—';
  const initials = inv.initials || '??';
  const role = inv.role || 'Investigator';
  const chainId = inv.chainId || '—';
  const workspace = inv.workspace || '—';
  const gpu = inv.gpu || '—';
  const model = ai.model || '—';
  const mode = sys.mode || '—';
  const framework = br.orgName
    ? `${br.orgName} v1.0.0`
    : 'Agentic Blockchain Forensics v1.0.0';
  const mlModels = 'XGBoost + PyTorch Autoencoder';

  root.innerHTML = `
    <div class="panel profile-card animate-in">
      <div class="avatar">${escapeHtml(initials)}</div>
      <h2 class="profile-name">${escapeHtml(name)}</h2>
      <p class="profile-role">${escapeHtml(role)}</p>
      <div class="profile-divider"></div>
      <div class="profile-chips">
        <span class="profile-chip">Cases Handled</span>
        <span class="profile-chip">Chain Identity</span>
        <span class="profile-chip">Clearance Level</span>
      </div>
      <table class="table profile-table">
        <tbody>
          <tr><td>Workspace</td><td>${escapeHtml(workspace)}</td></tr>
          <tr><td>LLM</td><td>${escapeHtml(model)} (${escapeHtml(mode)})</td></tr>
          <tr><td>Chain ID</td><td class="mono">${escapeHtml(chainId)}</td></tr>
          <tr><td>Framework</td><td>${escapeHtml(framework)}</td></tr>
          <tr><td>GPU</td><td>${escapeHtml(gpu)}</td></tr>
          <tr><td>Models</td><td>${escapeHtml(mlModels)}</td></tr>
        </tbody>
      </table>
    </div>
  `;
}
