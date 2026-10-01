/**
 * Agentic Blockchain Forensics renderer — view routing and shared state.
 */

import { escapeHtml } from './util.js';
import { renderDashboard } from './views/dashboard.js';
import { renderCases } from './views/cases.js';
import { renderEvidence } from './views/evidence.js';
import { renderChat } from './views/chat.js';
import { renderBlockchain } from './views/blockchain.js';
import { renderReports } from './views/reports.js';
import { renderInvestigators } from './views/investigators.js';
import { renderSettings } from './views/settings.js';

const TITLES = {
  dashboard: 'Investigator Dashboard',
  cases: 'Cases',
  evidence: 'Evidence Vault',
  chat: 'AI Agents',
  reports: 'Reports',
  blockchain: 'Blockchain Ledger',
  investigators: 'Investigators',
  settings: 'Settings',
};

const state = {
  view: 'dashboard',
  selectedCaseId: null,
  selectedCaseName: null,
  verifyCache: {}, // caseId → { isValid, tampered, verifiedAt, storedHash, recomputedHash, evidenceId, acquisitionHash, imageName, sealedAt, submittedBy }
  config: null, // loaded from GET /api/config
  aiInfo: null, // loaded from GET /health (aiInfo sub-object)
  healthTimer: null,
  cleanup: null,
  navEpoch: 0,
};

const content = document.getElementById('content');
const pageTitle = document.getElementById('page-title');
const activeCaseChip = document.getElementById('active-case-chip');
const modalRoot = document.getElementById('modal-root');
const toastRoot = document.getElementById('toast-root');

export function getState() {
  return state;
}

export function setSelectedCase(caseId, caseName) {
  state.selectedCaseId = caseId;
  state.selectedCaseName = caseName || caseId;
  activeCaseChip.textContent = caseId
    ? `Case: ${state.selectedCaseName}`
    : 'No case selected';
}

export function setVerifyResult(caseId, result) {
  if (!caseId) return;
  state.verifyCache[caseId] = {
    isValid: result.isValid,
    tampered: result.tampered,
    verifiedAt: new Date().toISOString(),
    storedHash: result.storedHash || '',
    recomputedHash: result.recomputedHash || '',
    evidenceId: result.evidenceId || '',
    acquisitionHash: result.acquisitionHash || '',
    imageName: result.imageName || '',
    sealedAt: result.sealedAt || '',
    submittedBy: result.submittedBy || '',
  };
}

/** @deprecated Replaced by setVerifyResult — kept as no-op shim for older call sites */
export function setChainIntegrity(_val) {
  /* replaced by setVerifyResult */
}

export function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = `toast${isError ? ' error' : ''}`;
  el.textContent = message;
  toastRoot.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

export function openModal(html) {
  modalRoot.innerHTML = `<div class="modal">${html}</div>`;
  modalRoot.hidden = false;
  modalRoot.removeAttribute('hidden');
}

export function closeModal() {
  modalRoot.hidden = true;
  modalRoot.setAttribute('hidden', '');
  modalRoot.innerHTML = '';
}

export function statusBadge(status) {
  const s = String(status || 'pending').toLowerCase();
  if (s === 'complete' || s === 'mounted') return { cls: 'closed', label: 'Closed' };
  if (s === 'error') return { cls: 'error', label: 'Error' };
  if (s === 'analysing' || s === 'queued' || s === 'pending') {
    return { cls: 'active', label: 'Active' };
  }
  if (s === 'review') return { cls: 'review', label: 'Review' };
  return { cls: 'review', label: status || 'Unknown' };
}

/** Map analysing statuses to Active; complete→can show Review for demo browsing */
export function caseBadge(status) {
  const s = String(status || 'pending').toLowerCase();
  if (['analysing', 'queued', 'pending', 'mounting'].includes(s)) {
    return { cls: 'active', label: 'Active' };
  }
  if (s === 'error') return { cls: 'error', label: 'Error' };
  if (s === 'complete') return { cls: 'review', label: 'Review' };
  return { cls: 'closed', label: 'Closed' };
}

export function initTilt() {
  if (window.matchMedia('(pointer: coarse)').matches) return;
  content.querySelectorAll('.stat-card').forEach((card) => {
    if (card.dataset.tiltBound) return;
    card.dataset.tiltBound = '1';
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = (e.clientY - rect.top) / rect.height - 0.5;
      const y = (e.clientX - rect.left) / rect.width - 0.5;
      card.style.transition = 'transform 60ms linear';
      card.style.transform = `perspective(600px) rotateX(${-x * 4}deg) rotateY(${y * 4}deg)`;
    });
    card.addEventListener('mouseleave', () => {
      card.style.transform = '';
      card.style.transition = 'transform 0.3s var(--ease)';
    });
  });
}

function animatePanels() {
  content.querySelectorAll('.panel').forEach((p, i) => {
    p.style.animationDelay = `${i * 50}ms`;
    p.classList.add('animate-in');
  });
}

export async function navigate(view, params = {}) {
  if (state.cleanup) {
    try { state.cleanup(); } catch { /* ignore */ }
    state.cleanup = null;
  }

  if (params.caseId) {
    setSelectedCase(params.caseId, params.caseName || params.caseId);
  }

  state.view = view;
  pageTitle.textContent = TITLES[view] || view;
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === view);
  });

  content.innerHTML = '<div class="empty">Loading…</div>';

  const navEpoch = ++state.navEpoch;
  const isNavCurrent = () => state.navEpoch === navEpoch;

  const renderers = {
    dashboard: renderDashboard,
    cases: renderCases,
    evidence: renderEvidence,
    chat: renderChat,
    reports: renderReports,
    blockchain: renderBlockchain,
    investigators: renderInvestigators,
    settings: renderSettings,
  };

  const fn = renderers[view] || renderDashboard;
  try {
    const result = await fn(content, {
      state,
      navigate,
      toast,
      openModal,
      closeModal,
      setSelectedCase,
      setChainIntegrity,
      setVerifyResult,
      caseBadge,
      params,
      isNavCurrent,
      config: state.config,
      aiInfo: state.aiInfo,
    });
    if (!isNavCurrent()) return;
    if (result && typeof result.cleanup === 'function') {
      state.cleanup = result.cleanup;
    }
    if (view === 'cases' && params.openNew && result && typeof result.openNew === 'function') {
      result.openNew();
    }
    animatePanels();
    initTilt();
  } catch (err) {
    if (!isNavCurrent()) return;
    content.innerHTML = `<div class="panel empty">Failed to load view: ${escapeHtml(err.message || err)}</div>`;
    toast(err.message || String(err), true);
  }
}

async function refreshHealth() {
  const fabricDot = document.getElementById('fabric-dot');
  const fabricLabel = document.getElementById('fabric-label');
  const fabricStatus = document.getElementById('fabric-status');
  const agentsDot = document.getElementById('agents-dot');
  const agentsLabel = document.getElementById('agents-label');

  const health = await window.api.healthCheck();
  if (health && health.aiInfo) {
    state.aiInfo = health.aiInfo;
  }
  const online = health && health.status === 'ok';
  fabricDot.className = `dot ${online ? 'green' : 'red'}`;
  // mockChain is always available when the Node backend is up — do not claim Fabric Online
  fabricLabel.textContent = online ? 'Active' : 'Offline';
  if (fabricStatus) {
    fabricStatus.style.opacity = '0.55';
    requestAnimationFrame(() => {
      fabricStatus.style.opacity = '1';
    });
  }

  // Agents Running if any selected case is analysing
  let running = false;
  if (state.selectedCaseId && online) {
    try {
      const st = await window.api.fetchAPI(`/cases/${encodeURIComponent(state.selectedCaseId)}/status`);
      running = st.status === 'analysing' || st.status === 'queued' || st.running === true
        || (st.investigation && st.investigation.phase === 'analysing');
    } catch { /* ignore */ }
  }
  agentsDot.className = `dot ${running ? 'green' : 'grey'}`;
  agentsLabel.textContent = running ? 'Running' : 'Idle';
}

async function loadConfig() {
  try {
    const cfg = await window.api.fetchAPI('/config');
    state.config = cfg;
    applyBranding(cfg.branding);
  } catch (err) {
    console.warn('[config] Could not load app config:', err.message);
  }
}

function applyBranding(branding) {
  if (!branding) return;
  const markEl = document.querySelector('.brand-mark');
  const nameEl = document.querySelector('.brand-name');
  const subEl = document.querySelector('.brand-sub');
  if (markEl && branding.orgMark) markEl.textContent = branding.orgMark;
  if (nameEl && branding.orgName) nameEl.textContent = branding.orgName;
  if (subEl && branding.orgSubtitle) subEl.textContent = branding.orgSubtitle;

  const tbMark = document.getElementById('titlebar-mark');
  const tbName = document.getElementById('titlebar-name');
  const tbSub = document.getElementById('titlebar-sub');
  if (tbMark && branding.orgMark) tbMark.textContent = branding.orgMark;
  if (tbName && branding.orgName) tbName.textContent = branding.orgName;
  if (tbSub && branding.orgSubtitle) tbSub.textContent = branding.orgSubtitle;

  if (branding.windowTitle) document.title = branding.windowTitle;
}

function bindNav() {
  document.getElementById('nav').addEventListener('click', (e) => {
    const btn = e.target.closest('.nav-item');
    if (!btn) return;
    navigate(btn.dataset.view);
  });

  modalRoot.addEventListener('click', (e) => {
    if (e.target === modalRoot) {
      closeModal();
      return;
    }
    // Cancel / dismiss controls inside the modal (works even if per-button handlers fail)
    if (e.target.closest('[data-modal-close], #nc-cancel')) {
      e.preventDefault();
      e.stopPropagation();
      closeModal();
    }
  });
}

bindNav();
loadConfig();
refreshHealth();
state.healthTimer = setInterval(refreshHealth, 8000);
navigate('dashboard');
