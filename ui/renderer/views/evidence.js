import { escapeHtml } from '../util.js';

const STAGE_DEFS = [
  { key: 'disk_mount', label: 'Mounting' },
  { key: 'registry', label: 'Registry' },
  { key: 'events', label: 'Events' },
  { key: 'browser', label: 'Browser' },
  { key: 'prefetch', label: 'Prefetch' },
  { key: 'threat_analysis', label: 'ML Analysis' },
  { key: 'rag_indexing', label: 'RAG Indexing' },
  { key: 'blockchain', label: 'Blockchain Commit' },
];

const FEATURE_KEYS = [
  'failed_logon_count',
  'logon_outside_hours',
  'new_service_installed',
  'scheduled_task_created',
  'process_creation_count',
  'unique_usb_devices',
  'autorun_entries',
  'tor_visits',
  'total_urls',
  'known_malware_executed',
  'total_executions',
  'sensitive_file_access',
];

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

export async function renderEvidence(root, ctx) {
  const { state, navigate, toast, setSelectedCase } = ctx;
  let caseId = state.selectedCaseId;
  let pollTimer = null;

  if (!caseId) {
    try {
      const data = await window.api.fetchAPI('/cases');
      const cases = data.cases || [];
      if (cases.length) {
        caseId = cases[0].case_id;
        setSelectedCase(caseId, cases[0].name);
      }
    } catch { /* ignore */ }
  }

  if (!caseId) {
    root.innerHTML = `
      <div class="panel empty">
        <p>No case selected.</p>
        <button class="btn" id="ev-goto-cases">Go to Cases</button>
      </div>`;
    root.querySelector('#ev-goto-cases').onclick = () => navigate('cases');
    return;
  }

  function stageState(status, stages, investigation) {
    const done = new Set(stages || []);
    const invPhase = investigation?.phase;
    let currentKey = null;
    for (const s of STAGE_DEFS) {
      if (s.key === 'blockchain') {
        if (invPhase === 'done') done.add('blockchain');
        else if (invPhase === 'blockchain' || (status === 'complete' && invPhase !== 'done')) {
          currentKey = 'blockchain';
        }
        continue;
      }
      if (!done.has(s.key)) {
        if (!currentKey && (status === 'analysing' || status === 'queued' || status === 'pending')) {
          currentKey = s.key;
        }
        break;
      }
    }
    if (status === 'complete' && (invPhase === 'done' || !invPhase)) {
      done.add('blockchain');
      currentKey = null;
    }
    return { done, currentKey };
  }

  function scoreClass(n) {
    if (n == null || Number.isNaN(n)) return 'low';
    if (n > 0.7) return 'high';
    if (n >= 0.4) return 'mid';
    return 'low';
  }

  function borderForCard(card) {
    if (card.flagged || (card.score != null && Number(card.score) > 0.7)) {
      return 'var(--type-threat)';
    }
    if (card.amber) return 'var(--amber)';
    return (TYPE_META[card.type] || TYPE_META.REGISTRY).color;
  }

  function renderThreatSummary(threats) {
    const list = threats.threats || threats.flagged || [];
    const first = list[0] || {};
    let data = {};
    try {
      if (first.data_json) data = typeof first.data_json === 'string' ? JSON.parse(first.data_json) : first.data_json;
      else if (first.features) data = first.features;
      else if (threats.features) data = threats.features;
    } catch { data = {}; }

    const xgb = first.xgboost_score ?? threats.xgboost_score ?? list.find((t) => t.xgboost_score != null)?.xgboost_score;
    const ae = first.autoencoder_score ?? threats.autoencoder_score ?? first.anomaly_score;
    const flagged = (threats.flagged || []).length > 0 || list.some((t) => t.flagged);
    const highRisk = flagged || (xgb != null && Number(xgb) > 0.7);
    const hotKeys = new Set(['known_malware_executed', 'sensitive_file_access', 'tor_visits']);

    const featureRows = FEATURE_KEYS.map((k) => {
      const v = data[k] ?? data[k.replace(/_/g, '')] ?? 0;
      const num = Number(v) || 0;
      let cls = 'feat-zero';
      if (num !== 0) cls = hotKeys.has(k) ? 'feat-hot' : 'feat-nonzero';
      return `<tr>
        <td>${escapeHtml(k)}</td>
        <td class="${cls}">${escapeHtml(String(v ?? 0))}</td>
      </tr>`;
    }).join('');

    const riskClass = highRisk ? 'risk-high' : 'risk-low';

    return `
      <div class="panel threat-panel threat-summary">
        <div class="threat-panel-title">Threat Assessment</div>
        <div class="threat-divider"></div>
        <div class="muted threat-label">Supervised ML Score</div>
        <div class="threat-score ${scoreClass(Number(xgb))}">${xgb != null ? Number(xgb).toFixed(3) : '—'}</div>
        <div class="muted threat-label threat-label-spaced">Anomaly Detection Score</div>
        <div class="threat-ae">${ae != null ? Number(ae).toFixed(3) : '—'}</div>
        <div class="threat-risk-wrap">
          <span class="badge ${riskClass}">${highRisk ? 'HIGH RISK' : 'LOW RISK'}</span>
        </div>
        <div class="threat-divider"></div>
        <div class="muted threat-label threat-label-features">Feature Breakdown</div>
        <table class="feature-mini">${featureRows}</table>
      </div>`;
  }

  async function refresh() {
    const status = await window.api.fetchAPI(`/cases/${encodeURIComponent(caseId)}/status`);
    const { done, currentKey } = stageState(
      status.status,
      status.stages,
      status.investigation
    );

    const doneCount = STAGE_DEFS.filter((s) => done.has(s.key)).length;
    const stagesHtml = STAGE_DEFS.map((s) => {
      const isDone = done.has(s.key);
      const isCurrent = currentKey === s.key;
      const cls = isDone ? 'done' : isCurrent ? 'current' : 'pending';
      const mark = isDone ? '✓' : isCurrent ? '▶' : '○';
      const stateLabel = isDone ? 'Complete' : isCurrent ? 'In progress' : 'Waiting';
      return `<div class="stage ${cls}">
        <span>${mark}</span>
        <div class="stage-name">${s.label}</div>
        <div class="stage-state">${stateLabel}</div>
      </div>`;
    }).join('');

    const stillRunning =
      status.status === 'analysing' ||
      status.status === 'queued' ||
      status.running ||
      (status.investigation &&
        ['analysing', 'blockchain'].includes(status.investigation.phase));

    let artifactsHtml = '';
    let threatHtml = '';
    if (status.status === 'complete' || done.has('threat_analysis')) {
      try {
        const [arts, threats] = await Promise.all([
          window.api.fetchAPI(`/cases/${encodeURIComponent(caseId)}/artifacts`),
          window.api.fetchAPI(`/cases/${encodeURIComponent(caseId)}/threats`),
        ]);
        artifactsHtml = renderArtifacts(arts, threats);
        threatHtml = renderThreatSummary(threats);
      } catch (err) {
        artifactsHtml = `<div class="muted">Could not load artifacts: ${escapeHtml(err.message)}</div>`;
      }
    } else if (stillRunning) {
      artifactsHtml = '<div class="muted">Waiting for analysis to finish…</div>';
    }

    const acqRaw = status.acquisition_hash;
    const acqMissing =
      acqRaw == null ||
      acqRaw === '' ||
      String(acqRaw).toUpperCase() === 'NOT_EMBEDDED';
    const acqHtml = acqMissing
      ? '<span class="muted hash-missing">Not embedded in source image</span>'
      : `<code>${escapeHtml(acqRaw)}</code>`;
    const sys = status.system_hash || '—';

    const statusCls =
      status.status === 'complete'
        ? 'closed'
        : status.status === 'error'
          ? 'error'
          : 'active';

    const progressLabel = status.progress || `${doneCount}/8`;
    const showMain = status.status === 'complete' || done.has('threat_analysis');

    root.innerHTML = `
      <div class="panel ev-header-panel">
        <div class="toolbar ev-header-toolbar">
          <div>
            <h2 class="ev-case-title">${escapeHtml(status.name || caseId)}</h2>
            <div class="ev-case-meta">
              <span class="case-chip mono">${escapeHtml(caseId)}</span>
              <span class="badge ${statusCls}">${escapeHtml(status.status || '')}</span>
              <span class="muted ev-case-progress">${escapeHtml(progressLabel)}</span>
            </div>
          </div>
          <div class="ev-header-actions">
            <button class="btn secondary" id="ev-chat">Ask AI →</button>
            <button class="btn ghost" id="ev-chain">View Ledger →</button>
          </div>
        </div>
        <div class="hash-row">
          <div class="hash-box">
            <div class="hl">Acquisition Hash</div>
            ${acqHtml}
          </div>
          <div class="hash-box">
            <div class="hl">System SHA-256</div>
            <code>${escapeHtml(sys)}</code>
          </div>
        </div>
        ${
          stillRunning
            ? `<h3 class="ev-progress-heading">Analysis Progress</h3>
               <div class="stages">${stagesHtml}</div>`
            : ''
        }
      </div>
      ${
        showMain
          ? `<div class="evidence-split ev-split">
              <div class="panel">
                <div class="toolbar ev-artifacts-toolbar">
                  <h2>Artifacts</h2>
                </div>
                ${artifactsHtml}
              </div>
              ${threatHtml || '<div class="panel threat-panel threat-summary"><div class="threat-panel-title">Threat Assessment</div><div class="muted">No threat data yet</div></div>'}
            </div>`
          : stillRunning
            ? ''
            : `<div class="panel"><h2>Artifacts</h2>${artifactsHtml || '<div class="muted">No artifacts yet.</div>'}</div>`
      }
    `;

    root.querySelector('#ev-chat').onclick = () =>
      navigate('chat', { caseId, caseName: status.name });
    root.querySelector('#ev-chain').onclick = () =>
      navigate('blockchain', { caseId, caseName: status.name });

    if (!stillRunning && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function renderArtifacts(arts, threats) {
    const flaggedIds = new Set(
      (threats.flagged || []).map((t) => t.id).filter(Boolean)
    );
    const cards = [];

    const push = (type, agent, items, mapper) => {
      for (const item of items || []) {
        cards.push(mapper(type, agent, item));
      }
    };

    push('REGISTRY', 'Collection Agent', arts.registry, (type, agent, r) => ({
      type,
      agent,
      title: `${r.hive || ''} ${r.key_path || ''}`.trim() || 'Registry entry',
      detail: r.key_path || r.hive || '',
      ts: r.timestamp,
      hash: r.hash || r.id,
      onChain: true,
      flagged: false,
      amber: false,
    }));
    push('EVENT LOG', 'Collection Agent', arts.events, (type, agent, r) => ({
      type,
      agent,
      title: `Event ${r.event_id} · ${r.channel || ''}`.trim(),
      detail: r.channel || r.provider || '',
      ts: r.timestamp,
      hash: r.hash || r.id,
      onChain: true,
      flagged: false,
      amber: false,
    }));
    push('BROWSER', 'Collection Agent', arts.browser, (type, agent, r) => ({
      type,
      agent,
      title: r.title || r.url || 'Visit',
      detail: r.url || '',
      ts: r.visit_time,
      hash: r.hash || r.url,
      onChain: true,
      flagged: false,
      amber: false,
    }));
    push('PREFETCH', 'Collection Agent', arts.prefetch, (type, agent, r) => {
      const amber = !!String(r.executable || '').toLowerCase().match(/cain|ethereal/);
      return {
        type,
        agent,
        title: r.executable || 'Prefetch',
        detail: r.path || r.executable || '',
        ts: r.last_run,
        hash: r.hash || r.executable,
        onChain: true,
        flagged: amber,
        amber,
      };
    });
    push('THREAT', 'Threat Agent', threats.threats || arts.scored, (type, agent, r) => ({
      type,
      agent,
      title: r.artifact_type || 'Threat assessment',
      detail: r.reason || r.summary || '',
      ts: null,
      hash: r.id,
      onChain: true,
      score: r.xgboost_score,
      flagged: !!(r.flagged || flaggedIds.has(r.id) || (r.xgboost_score != null && Number(r.xgboost_score) > 0.7)),
      amber: false,
    }));

    if (!cards.length) {
      const counts = arts.counts || {};
      return `<div class="muted">Parsed counts — registry ${counts.registry || 0}, events ${counts.events || 0}, browser ${counts.browser || 0}, prefetch ${counts.prefetch || 0}. Open AI Agents for grounded queries.</div>`;
    }

    const total = cards.length;
    const shown = cards.slice(0, 50);
    const overflow =
      total > 50
        ? `<div class="muted ev-overflow-note">Showing 50 of ${total} — view full report for complete listing</div>`
        : '';

    return `
      <span class="chip-stat chip-stat-count">${total} artifact${total === 1 ? '' : 's'}</span>
      <div class="artifact-list">${shown
        .map((c) => {
          const meta = TYPE_META[c.type] || TYPE_META.REGISTRY;
          const border = borderForCard(c);
          const hashStr = c.hash != null ? String(c.hash) : '';
          const hashLine = hashStr ? `SHA: ${truncate(hashStr, 40)}` : '';
          const detail = truncate(c.detail || '', 80);
          return `
      <div class="artifact-card" style="border-left-color:${border}">
        <div class="artifact-card-top">
          <span class="badge ${meta.cls}">${escapeHtml(c.type)}</span>
          <strong class="artifact-card-title">${escapeHtml(c.title || '—')}</strong>
          <span class="muted artifact-card-ts">${escapeHtml((c.ts || '').toString().slice(0, 19) || '')}</span>
        </div>
        ${detail ? `<div class="mono muted artifact-card-detail">${escapeHtml(detail)}</div>` : ''}
        ${hashLine ? `<div class="mono muted artifact-card-hash">${escapeHtml(hashLine)}</div>` : ''}
        <div class="artifact-card-foot">
          <span class="muted artifact-agent">${escapeHtml(c.agent)}</span>
          ${c.onChain ? '<span class="onchain-chip">On-chain ⬡</span>' : ''}
        </div>
      </div>`;
        })
        .join('')}</div>${overflow}`;
  }

  try {
    await refresh();
    pollTimer = setInterval(() => {
      refresh().catch((err) => toast(err.message, true));
    }, 2000);
  } catch (err) {
    root.innerHTML = `<div class="panel empty">${escapeHtml(err.message)}</div>`;
  }

  return {
    cleanup() {
      if (pollTimer) clearInterval(pollTimer);
    },
  };
}
