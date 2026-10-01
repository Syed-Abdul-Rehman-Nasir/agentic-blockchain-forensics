import { escapeHtml } from '../util.js';

export async function renderReports(root, ctx) {
  const { state, navigate, toast, setSelectedCase, caseBadge } = ctx;

  let cases = [];
  try {
    const data = await window.api.fetchAPI('/cases');
    cases = data.cases || [];
  } catch (err) {
    root.innerHTML = `<div class="panel empty">${escapeHtml(err.message)}</div>`;
    return;
  }

  if (!cases.length) {
    root.innerHTML = `<div class="panel empty"><p>No cases yet.</p>
      <button class="btn" id="rep-cases">Go to Cases</button></div>`;
    root.querySelector('#rep-cases').onclick = () => navigate('cases');
    return;
  }

  let selected = state.selectedCaseId || null;
  let previewBlobUrl = null;
  let lastHtml = null;
  let lastCaseId = null;

  function revokePreview() {
    if (previewBlobUrl) {
      URL.revokeObjectURL(previewBlobUrl);
      previewBlobUrl = null;
    }
  }

  async function fetchReport(caseId) {
    return window.api.fetchAPI(`/cases/${encodeURIComponent(caseId)}/report`);
  }

  async function openReport(caseId) {
    try {
      toast('Generating report…');
      const data = lastCaseId === caseId && lastHtml
        ? { html: lastHtml }
        : await fetchReport(caseId);
      if (!data.html) throw new Error('No HTML returned');
      lastHtml = data.html;
      lastCaseId = caseId;
      await window.api.openReportHtml(data.html, caseId);
      toast('Report opened');
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function saveReport(caseId) {
    try {
      toast('Generating report…');
      const data = lastCaseId === caseId && lastHtml
        ? { html: lastHtml }
        : await fetchReport(caseId);
      if (!data.html) throw new Error('No HTML returned');
      lastHtml = data.html;
      lastCaseId = caseId;
      const path = await window.api.saveReportHtml(data.html, caseId);
      if (path) toast(`Saved: ${path}`);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function showEmptyPreview() {
    const area = root.querySelector('#rep-preview');
    if (!area) return;
    revokePreview();
    area.innerHTML = `
      <div class="report-empty">
        <div class="report-empty-icon" aria-hidden="true">📄</div>
        <div>Select a case to generate and preview its report</div>
      </div>`;
  }

  async function loadPreview(caseId, caseName) {
    selected = caseId;
    const c = cases.find((x) => x.case_id === caseId);
    setSelectedCase(caseId, caseName || c?.name);
    paintSidebar();

    const area = root.querySelector('#rep-preview');
    area.innerHTML = `
      <div class="report-loading">
        <span class="spinner dark"></span>
        Generating report for ${escapeHtml(caseName || caseId)}…
      </div>`;

    try {
      const data = await fetchReport(caseId);
      const html = typeof data === 'string' ? data : data.html;
      if (!html) throw new Error('No HTML returned');
      lastHtml = html;
      lastCaseId = caseId;
      revokePreview();
      const blob = new Blob([html], { type: 'text/html' });
      previewBlobUrl = URL.createObjectURL(blob);
      area.innerHTML = `
        <div class="report-toolbar">
          <div class="report-toolbar-left">
            <strong>${escapeHtml(caseName || caseId)}</strong>
            <span class="case-chip mono">${escapeHtml(caseId)}</span>
          </div>
          <div class="report-toolbar-right">
            <button class="btn secondary sm" id="rep-open-preview">Open in Browser</button>
            <button class="btn secondary sm" id="rep-dl-preview">Download</button>
          </div>
        </div>
        <iframe class="report-iframe" title="Report preview"></iframe>`;
      area.querySelector('iframe').src = previewBlobUrl;
      area.querySelector('#rep-open-preview').onclick = () => openReport(caseId);
      area.querySelector('#rep-dl-preview').onclick = () => saveReport(caseId);
    } catch (err) {
      area.innerHTML = `<div class="empty">Failed to generate report: ${escapeHtml(err.message)}</div>`;
    }
  }

  function paintSidebar() {
    const side = root.querySelector('#rep-sidebar');
    if (!side) return;
    side.innerHTML = cases
      .map((c) => {
        const b = caseBadge ? caseBadge(c.status) : { cls: 'closed', label: c.status || '—' };
        const sel = c.case_id === selected ? 'selected' : '';
        const name = c.name || c.case_id;
        return `<div class="report-case ${sel}" data-id="${escapeHtml(c.case_id)}" data-name="${escapeHtml(name)}">
          <div class="report-case-name">${escapeHtml(name)}</div>
          <div class="mono report-case-id">${escapeHtml(c.case_id)}</div>
          <div class="report-case-meta">
            <span class="muted">${escapeHtml((c.created_at || '').slice(0, 10))}</span>
            <span class="badge ${b.cls}">${escapeHtml(b.label)}</span>
          </div>
          <div class="report-case-actions">
            <button class="btn primary sm rep-preview" data-id="${escapeHtml(c.case_id)}" data-name="${escapeHtml(name)}">Preview</button>
            <button class="btn ghost sm rep-open" data-id="${escapeHtml(c.case_id)}">Open</button>
            <button class="btn ghost sm rep-save" data-id="${escapeHtml(c.case_id)}" title="Download">⬇</button>
          </div>
        </div>`;
      })
      .join('');

    side.querySelectorAll('.report-case').forEach((row) => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button')) return;
        loadPreview(row.dataset.id, row.dataset.name);
      });
    });
    side.querySelectorAll('.rep-preview').forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        loadPreview(btn.dataset.id, btn.dataset.name);
      };
    });
    side.querySelectorAll('.rep-open').forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        openReport(btn.dataset.id);
      };
    });
    side.querySelectorAll('.rep-save').forEach((btn) => {
      btn.onclick = (e) => {
        e.stopPropagation();
        saveReport(btn.dataset.id);
      };
    });
  }

  root.innerHTML = `
    <div class="report-split">
      <div class="report-sidebar" id="rep-sidebar"></div>
      <div class="report-preview" id="rep-preview"></div>
    </div>
  `;

  paintSidebar();
  showEmptyPreview();

  return {
    cleanup() {
      revokePreview();
    },
  };
}
