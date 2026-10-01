import { escapeHtml } from '../util.js';

export async function renderCases(root, ctx) {
  const { navigate, toast, openModal, closeModal, caseBadge } = ctx;
  let searchTimer;

  async function load(filter = '') {
    const data = await window.api.fetchAPI('/cases');
    let cases = data.cases || [];
    const q = filter.trim().toLowerCase();
    if (q) {
      cases = cases.filter(
        (c) =>
          String(c.case_id).toLowerCase().includes(q) ||
          String(c.name || '').toLowerCase().includes(q)
      );
    }
    return cases;
  }

  function counts(cases) {
    const total = cases.length;
    const active = cases.filter((c) =>
      ['analysing', 'queued', 'pending', 'mounting'].includes(String(c.status || '').toLowerCase())
    ).length;
    const complete = cases.filter((c) => String(c.status || '').toLowerCase() === 'complete').length;
    return { total, active, complete };
  }

  function paint(cases) {
    const c = counts(cases);
    root.innerHTML = `
      <div class="toolbar toolbar-spread">
        <div class="toolbar-left toolbar-cluster">
          <input type="search" id="case-search" placeholder="Search cases…" />
          <span class="chip-stat">Total <strong>${c.total}</strong></span>
          <span class="chip-stat">Active <strong>${c.active}</strong></span>
          <span class="chip-stat">Complete <strong>${c.complete}</strong></span>
        </div>
        <button class="btn primary" id="btn-new-case">+ New Investigation</button>
      </div>
      <div class="panel">
        ${
          cases.length
            ? `<table class="table">
                <thead>
                  <tr>
                    <th>Case ID</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Hashes</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${cases
                    .map((row) => {
                      const b = caseBadge(row.status);
                      const sealed = !!row.system_hash;
                      const fullId = String(row.case_id || '');
                      const idShort =
                        fullId.length > 16 ? `${fullId.slice(0, 16)}…` : fullId;
                      return `<tr class="clickable" data-id="${escapeHtml(row.case_id)}" data-name="${escapeHtml(row.name || row.case_id)}">
                        <td class="mono" title="${escapeHtml(fullId)}">${escapeHtml(idShort)}</td>
                        <td><strong>${escapeHtml(row.name || row.case_id)}</strong></td>
                        <td><span class="badge ${b.cls}">${escapeHtml(b.label)}</span></td>
                        <td>${
                          sealed
                            ? '<span class="status-sealed">Sealed</span>'
                            : '<span class="muted">Pending</span>'
                        }</td>
                        <td>${escapeHtml((row.created_at || '').slice(0, 19).replace('T', ' ') || '—')}</td>
                        <td><button class="btn ghost sm btn-open" data-id="${escapeHtml(row.case_id)}" data-name="${escapeHtml(row.name || row.case_id)}">Open →</button></td>
                      </tr>`;
                    })
                    .join('')}
                </tbody>
              </table>`
            : '<div class="empty">No cases match. Create a new investigation to begin.</div>'
        }
      </div>
    `;

    const openCase = (id, name) => navigate('evidence', { caseId: id, caseName: name });

    root.querySelector('#btn-new-case').addEventListener('click', showNewCaseModal);
    root.querySelectorAll('tr.clickable').forEach((row) => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('.btn-open')) return;
        openCase(row.dataset.id, row.dataset.name);
      });
    });
    root.querySelectorAll('.btn-open').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        openCase(btn.dataset.id, btn.dataset.name);
      });
    });

    const search = root.querySelector('#case-search');
    search.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(async () => {
        try {
          const val = search.value;
          paint(await load(val));
          root.querySelector('#case-search').value = val;
          root.querySelector('#case-search').focus();
        } catch (err) {
          toast(err.message, true);
        }
      }, 250);
    });
  }

  function showNewCaseModal() {
    openModal(`
      <h2>New Investigation</h2>
      <p class="modal-sub">Submit a forensic disk image for AI analysis</p>
      <div class="field">
        <label for="nc-name">Case Name</label>
        <input id="nc-name" type="text" placeholder="e.g. Operation Nightfall" />
      </div>
      <div class="field">
        <label>Disk Image</label>
        <div class="file-pick">
          <span class="path" id="nc-path">No file selected</span>
          <button type="button" class="btn secondary" id="nc-pick">Browse</button>
          <span class="muted file-pick-hint">Supports: E01, .001, .dd, .img, .raw</span>
        </div>
      </div>
      <button type="button" class="advanced-toggle" id="nc-adv">Advanced: set custom ID ▸</button>
      <div class="field" id="nc-id-wrap" hidden>
        <label for="nc-id">Case ID (optional)</label>
        <input id="nc-id" type="text" placeholder="Auto-generated if blank" />
      </div>
      <div class="modal-actions">
        <button type="button" class="btn secondary" id="nc-cancel" data-modal-close>Cancel</button>
        <button type="button" class="btn primary" id="nc-submit">Start Investigation</button>
      </div>
    `);

    let selectedPath = null;
    document.getElementById('nc-cancel')?.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeModal();
    });
    document.getElementById('nc-adv').onclick = () => {
      const wrap = document.getElementById('nc-id-wrap');
      wrap.hidden = !wrap.hidden;
    };
    document.getElementById('nc-pick').onclick = async () => {
      const file = await window.api.selectFile();
      if (!file) return;
      selectedPath = window.api.toWslPath(file);
      document.getElementById('nc-path').textContent = selectedPath;
    };
    document.getElementById('nc-submit').onclick = async () => {
      const name = document.getElementById('nc-name').value.trim();
      const caseId = document.getElementById('nc-id').value.trim() || undefined;
      if (!name) {
        toast('Case name is required', true);
        return;
      }
      if (!selectedPath) {
        toast('Select a disk image', true);
        return;
      }
      const submitBtn = document.getElementById('nc-submit');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner"></span>Starting…';
      try {
        const body = { name, image_path: selectedPath };
        if (caseId) body.case_id = caseId;
        const created = await window.api.fetchAPI('/cases', { method: 'POST', body });
        const id = created.case_id;
        await window.api.fetchAPI(`/cases/${encodeURIComponent(id)}/analyse`, {
          method: 'POST',
          body: { image_path: selectedPath },
        });
        closeModal();
        toast(`Case ${id} submitted — analysis started`);
        navigate('evidence', { caseId: id, caseName: name });
      } catch (err) {
        toast(err.message || String(err), true);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Start Investigation';
      }
    };
  }

  try {
    paint(await load());
  } catch (err) {
    root.innerHTML = `<div class="panel empty">${escapeHtml(err.message)}</div>`;
  }

  return {
    openNew: showNewCaseModal,
    cleanup() {
      clearTimeout(searchTimer);
    },
  };
}
