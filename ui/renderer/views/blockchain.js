import { escapeHtml } from '../util.js';

function formatTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  } catch {
    return String(ts);
  }
}

function truncateHash(h, n = 20) {
  const s = String(h || '');
  if (!s) return '—';
  if (s.length <= n) return s;
  return `${s.slice(0, 10)}…${s.slice(-6)}`;
}

function truncateStr(str, n) {
  const s = String(str || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function analystLabel(analystId, config) {
  const id = String(analystId || '').toLowerCase();
  if (id === 'org1msp' || id === 'system') return 'System (Fabric Node)';
  if (id === 'ai-system') return 'Analysis Agent';
  if (id === 'investigator') {
    return config?.investigator?.name || 'Investigator';
  }
  if (id === 'verify_pass' || id === 'verify_fail') return 'Verification';
  return analystId || '—';
}

function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function cardState(caseId, sealed, verifyCache) {
  const cached = verifyCache[caseId];
  if (cached) {
    if (cached.tampered || cached.isValid === false) {
      return {
        chipText: 'Tampered ✗',
        chipClass: 'chip-bad',
        barClass: 'bar-bad',
        barPct: 100,
        footer: cached.verifiedAt
          ? `Verified ${timeAgo(cached.verifiedAt)} · ${formatTime(cached.verifiedAt)}`
          : 'Tampered',
      };
    }
    if (cached.isValid === true) {
      return {
        chipText: 'Verified ✓',
        chipClass: 'chip-ok',
        barClass: 'bar-ok',
        barPct: 100,
        footer: cached.verifiedAt
          ? `Verified ${timeAgo(cached.verifiedAt)} · ${formatTime(cached.verifiedAt)}`
          : 'Verified',
      };
    }
  }
  if (sealed) {
    return {
      chipText: 'Sealed',
      chipClass: 'chip-sealed',
      barClass: 'bar-sealed',
      barPct: 100,
      footer: 'Not verified',
    };
  }
  return {
    chipText: 'Unverified',
    chipClass: 'chip-neutral',
    barClass: 'bar-neutral',
    barPct: 0,
    footer: 'Not verified',
  };
}

function timelineDotClass(action) {
  const a = String(action || '').toUpperCase();
  if (a === 'EVIDENCE_SEALED') return 'dot-sealed';
  if (a === 'ANALYSIS_COMPLETE') return 'dot-complete';
  if (a === 'QUERY') return 'dot-query';
  if (a === 'VERIFY_PASS') return 'dot-ok';
  if (a === 'VERIFY_FAIL') return 'dot-bad';
  return 'dot-other';
}

function timelineIcon(action) {
  const a = String(action || '').toUpperCase();
  if (a === 'EVIDENCE_SEALED') return '⬡';
  if (a === 'ANALYSIS_COMPLETE') return '✓';
  if (a === 'QUERY') return '?';
  if (a === 'VERIFY_PASS') return '✓';
  if (a === 'VERIFY_FAIL') return '✗';
  return '·';
}

const FILTERS = {
  all: () => true,
  chain: (e) => ['EVIDENCE_SEALED', 'ANALYSIS_COMPLETE'].includes(e.action),
  queries: (e) => e.action === 'QUERY',
  verify: (e) => ['VERIFY_PASS', 'VERIFY_FAIL'].includes(e.action),
};

export async function renderBlockchain(root, ctx) {
  const { state, navigate, toast, setSelectedCase, setVerifyResult, config } = ctx;
  let copyFlashTimer = null;
  let overview = [];
  let selectedCaseId = null;
  let cachedTrail = [];
  let currentFilter = 'all';

  try {
    const data = await window.api.fetchAPI('/blockchain/integrity-overview');
    overview = data.overview || [];
  } catch (err) {
    root.innerHTML = `<div class="panel empty">${escapeHtml(err.message || err)}</div>`;
    return {
      cleanup() {
        if (copyFlashTimer) clearTimeout(copyFlashTimer);
      },
    };
  }

  if (!overview.length) {
    root.innerHTML = `<div class="panel empty"><p>No cases yet.</p>
      <button class="btn" id="bc-cases">Go to Cases</button></div>`;
    root.querySelector('#bc-cases').onclick = () => navigate('cases');
    return {
      cleanup() {
        if (copyFlashTimer) clearTimeout(copyFlashTimer);
      },
    };
  }

  const cache = state.verifyCache || {};
  const cachedIds = Object.keys(cache);
  selectedCaseId =
    cachedIds.find((id) => overview.some((c) => c.case_id === id)) ||
    overview[0].case_id;

  function caseMeta(caseId) {
    return overview.find((c) => c.case_id === caseId) || null;
  }

  function updateDetailVerifyBtn(caseId) {
    const btn = root.querySelector('#bc-detail-verify-btn');
    if (!btn) return;
    const cached = (state.verifyCache || {})[caseId];
    if (cached && cached.isValid === true && !cached.tampered) {
      btn.textContent = 'Re-verify';
    } else {
      btn.textContent = 'Verify';
    }
  }

  function paintCards() {
    const grid = root.querySelector('#bc-overview-grid');
    if (!grid) return;
    grid.innerHTML = overview
      .map((c) => {
        const st = cardState(c.case_id, c.sealed, state.verifyCache || {});
        const selected = c.case_id === selectedCaseId ? 'selected' : '';
        return `
          <div class="integrity-case-card ${selected}" data-case-id="${escapeHtml(c.case_id)}">
            <div class="case-card-header">
              <div class="case-name" title="${escapeHtml(c.name || c.case_id)}">${escapeHtml(c.name || c.case_id)}</div>
              <span class="integrity-chip ${st.chipClass}">${escapeHtml(st.chipText)}</span>
            </div>
            <div class="integrity-bar ${st.barClass}">
              <div class="integrity-bar-fill" style="width:${st.barPct}%"></div>
            </div>
            <div class="case-card-footer">
              <span class="verified-at">${escapeHtml(st.footer)}</span>
              <button type="button" class="btn sm secondary verify-btn" data-verify="${escapeHtml(c.case_id)}">Verify</button>
            </div>
          </div>`;
      })
      .join('');
  }

  function identityBlockHtml(caseId) {
    const cached = (state.verifyCache || {})[caseId];
    const evidenceId = cached?.evidenceId || `EV_${caseId}`;
    const imageName = cached?.imageName || '';
    const sealedAt = cached?.sealedAt || '';
    const submittedBy = cached?.submittedBy || '';
    return `
      <div class="evidence-identity-block">
        <div class="identity-row">
          <span class="identity-label">Evidence ID</span>
          <code class="identity-value mono">${escapeHtml(evidenceId || '—')}</code>
        </div>
        <div class="identity-row">
          <span class="identity-label">Image File</span>
          <span class="identity-value">${escapeHtml(imageName || '—')}</span>
        </div>
        <div class="identity-row">
          <span class="identity-label">Sealed At</span>
          <span class="identity-value">${sealedAt ? escapeHtml(formatTime(sealedAt)) : '—'}</span>
        </div>
        <div class="identity-row">
          <span class="identity-label">Submitted By</span>
          <span class="identity-value">${escapeHtml(analystLabel(submittedBy, config))}</span>
        </div>
      </div>`;
  }

  function paintHashGrid(caseId) {
    const area = root.querySelector('#bc-hash-grid');
    if (!area) return;
    const cached = (state.verifyCache || {})[caseId];
    const identity = identityBlockHtml(caseId);

    if (!cached) {
      area.innerHTML = `
        ${identity}
        <div class="hash-row"><span class="hash-label">Stored Hash</span><code class="hash-value mono">—</code></div>
        <div class="hash-row"><span class="hash-label">Recomputed</span><code class="hash-value mono">—</code></div>
        <div class="hash-match-badge badge review">Not verified yet</div>`;
      return;
    }

    const match = cached.isValid && !cached.tampered;
    const storedFull = cached.storedHash || '';
    const recomputedFull = cached.recomputedHash || '';
    const acquisitionHash = cached.acquisitionHash || '';

    const acqSection = acquisitionHash
      ? `
      <div class="hash-section-label spaced">Acquisition Hash (from E01)</div>
      <div class="hash-row">
        <span class="hash-label">Sealed</span>
        <div class="hash-value-row">
          <code class="hash-value mono" title="${escapeHtml(acquisitionHash)}">${escapeHtml(truncateHash(acquisitionHash, 28))}</code>
          <button type="button" class="btn ghost sm hash-copy-btn" data-copy="${escapeHtml(acquisitionHash)}" title="Copy">⧉</button>
        </div>
      </div>
      <div class="hash-note">Acquisition hash reflects the E01 container. System hash reflects raw disk stream. A mismatch between these two is expected and does not indicate tampering.</div>`
      : '';

    area.innerHTML = `
      ${identity}
      <div class="hash-section-label">System Hash (integrity)</div>
      <div class="hash-row">
        <span class="hash-label">Stored</span>
        <div class="hash-value-row">
          <code class="hash-value mono" title="${escapeHtml(storedFull)}">${escapeHtml(truncateHash(storedFull, 28))}</code>
          <button type="button" class="btn ghost sm hash-copy-btn" data-copy="${escapeHtml(storedFull)}" title="Copy">⧉</button>
        </div>
      </div>
      <div class="hash-row">
        <span class="hash-label">Recomputed</span>
        <div class="hash-value-row">
          <code class="hash-value mono" title="${escapeHtml(recomputedFull)}">${escapeHtml(truncateHash(recomputedFull, 28))}</code>
          <button type="button" class="btn ghost sm hash-copy-btn" data-copy="${escapeHtml(recomputedFull)}" title="Copy">⧉</button>
        </div>
      </div>
      <div class="hash-match-badge ${match ? 'match-ok' : 'match-bad'}">${match ? '✓ Match' : '✗ Mismatch'}</div>
      ${acqSection}`;
  }

  function renderTimeline() {
    const area = root.querySelector('#bc-timeline');
    if (!area) return;

    const trail = cachedTrail;
    if (!trail.length) {
      area.innerHTML = `<div class="empty">No audit events for this case</div>`;
      return;
    }

    const sealCount = trail.filter((e) => e.action === 'EVIDENCE_SEALED').length;
    const analysisCount = trail.filter((e) => e.action === 'ANALYSIS_COMPLETE').length;
    const queryCount = trail.filter((e) => e.action === 'QUERY').length;
    const verifyCount = trail.filter(
      (e) => e.action === 'VERIFY_PASS' || e.action === 'VERIFY_FAIL'
    ).length;
    const lastEntry = trail[trail.length - 1];
    const lastActivity = lastEntry ? `last activity ${timeAgo(lastEntry.timestamp)}` : '';

    if (verifyCount === 0 && currentFilter === 'verify') {
      currentFilter = 'all';
    }

    const filterFn = FILTERS[currentFilter] || FILTERS.all;
    const filtered = trail.filter(filterFn);

    const filtersHtml = `
      <div class="timeline-filters">
        <button type="button" class="tf-tab ${currentFilter === 'all' ? 'active' : ''}" data-filter="all">All</button>
        <button type="button" class="tf-tab ${currentFilter === 'chain' ? 'active' : ''}" data-filter="chain">Seal &amp; Analysis</button>
        <button type="button" class="tf-tab ${currentFilter === 'queries' ? 'active' : ''}" data-filter="queries">Queries</button>
        ${
          verifyCount > 0
            ? `<button type="button" class="tf-tab ${currentFilter === 'verify' ? 'active' : ''}" data-filter="verify">Verifications</button>`
            : ''
        }
      </div>`;

    const countsHtml = `
      <div class="timeline-counts">
        <span class="tc-chip">${sealCount} seal${sealCount !== 1 ? 's' : ''}</span>
        <span class="tc-chip">${analysisCount} analysis</span>
        <span class="tc-chip">${queryCount} ${queryCount === 1 ? 'query' : 'queries'}</span>
        ${
          verifyCount > 0
            ? `<span class="tc-chip">${verifyCount} verification${verifyCount !== 1 ? 's' : ''}</span>`
            : ''
        }
        ${lastActivity ? `<span class="tc-muted">${escapeHtml(lastActivity)}</span>` : ''}
      </div>`;

    const entriesHtml =
      filtered.length === 0
        ? `<div class="empty">No events for this filter</div>`
        : filtered
            .map((e, i) => {
              const action = e.action || 'UNKNOWN';
              const last = i === filtered.length - 1 ? 'last' : '';
              const details = e.details || '';
              return `
            <div class="timeline-entry ${last}" data-action="${escapeHtml(action)}" data-expanded="false">
              <div class="timeline-rail">
                <div class="timeline-dot ${timelineDotClass(action)}" aria-hidden="true">${timelineIcon(action)}</div>
                <div class="timeline-connector"></div>
              </div>
              <div class="timeline-body">
                <div class="timeline-header">
                  <span class="timeline-action">${escapeHtml(action)}</span>
                  <span class="timeline-analyst">${escapeHtml(analystLabel(e.analystId, config))}</span>
                  <span class="timeline-time">${escapeHtml(formatTime(e.timestamp))}</span>
                  <button type="button" class="tl-expand-btn" title="Expand">›</button>
                </div>
                <div class="timeline-details-short">${escapeHtml(truncateStr(details, 60))}</div>
                <div class="timeline-details-full" hidden>${escapeHtml(details)}</div>
              </div>
            </div>`;
            })
            .join('');

    area.innerHTML = `${filtersHtml}${countsHtml}${entriesHtml}`;
  }

  async function paintTimeline(caseId) {
    const area = root.querySelector('#bc-timeline');
    if (!area) return;
    area.innerHTML = `<div class="empty"><span class="spinner dark"></span> Loading audit trail…</div>`;
    currentFilter = 'all';
    try {
      const audit = await window.api.fetchAPI(
        `/cases/${encodeURIComponent(caseId)}/audit`
      );
      cachedTrail = audit.trail || [];
      renderTimeline();
    } catch (err) {
      cachedTrail = [];
      area.innerHTML = `<div class="empty">${escapeHtml(err.message || err)}</div>`;
      toast(`Audit: ${err.message}`, true);
    }
  }

  async function selectCase(caseId) {
    selectedCaseId = caseId;
    const meta = caseMeta(caseId);
    if (meta) setSelectedCase(caseId, meta.name || caseId);
    paintCards();
    const detail = root.querySelector('#bc-chain-detail');
    if (detail) detail.hidden = false;
    const title = root.querySelector('#bc-detail-title');
    if (title) {
      title.textContent = `Chain Detail — ${meta?.name || caseId}`;
    }
    updateDetailVerifyBtn(caseId);
    paintHashGrid(caseId);
    await paintTimeline(caseId);
  }

  async function verifyOne(caseId, btn) {
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner dark"></span>';
    }
    const meta = caseMeta(caseId);
    const label = meta?.name || caseId;
    try {
      const result = await window.api.fetchAPI(
        `/cases/${encodeURIComponent(caseId)}/verify`,
        { method: 'POST', body: {} }
      );
      setVerifyResult(caseId, result);
      const ok = result.isValid && !result.tampered;
      toast(
        ok
          ? `Case ${label}: Chain Intact ✓`
          : `Case ${label}: Tampered — hash mismatch ✗`,
        !ok
      );
      paintCards();
      if (selectedCaseId === caseId) {
        paintHashGrid(caseId);
        updateDetailVerifyBtn(caseId);
        await paintTimeline(caseId);
      }
    } catch (err) {
      toast(`${label}: ${err.message || err}`, true);
    } finally {
      if (btn) {
        btn.disabled = false;
        if (btn.id === 'bc-detail-verify-btn') {
          updateDetailVerifyBtn(caseId);
        } else {
          btn.textContent = 'Verify';
        }
      }
    }
  }

  root.innerHTML = `
    <div class="page-header">
      <h2>Blockchain Integrity Ledger</h2>
      <div class="page-actions">
        <span class="verify-progress muted" id="bc-progress" hidden></span>
        <button type="button" class="btn primary" id="bc-verify-all">Verify All Cases</button>
      </div>
    </div>

    <div class="integrity-overview-grid" id="bc-overview-grid"></div>

    <div class="panel chain-detail" id="bc-chain-detail" hidden>
      <div class="chain-detail-header">
        <h3 class="detail-title" id="bc-detail-title">Chain Detail</h3>
        <button type="button" class="btn secondary sm" id="bc-detail-verify-btn">Verify</button>
      </div>
      <div class="hash-grid" id="bc-hash-grid"></div>
      <h3 class="timeline-heading">Audit Timeline</h3>
      <div class="timeline-scroll-wrap">
        <div class="audit-timeline" id="bc-timeline"></div>
      </div>
    </div>
  `;

  paintCards();
  await selectCase(selectedCaseId);

  root.querySelector('#bc-overview-grid').addEventListener('click', async (e) => {
    const verifyBtn = e.target.closest('[data-verify]');
    if (verifyBtn) {
      e.stopPropagation();
      await verifyOne(verifyBtn.dataset.verify, verifyBtn);
      return;
    }
    const card = e.target.closest('.integrity-case-card');
    if (card?.dataset.caseId) {
      await selectCase(card.dataset.caseId);
    }
  });

  root.querySelector('#bc-chain-detail').addEventListener('click', (e) => {
    const filterTab = e.target.closest('.tf-tab[data-filter]');
    if (filterTab) {
      e.stopPropagation();
      currentFilter = filterTab.dataset.filter || 'all';
      renderTimeline();
      return;
    }

    const expandBtn = e.target.closest('.tl-expand-btn');
    if (expandBtn) {
      e.stopPropagation();
      const entry = expandBtn.closest('.timeline-entry');
      if (!entry) return;
      const expanded = entry.getAttribute('data-expanded') === 'true';
      const next = !expanded;
      entry.setAttribute('data-expanded', next ? 'true' : 'false');
      expandBtn.textContent = next ? '↓' : '›';
      const shortEl = entry.querySelector('.timeline-details-short');
      const fullEl = entry.querySelector('.timeline-details-full');
      if (shortEl) shortEl.hidden = next;
      if (fullEl) fullEl.hidden = !next;
      return;
    }

    const copyEl = e.target.closest('[data-copy]');
    if (!copyEl || !copyEl.dataset.copy) return;
    e.stopPropagation();
    const text = copyEl.dataset.copy;
    const flashTarget = copyEl;
    navigator.clipboard
      ?.writeText(text)
      .then(() => {
        flashTarget.classList.add('copied');
        if (copyFlashTimer) clearTimeout(copyFlashTimer);
        copyFlashTimer = setTimeout(() => {
          flashTarget.classList.remove('copied');
          copyFlashTimer = null;
        }, 800);
        toast('Hash copied');
      })
      .catch(() => toast('Copy failed', true));
  });

  root.querySelector('#bc-detail-verify-btn').onclick = async (e) => {
    e.stopPropagation();
    const btn = e.currentTarget;
    if (!selectedCaseId) return;
    await verifyOne(selectedCaseId, btn);
  };

  root.querySelector('#bc-verify-all').onclick = async () => {
    const btn = root.querySelector('#bc-verify-all');
    const progress = root.querySelector('#bc-progress');
    btn.disabled = true;
    progress.hidden = false;
    const list = overview.slice();
    for (let i = 0; i < list.length; i++) {
      progress.textContent = `Verifying ${i + 1} of ${list.length}…`;
      const cardBtn = root.querySelector(
        `.verify-btn[data-verify="${CSS.escape(list[i].case_id)}"]`
      );
      await verifyOne(list[i].case_id, cardBtn);
    }
    progress.hidden = true;
    progress.textContent = '';
    btn.disabled = false;
  };

  return {
    cleanup() {
      if (copyFlashTimer) clearTimeout(copyFlashTimer);
    },
  };
}
