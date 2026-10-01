'use strict';
/** Smoke-test the same HTTP endpoints the Electron UI uses. */
const BASE = process.env.API_BASE || 'http://127.0.0.1:3000';
let passed = 0;
let failed = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log('PASS ', name);
    passed++;
  } catch (err) {
    console.log('FAIL ', name, '-', err.message);
    failed++;
  }
}

async function main() {
  let caseId = 'TEST_NIST';
  await check('GET /health', async () => {
    const r = await fetch(`${BASE}/health`);
    if (!r.ok) throw new Error(String(r.status));
  });
  await check('GET /api/cases', async () => {
    const r = await fetch(`${BASE}/api/cases`);
    const d = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(d));
    const cases = d.cases || [];
    if (!cases.length) throw new Error('no cases');
    caseId = cases.find((c) => c.case_id === 'TEST_NIST')?.case_id || cases[0].case_id;
  });
  await check('GET status', async () => {
    const r = await fetch(`${BASE}/api/cases/${caseId}/status`);
    if (!r.ok) throw new Error(String(r.status));
  });
  await check('GET artifacts', async () => {
    const r = await fetch(`${BASE}/api/cases/${caseId}/artifacts`);
    if (!r.ok) throw new Error(String(r.status));
  });
  await check('GET audit (may warn if Fabric down)', async () => {
    const r = await fetch(`${BASE}/api/cases/${caseId}/audit`);
    // 200 with trail or 500 if Fabric down — both mean route exists
    if (r.status !== 200 && r.status !== 500) throw new Error(String(r.status));
  });
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}
main();
