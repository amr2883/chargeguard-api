// Static guard: reads source files only (no app import, no DB, no network).
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src');
const ROUTE_RE = /^\s*router\.(get|post|put|patch|delete|all)\(\s*['"]([^'"]+)['"]/;
const ANY_ROUTE_RE = /^\s*router\.(get|post|put|patch|delete|use|all)\(/;
const rel = (f) => path.relative(SRC, f).split(path.sep).join('/');

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === '__tests__' ? [] : walk(p);
    return e.name.endsWith('.js') ? [p] : [];
  });
}

// RISK_JS_PATH points the test at another copy of routes/risk.js
// (used once, to prove the test fails on the old version).
function load(file) {
  const useOverride = process.env.RISK_JS_PATH && rel(file) === 'routes/risk.js';
  return fs.readFileSync(useOverride ? process.env.RISK_JS_PATH : file, 'utf8').split('\n');
}

function blockOf(lines, method, routePath) {
  const start = lines.findIndex((l) => {
    const m = ROUTE_RE.exec(l);
    return m && m[1] === method && m[2] === routePath;
  });
  if (start < 0) return null;
  const next = lines.findIndex((l, i) => i > start && ANY_ROUTE_RE.test(l));
  return lines.slice(start, next < 0 ? lines.length : next).join('\n');
}

test('no METHOD+PATH is registered twice inside the same route file', () => {
  const dups = [];
  for (const f of walk(SRC)) {
    const seen = new Map();
    load(f).forEach((line, i) => {
      const m = ROUTE_RE.exec(line);
      if (!m) return;
      const key = `${m[1].toUpperCase()} ${m[2]}`;
      if (seen.has(key)) dups.push(`${rel(f)}: ${key} at lines ${seen.get(key)} and ${i + 1}`);
      else seen.set(key, i + 1);
    });
  }
  expect(dups).toEqual([]);
});

test('GET /blacklist reads blacklistEntry only, GET /whitelist reads whitelistEntry only', () => {
  const lines = load(path.join(SRC, 'routes', 'risk.js'));
  const bl = blockOf(lines, 'get', '/blacklist');
  const wl = blockOf(lines, 'get', '/whitelist');
  expect(bl).not.toBeNull();
  expect(wl).not.toBeNull();
  expect(bl).toMatch(/blacklistEntry\.findMany/);
  expect(bl).not.toMatch(/whitelistEntry/);
  expect(wl).toMatch(/whitelistEntry\.findMany/);
  expect(wl).not.toMatch(/blacklistEntry/);
});
