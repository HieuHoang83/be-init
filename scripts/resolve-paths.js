/**
 * Cho phep chay ban bien dich cua `scripts/` bang Node that.
 *
 * Mot so file trong `src/` import theo kieu `src/user/user.service` (nhờ `baseUrl` trong
 * tsconfig) thay vi duong dan tuong doi. `nest build` tu viet lai thanh duong dan tuong doi khi
 * bien dich, nhung khi bien dich bang `tsc` thi nhanh giữ nguyen, va Node khong tim thay vi
 * coi no la ten package.
 *
 * File nay uu tien tra loi cac ten dang do ve `dist-scripts/` truoc khi Node tu tim trong
 * `node_modules`, nen khong can bien bien `NODE_PATH` theo tung he dieu hanh.
 *
 * Dung: node --require ./scripts/resolve-paths.js dist-scripts/scripts/seed-customers.js
 */
const fs = require('fs');
const path = require('path');
const Module = require('module');

const root = path.resolve(__dirname, '..', 'dist-scripts');
const originalResolve = Module._resolveFilename;

/** Tra ve duong dan tuyet doi neu request co that trong `dist-scripts`, nguoc lai `null`. */
function resolveInRoot(request) {
  if (!request || request.startsWith('.') || request.startsWith('/')) return null;
  if (path.isAbsolute(request)) return null;

  const base = path.join(root, request);
  const candidates = [base, `${base}.js`, `${base}.json`, path.join(base, 'index.js')];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }
  return null;
}

Module._resolveFilename = function resolveFilename(request, ...rest) {
  const mapped = resolveInRoot(request);
  return originalResolve.call(this, mapped ?? request, ...rest);
};
