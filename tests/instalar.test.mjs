// Pruebas de la descarga de escáneres: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MANIFEST, download, pinnedPath, platformKey } from '../skills/lupa/scripts/lib/install.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-test-'));
const fakeFetch = (body) => async () => ({ ok: true, status: 200, arrayBuffer: async () => Buffer.from(body) });

test('cada escáner tiene versión fijada y descarga con hash para las cinco plataformas', () => {
  for (const name of ['gitleaks', 'trivy', 'semgrep']) {
    const t = MANIFEST[name];
    assert.match(t.version, /^\d+\.\d+\.\d+$/, name);
    for (const p of ['win32-x64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64']) {
      const d = t.descargas[p];
      assert.ok(d, `${name} sin descarga para ${p}`);
      assert.match(d.sha256, /^[0-9a-f]{64}$/, `${name} ${p}: hash`);
      assert.match(d.url, /^https:\/\/(github\.com\/(gitleaks|aquasecurity)\/|files\.pythonhosted\.org\/)/, `${name} ${p}: origen`);
      assert.ok(d.url.includes(t.version), `${name} ${p}: la URL no es de la versión fijada`);
    }
  }
});

test('una descarga cuyo hash no coincide se rechaza y no deja fichero', async () => {
  const d = tmp();
  const dest = path.join(d, 'gitleaks.zip');
  await assert.rejects(download('https://x/y.zip', '0'.repeat(64), dest, { fetchImpl: fakeFetch('malicioso') }), /no coincide/);
  assert.equal(fs.existsSync(dest), false);
});

test('una descarga con el hash correcto se guarda', async () => {
  const d = tmp();
  const body = 'binario de verdad';
  const sha = crypto.createHash('sha256').update(body).digest('hex');
  const dest = await download('https://x/y.zip', sha, path.join(d, 'sub', 'y.zip'), { fetchImpl: fakeFetch(body) });
  assert.equal(fs.readFileSync(dest, 'utf8'), body);
});

test('la copia fijada vive en la carpeta de Lupa, una por versión', () => {
  const home = path.join('h', 'bin');
  assert.ok(pinnedPath('trivy', home).startsWith(path.join(home, `trivy-${MANIFEST.trivy.version}`)));
  assert.ok(pinnedPath('semgrep', home).includes(`semgrep-${MANIFEST.semgrep.version}`));
  assert.equal(pinnedPath('nmap', home), null);
  assert.equal(platformKey('win32', 'x64'), 'win32-x64');
});
