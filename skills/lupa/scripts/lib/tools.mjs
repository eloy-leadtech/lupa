// Encuentra los escáneres que usa Lupa (gitleaks, Semgrep, Trivy) en cualquier sistema.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run } from './util.mjs';

const WIN = process.platform === 'win32';
const exe = (n) => (WIN ? n + '.exe' : n);

/** Sitios típicos donde acaban instalados, además del PATH. */
function candidates(name) {
  const home = os.homedir();
  const list = [];
  if (WIN) {
    const pk = path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'Microsoft', 'WinGet', 'Packages');
    try { for (const d of fs.readdirSync(pk)) if (d.toLowerCase().includes(name)) list.push(path.join(pk, d, exe(name))); } catch {}
    list.push(path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', exe(name)));
    list.push(path.join('C:\\dev\\tools', 'semgrep-venv', 'Scripts', exe(name)));
    list.push(path.join(home, 'scoop', 'shims', exe(name)));
  } else {
    list.push('/opt/homebrew/bin/' + name, '/usr/local/bin/' + name, '/usr/bin/' + name, path.join(home, '.local', 'bin', name));
  }
  return list;
}

function onPath(name) {
  const r = run(WIN ? 'where' : 'which', [name], { timeout: 10_000 });
  return r.status === 0 ? r.stdout.split(/\r?\n/).map((s) => s.trim()).find(Boolean) : null;
}

const VERSION_ARGS = { gitleaks: ['version'], semgrep: ['--version'], trivy: ['--version'], claude: ['--version'], git: ['--version'] };

export function findTool(name) {
  const override = process.env['LUPA_' + name.toUpperCase()];
  const tries = [override, onPath(name), ...candidates(name)].filter(Boolean);
  for (const p of tries) {
    if (!fs.existsSync(p) && p !== name) continue;
    const r = run(p, VERSION_ARGS[name] || ['--version'], { timeout: 60_000 });
    if (r.status === 0) return { name, path: p, version: (r.stdout || r.stderr).split(/\r?\n/).find(Boolean)?.replace(/^Version:\s*/, '').trim() || '?' };
  }
  return null;
}

export const INSTALL = {
  gitleaks: { win: 'winget install --id Gitleaks.Gitleaks -e', mac: 'brew install gitleaks', linux: 'https://github.com/gitleaks/gitleaks/releases (binario oficial)' },
  semgrep: { win: 'py -m venv C:\\dev\\tools\\semgrep-venv && C:\\dev\\tools\\semgrep-venv\\Scripts\\pip install semgrep', mac: 'brew install semgrep', linux: 'pipx install semgrep' },
  trivy: { win: 'winget install --id AquaSecurity.Trivy -e', mac: 'brew install trivy', linux: 'https://aquasecurity.github.io/trivy (paquete oficial)' },
};

export function installHint(name) {
  const h = INSTALL[name]; if (!h) return '';
  return WIN ? h.win : process.platform === 'darwin' ? h.mac : h.linux;
}

export function findAll() {
  return Object.fromEntries(['git', 'gitleaks', 'semgrep', 'trivy'].map((n) => [n, findTool(n)]));
}
