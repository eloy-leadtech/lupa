// Encuentra los escáneres que usa Lupa (gitleaks, Semgrep, Trivy) en cualquier sistema.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run } from './util.mjs';
import { pinnedPath } from './install.mjs';

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

const VERSION_ARGS = { gitleaks: ['version'], semgrep: ['--version'], trivy: ['--version'], zizmor: ['--version'], claude: ['--version'], git: ['--version'] };

/**
 * En Windows, los .exe que pip genera al instalar (semgrep.exe, pysemgrep.exe) son únicos de cada
 * equipo, y la regla ASR de Defender «bloquear ejecutables poco comunes» los para (evento 1121).
 * El python.exe del entorno virtual y semgrep-core.exe sí pasan: son los mismos bytes en todo el
 * mundo. Así que, si hay un python.exe al lado, se llama a Semgrep a través de él.
 */
// -I: Python no mira la carpeta actual (la raíz del proyecto que se audita: un «logging.py» suyo se cargaría
// en vez del de verdad) ni las variables PYTHON*; por eso -X utf8 en lugar de PYTHONUTF8.
const VIA_PYTHON = { semgrep: ['-I', '-X', 'utf8', '-c', 'import sys; from semgrep.console_scripts.pysemgrep import main; sys.exit(main())'] };
function launcher(name, p) {
  const py = path.join(path.dirname(p), 'python.exe');
  return WIN && VIA_PYTHON[name] && path.isAbsolute(p) && fs.existsSync(py) ? { path: py, args: VIA_PYTHON[name] } : { path: p, args: [] };
}

/** Ejecuta una herramienta encontrada por findTool, con sus argumentos fijos delante. */
export const runTool = (tool, args, opts) => run(tool.path, [...(tool.args || []), ...args], opts);

export function findTool(name) {
  const override = process.env['LUPA_' + name.toUpperCase()];
  // la versión fijada que descarga «doctor.mjs --instalar» va primero: así todos los equipos escanean igual
  const tries = [override, pinnedPath(name), onPath(name), ...candidates(name)].filter(Boolean);
  for (const p of tries) {
    if (!fs.existsSync(p) && p !== name) continue;
    const tool = { name, ...launcher(name, p) };
    const r = runTool(tool, VERSION_ARGS[name] || ['--version'], { timeout: 60_000 });
    if (r.status === 0) return { ...tool, version: (r.stdout || r.stderr).split(/\r?\n/).find(Boolean)?.replace(/^Version:\s*/, '').trim() || '?' };
  }
  return null;
}

export const INSTALL = {
  gitleaks: { win: 'winget install --id Gitleaks.Gitleaks -e', mac: 'brew install gitleaks', linux: 'https://github.com/gitleaks/gitleaks/releases (binario oficial)' },
  semgrep: { win: 'py -m venv C:\\dev\\tools\\semgrep-venv && C:\\dev\\tools\\semgrep-venv\\Scripts\\pip install semgrep', mac: 'brew install semgrep', linux: 'pipx install semgrep' },
  trivy: { win: 'winget install --id AquaSecurity.Trivy -e', mac: 'brew install trivy', linux: 'https://aquasecurity.github.io/trivy (paquete oficial)' },
  zizmor: { win: 'https://github.com/zizmorcore/zizmor/releases (binario oficial)', mac: 'brew install zizmor', linux: 'pipx install zizmor' },
};

export function installHint(name) {
  const h = INSTALL[name]; if (!h) return '';
  return `node doctor.mjs --instalar (o a mano: ${WIN ? h.win : process.platform === 'darwin' ? h.mac : h.linux})`;
}

export function findAll() {
  return Object.fromEntries(['git', 'gitleaks', 'semgrep', 'trivy', 'zizmor'].map((n) => [n, findTool(n)]));
}
