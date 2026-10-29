// Descarga los escáneres en una carpeta propia de Lupa (~/.cache/lupa/bin), sin tocar el sistema ni
// pedir permisos de administrador. Las versiones y su SHA-256 van fijadas en herramientas.json: si lo
// descargado no coincide byte a byte, se borra y no se usa. Así todos los equipos escanean con lo mismo
// y los informes se pueden comparar.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run, readJSON, tmpDir } from './util.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const MANIFEST = readJSON(path.join(HERE, '..', '..', 'herramientas.json'), {});
const CONSTRAINTS = path.join(HERE, '..', '..', 'semgrep-constraints.txt');

/** ¿Es esta la copia fijada que descarga Lupa? (y no una del sistema, de otra versión) */
export const isPinned = (tool) => !!tool && !!pinnedPath(tool.name) && path.dirname(tool.path) === path.dirname(pinnedPath(tool.name));
const WIN = process.platform === 'win32';
const exe = (n) => (WIN ? n + '.exe' : n);

export const platformKey = (platform = process.platform, arch = process.arch) => `${platform}-${arch}`;

/** Carpeta de los escáneres de Lupa. LUPA_HOME la cambia (útil en CI). */
export function toolsHome() {
  return process.env.LUPA_HOME ? path.resolve(process.env.LUPA_HOME) : path.join(os.homedir(), '.cache', 'lupa', 'bin');
}

/** Dónde queda el ejecutable de la versión fijada de cada escáner, esté o no descargado. */
export function pinnedPath(name, home = toolsHome()) {
  const v = MANIFEST[name]?.version;
  if (!v) return null;
  if (name === 'semgrep') return path.join(home, `semgrep-${v}`, WIN ? 'Scripts' : 'bin', exe('semgrep'));
  return path.join(home, `${name}-${v}`, exe(name));
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/**
 * Descarga un fichero y lo guarda solo si su SHA-256 es el esperado. Devuelve la ruta.
 * @param fetchImpl inyectable para las pruebas.
 */
export async function download(url, expected, dest, { fetchImpl = fetch } = {}) {
  const r = await fetchImpl(url, { redirect: 'follow', signal: AbortSignal.timeout(15 * 60_000), headers: { 'user-agent': 'lupa-security-audit' } });
  if (!r.ok) throw new Error(`HTTP ${r.status} al descargar ${url}`);
  const buf = Buffer.from(await r.arrayBuffer());
  const got = sha256(buf);
  if (got !== expected) throw new Error(`el SHA-256 de ${path.basename(dest)} no coincide (esperado ${expected.slice(0, 12)}…, llegó ${got.slice(0, 12)}…): no se usa`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, buf);
  return dest;
}

/** Descomprime con el tar del sistema; en Windows, el de System32, que también abre .zip. */
function extract(archive, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const tar = WIN ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  const r = run(tar, ['-xf', archive, '-C', dir], { timeout: 5 * 60_000 });
  if (r.status !== 0) throw new Error(`no pude descomprimir ${path.basename(archive)}: ${(r.stderr || r.error?.message || '').slice(0, 200)}`);
}

/** Un Python 3.10 o más reciente, que Semgrep necesita: { cmd, args, version }. */
export function findPython(min = MANIFEST.semgrep?.python || '3.10') {
  const [maj, mnr] = min.split('.').map(Number);
  const tries = WIN ? [['py', ['-3']], ['python', []]] : [['python3', []], ['python', []]];
  for (const [cmd, args] of tries) {
    const r = run(cmd, [...args, '-c', 'import sys;print("%d.%d" % sys.version_info[:2])'], { timeout: 30_000 });
    const m = /^(\d+)\.(\d+)/.exec(r.stdout.trim());
    if (r.status === 0 && m && (+m[1] > maj || (+m[1] === maj && +m[2] >= mnr))) return { cmd, args, version: m[0] };
  }
  return null;
}

async function installBinary(name, spec, home) {
  const final = path.dirname(pinnedPath(name, home));
  const work = fs.mkdtempSync(path.join(tmpDir(), `lupa-${name}-`));
  try {
    const archive = await download(spec.url, spec.sha256, path.join(work, path.basename(new URL(spec.url).pathname)));
    extract(archive, path.join(work, 'x'));
    fs.rmSync(final, { recursive: true, force: true });
    fs.mkdirSync(final, { recursive: true });
    fs.copyFileSync(path.join(work, 'x', exe(name)), path.join(final, exe(name)));
    if (!WIN) fs.chmodSync(path.join(final, exe(name)), 0o755);
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
}

/** Semgrep es Python: un entorno virtual propio con la rueda fijada (comprobada por hash) dentro. */
async function installSemgrep(spec, home) {
  const py = findPython();
  if (!py) throw new Error(`Semgrep necesita Python ${MANIFEST.semgrep.python} o más reciente y no lo encuentro`);
  const venv = path.dirname(path.dirname(pinnedPath('semgrep', home)));
  const work = fs.mkdtempSync(path.join(tmpDir(), 'lupa-semgrep-'));
  try {
    // pip necesita el nombre original de la rueda
    const wheel = await download(spec.url, spec.sha256, path.join(work, path.basename(new URL(spec.url).pathname)));
    fs.rmSync(venv, { recursive: true, force: true });
    let r = run(py.cmd, [...py.args, '-m', 'venv', venv], { timeout: 5 * 60_000 });
    if (r.status !== 0) throw new Error(`no pude crear el entorno de Python: ${(r.stderr || '').slice(-200)}`);
    const vpy = path.join(venv, WIN ? 'Scripts' : 'bin', exe('python'));
    // las dependencias, en versiones exactas: una versión nueva (quizá comprometida) de alguna no entra sola
    r = run(vpy, ['-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--quiet', '-c', CONSTRAINTS, wheel], { timeout: 20 * 60_000 });
    if (r.status !== 0) throw new Error(`pip no pudo instalar Semgrep: ${(r.stderr || '').slice(-300)}`);
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
}

/**
 * Instala la versión fijada de cada escáner pedido. Devuelve { nombre: 'ok' | mensaje de error }.
 * Nunca deja a medias una versión que no pasó la comprobación del hash.
 */
export async function installTools(names, { home = toolsHome(), log = () => {} } = {}) {
  const out = {};
  for (const name of names) {
    const spec = MANIFEST[name]?.descargas?.[platformKey()];
    if (!spec) { out[name] = `no hay descarga fijada para ${platformKey()}`; continue; }
    log(`descargando ${name} ${MANIFEST[name].version}…`);
    try {
      await (name === 'semgrep' ? installSemgrep(spec, home) : installBinary(name, spec, home));
      out[name] = 'ok';
    } catch (e) { out[name] = e.message; }
  }
  return out;
}
