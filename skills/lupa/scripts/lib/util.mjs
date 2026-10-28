// Utilidades comunes de Lupa: rutas, ejecutar programas, leer JSON y tapar secretos.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const posix = (p) => p.split(path.sep).join('/').replace(/\\/g, '/');

/** Ruta relativa a la raíz del proyecto, siempre con barras normales y sin "./" delante. */
export function relTo(root, p) {
  const abs = path.isAbsolute(p) ? p : path.join(root, p);
  const r = posix(path.relative(root, abs));
  return r.replace(/^\.\//, '');
}

export function readJSON(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, '')); } catch { return fallback; }
}

export function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

/**
 * Carpeta temporal sin tildes ni eñes. En Windows, Semgrep revienta («Invalid argument
 * socketpair») si la carpeta temporal del usuario lleva caracteres no ASCII, como en
 * C:\Users\EloyBandínAraújo. Ahí se usa C:\Users\Public\lupa-tmp, que existe en todo Windows.
 */
export function tmpDir() {
  let dir = os.tmpdir();
  // Windows suele dar el nombre corto (C:\Users\ELOYBA~1\…), que es ASCII pero esconde la tilde
  let real = dir; try { real = fs.realpathSync.native(dir); } catch {}
  if (process.platform === 'win32' && /[^\x00-\x7F]/.test(real + os.homedir())) dir = path.join(process.env.PUBLIC || 'C:\\Users\\Public', 'lupa-tmp');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Ejecuta un programa sin shell y devuelve { status, stdout, stderr, error }. */
export function run(cmd, args, { cwd, env, timeout = 30 * 60_000 } = {}) {
  const tmp = tmpDir();
  const r = spawnSync(cmd, args, {
    cwd, encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 1024 * 1024 * 1024,
    env: { ...process.env, PYTHONUTF8: '1', TMP: tmp, TEMP: tmp, TMPDIR: tmp, ...env },
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', error: r.error };
}

/** Tapa un secreto: deja ver solo el principio y la longitud, nunca el valor entero. */
export function mask(value) {
  const v = String(value ?? '');
  if (!v) return '';
  return `${v.slice(0, Math.min(4, Math.floor(v.length / 4)))}… (${v.length} caracteres)`;
}

/** Quita de un texto cualquier secreto conocido antes de mostrarlo o guardarlo. */
export function scrub(text, secrets = []) {
  let out = String(text ?? '');
  for (const s of secrets) if (s && s.length >= 6) out = out.split(s).join('«secreto tapado»');
  return out;
}

/** Un glob de floorplan («**», «*», «?», «{a,b}») como expresión regular. Sin comodines vale también como carpeta. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') { re += '(?:.*/)?'; i++; if (glob[i + 1] === '/') i++; }
    else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '{') { const end = glob.indexOf('}', i); re += '(?:' + glob.slice(i + 1, end).split(',').map((s) => s.replace(/[.+^$()|[\]\\]/g, '\\$&')).join('|') + ')'; i = end; }
    else re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re.replace(/\(\?:\.\*\/\)\?$/, '.*') + '(?:/.*)?$');
}

export const SEVERITIES = ['high', 'medium', 'low'];
export const SEV_RANK = { high: 0, medium: 1, low: 2 };
export const worst = (list) => list.reduce((a, b) => (SEV_RANK[b] < SEV_RANK[a] ? b : a), 'low');

/** Traduce la severidad de cada herramienta a las tres de floorplan. */
export function normSeverity(s) {
  const v = String(s || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'ERROR', 'ALTA'].includes(v)) return 'high';
  if (['MEDIUM', 'MODERATE', 'WARNING', 'MEDIA'].includes(v)) return 'medium';
  return 'low';
}

export const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;

export function readLines(file) {
  try { return fs.readFileSync(file, 'utf8').split(/\r?\n/); } catch { return []; }
}

/** Unas líneas alrededor de una línea dada, numeradas, para que la IA vea el contexto. */
export function snippet(file, line, before = 3, after = 20, hide = new Set()) {
  try {
    const head = Buffer.alloc(8000);
    const fd = fs.openSync(file, 'r'); const n = fs.readSync(fd, head, 0, 8000, 0); fs.closeSync(fd);
    if (head.subarray(0, n).includes(0)) return '(fichero binario: sin fragmento)';
  } catch { return ''; }
  const lines = readLines(file);
  if (!lines.length) return '';
  const from = Math.max(1, line - before), to = Math.min(lines.length, line + after);
  const out = [];
  // las líneas donde hay un secreto se tapan: el fragmento acaba en un fichero y en la IA
  for (let i = from; i <= to; i++) out.push(`${String(i).padStart(5)}  ${hide.has(i) ? '«línea con un secreto: tapada»' : lines[i - 1].slice(0, 240)}`);
  return out.join('\n');
}
