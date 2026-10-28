#!/usr/bin/env node
// Lupa · escaneo. Lanza todos los escáneres sobre un proyecto ya mapeado con floorplan,
// junta lo que encuentran, hace el inventario de endpoints y prepara la revisión de la IA.
//
//   node scan.mjs <raíz> [--solo gitleaks,semgrep,trivy,propios] [--sin-paquetes]
//
// Escribe en <raíz>/floorplan/lupa/: hallazgos.json, superficie.json y revision/lote-*.{md,json}
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJSON, writeJSON, run, globToRegExp } from './lib/util.mjs';
import { findAll, installHint } from './lib/tools.mjs';
import { runGitleaks, runSemgrep, runTrivy } from './lib/scanners.mjs';
import { trackedFiles, sensitiveFiles, personalData, unlockedDependencies, extraEndpoints, SENSITIVE_PATH } from './lib/own-checks.mjs';
import { findingId } from './lib/issues.mjs';
import { writeWorksheets } from './lib/review.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FLOORPLAN = path.join(HERE, '..', '..', 'floorplan', 'scripts');
const RULES = path.join(HERE, '..', 'rules', 'lupa.yml');

const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const root = path.resolve(argv.find((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--solo')) || '.');
const only = (opt('--solo') || 'gitleaks,semgrep,trivy,propios').split(',');
const outDir = path.join(root, 'floorplan', 'lupa');
const logLines = [];
const log = (m) => { logLines.push(m); console.error('  · ' + m); };
const t0 = Date.now();

const graph = readJSON(path.join(root, 'floorplan', 'graph.json'));
if (!graph) {
  console.error(`No hay mapa en ${root}. Primero hay que hacer el mapa con floorplan (scan + architecture.json + build).`);
  process.exit(2);
}
if (!fs.existsSync(path.join(root, 'floorplan', '.cache', 'scan.json'))) run(process.execPath, [path.join(FLOORPLAN, 'scan.mjs'), root]);
const scan = readJSON(path.join(root, 'floorplan', '.cache', 'scan.json'), { repos: [] });
const repos = (scan.repos || []).map((r) => ({ path: r.path }));

console.log(`LUPA  escaneando ${graph.project?.name || path.basename(root)} (${repos.length} repo${repos.length === 1 ? '' : 's'})`);
const tools = findAll();
const versions = {};
for (const [n, t] of Object.entries(tools)) {
  if (t) versions[n] = t.version;
  else if (n !== 'git') log(`falta ${n}: sin él no se mira esa parte. Instálalo con: ${installHint(n)}`);
}

let findings = [];
const step = (name, fn) => {
  if (!only.includes(name)) return;
  const s = Date.now();
  try { const r = fn(); findings.push(...r); console.log(`  ${name.padEnd(9)} ${String(r.length).padStart(5)} hallazgos  (${Math.round((Date.now() - s) / 1000)} s)`); }
  catch (e) { log(`${name} falló: ${e.message}`); }
};

const files = trackedFiles(root, repos.length ? repos : [{ path: '.' }]);
step('gitleaks', () => (tools.gitleaks ? runGitleaks(tools.gitleaks, root, repos, log) : []));
step('semgrep', () => (tools.semgrep ? runSemgrep(tools.semgrep, root, { rulesFile: RULES, packs: argv.includes('--sin-paquetes') ? [] : undefined, log }) : []));
step('trivy', () => (tools.trivy ? runTrivy(tools.trivy, root, log) : []));
step('propios', () => [...sensitiveFiles(files), ...personalData(root, files), ...unlockedDependencies(files)]);

// lo que el mapa ignora a propósito (código generado, soluciones de ejemplo, librerías copiadas) tampoco cuenta aquí
const arch = readJSON(path.join(root, 'floorplan', 'architecture.json'), {});
const ignored = (arch.ignore || []).map(globToRegExp);
if (ignored.length) {
  const before = findings.length;
  findings = findings.filter((f) => !ignored.some((re) => re.test(f.file)));
  if (before > findings.length) console.log(`  (${before - findings.length} hallazgos en carpetas que el mapa ignora, fuera)`);
}

// con --solo se conserva lo que encontraron en la pasada anterior las herramientas que no se lanzan ahora
const TOOL_OF = { gitleaks: 'gitleaks', semgrep: 'semgrep', trivy: 'trivy', propios: 'lupa' };
const prevRun = readJSON(path.join(outDir, 'hallazgos.json'));
if (prevRun && only.length < Object.keys(TOOL_OF).length) {
  const ran = new Set(only.map((s) => TOOL_OF[s]));
  const kept = prevRun.hallazgos.filter((f) => !ran.has(f.tool));
  findings.push(...kept);
  Object.assign(versions, Object.fromEntries(Object.entries(prevRun.herramientas || {}).filter(([n]) => !versions[n])));
  if (kept.length) console.log(`  (se conservan ${kept.length} hallazgos de la pasada anterior)`);
}

// el mismo aviso visto dos veces (dos reglas, o la misma con varias coincidencias) cuenta una vez
const seen = new Set();
findings = findings.filter((f) => { const k = `${f.cat}|${f.rule}|${f.file}|${f.line}|${f.pkg || ''}`; if (seen.has(k)) return false; seen.add(k); return true; });
for (const f of findings) f.id = findingId(f);

// ---------------------------------------------------------------- superficie de ataque
const fpOpen = new Set();
// solo los avisos de floorplan: si el mapa ya pasó por merge.mjs, también trae los de Lupa
const fpHealth = (graph.health?.issues || []).filter((i) => !String(i.id).startsWith('lupa:'));
for (const i of fpHealth) if (i.kind === 'unprotected-endpoint') for (const id of i.items || []) fpOpen.add(id);
const routeFiles = new Set((graph.routes || []).map((r) => r.f));
// el mismo manejador montado con varios prefijos («/ftp/x», «/api/x»…) es un solo endpoint que revisar
const byHandler = new Map();
(graph.routes || []).forEach((r, i) => {
  const k = `${r.f}|${r.l}|${r.m}`;
  if (!byHandler.has(k)) byHandler.set(k, { refs: [], paths: [], method: r.m, file: r.f, line: r.l });
  const e = byHandler.get(k); e.refs.push('r:' + i); e.paths.push(r.p);
});
const WRITE = new Set(['POST', 'PUT', 'PATCH', 'DELETE', 'ANY']);
/**
 * floorplan a veces confunde un app.use('/ftp', serveIndex(…)) con un prefijo de router y monta cada
 * ruta debajo de cada carpeta servida («/ftp/rest/login», «/api-docs/rest/login»…). Si todas las
 * variantes acaban igual, la ruta real es ese final común. La clave de revisión sigue usando `path`,
 * para no perder lo ya revisado.
 */
function commonRoute(paths) {
  if (paths.length < 2) return paths[0];
  const parts = paths.map((p) => p.split('/').filter(Boolean));
  const tail = [];
  for (let i = 1; ; i++) {
    const seg = parts[0][parts[0].length - i];
    if (seg === undefined || !parts.every((p) => p[p.length - i] === seg)) break;
    tail.unshift(seg);
  }
  return tail.length ? '/' + tail.join('/') : paths[0];
}
const endpoints = [
  ...[...byHandler.values()].map((e) => {
    const paths = [...new Set(e.paths)].sort((a, b) => a.length - b.length);
    return { ref: e.refs[0], refs: e.refs, method: e.method, path: paths[0], realPath: commonRoute(paths), otherPaths: paths.slice(1), file: e.file, line: e.line, framework: '', floorplanOpen: e.refs.some((r) => fpOpen.has(r)) ? true : null };
  }),
  ...extraEndpoints(root, files, routeFiles).map((e) => ({ ref: 'f:' + e.file, method: e.method, path: e.path, file: e.file, line: e.line, framework: e.framework, authHint: e.authHint })),
].map((e) => ({ ...e, sensitive: SENSITIVE_PATH.test([e.path, ...(e.otherPaths || [])].join(' ')) }))
  // lo más arriesgado primero: así, si la revisión se corta, lo gordo ya está mirado
  .sort((a, b) => (+!!b.floorplanOpen - +!!a.floorplanOpen) || (+b.sensitive - +a.sensitive) || (+WRITE.has(b.method) - +WRITE.has(a.method)));

// también se criban los avisos de floorplan, que a veces se pasan de listos
const fpFindings = fpHealth.filter((i) => i.severity !== 'low').map((i) => ({
  id: 'fp:' + i.id, tool: 'floorplan', cat: i.kind === 'unprotected-endpoint' ? 'endpoints' : i.kind === 'secret' ? 'secretos' : 'exposicion',
  rule: i.kind, severity: i.severity, file: i.locations?.[0]?.file || '', line: i.locations?.[0]?.line || 1, title: i.title, detail: i.detail,
}));

writeJSON(path.join(outDir, 'hallazgos.json'), { generadoEn: new Date().toISOString(), raiz: root, herramientas: versions, avisos: logLines, hallazgos: findings });
writeJSON(path.join(outDir, 'superficie.json'), { generadoEn: new Date().toISOString(), endpoints });
const ws = writeWorksheets({ root, dir: path.join(outDir, 'revision'), endpoints, findings: [...findings, ...fpFindings] });

const bySev = (s) => findings.filter((f) => f.severity === s).length;
console.log(`HALLAZGOS  ${findings.length} (${bySev('high')} graves · ${bySev('medium')} a mirar · ${bySev('low')} menores)`);
console.log(`ENDPOINTS  ${endpoints.length} en total · ${endpoints.filter((e) => e.sensitive).length} con nombre delicado · ${endpoints.filter((e) => e.floorplanOpen).length} sin login según floorplan`);
console.log(`REVISIÓN   ${ws.lotes} lote(s) para la IA: ${ws.pendientesEndpoints} endpoints y ${ws.pendientesHallazgos} hallazgos pendientes${ws.yaRevisados ? ` · ${ws.yaRevisados} ya revisados de antes` : ''}`);
if (ws.lotes) console.log(`           floorplan/lupa/revision/lote-01.md … lote-${String(ws.lotes).padStart(2, '0')}.md`);
console.log(`✓ ${Math.round((Date.now() - t0) / 1000)} s. Siguiente: revisar los lotes y después node merge.mjs ${root}`);
