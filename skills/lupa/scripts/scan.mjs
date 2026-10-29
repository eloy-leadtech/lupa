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
import { readJSON, writeJSON, run, globToRegExp, snippet } from './lib/util.mjs';
import { findAll, installHint } from './lib/tools.mjs';
import { runGitleaks, runSemgrep, runTrivy } from './lib/scanners.mjs';
import { trackedFiles, sensitiveFiles, personalData, unlockedDependencies, extraEndpoints, SENSITIVE_PATH } from './lib/own-checks.mjs';
import { findingId } from './lib/issues.mjs';
import { writeWorksheets } from './lib/review.mjs';
import { loadEol, loadKev, loadEpss } from './lib/intel.mjs';
import { inventory, techFindings } from './lib/tech.mjs';
import { dataMap, dataFindings, aiFiles } from './lib/datamap.mjs';
import { loadServers, serverFindings, serverSummary } from './lib/servidores.mjs';
import { networkModel, exposure, networkFindings } from './lib/red.mjs';
import { externalFindings } from './lib/externo.mjs';
import { detectCi, runZizmor, ciLineFindings, deployModel, oidcTerraformFindings, platformFindings, awsCiFindings } from './lib/cicd.mjs';
import { credentials } from './lib/plataforma.mjs';
import crypto from 'node:crypto';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FLOORPLAN = path.join(HERE, '..', '..', 'floorplan', 'scripts');
const RULES = path.join(HERE, '..', 'rules', 'lupa.yml');

const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const root = path.resolve(argv.find((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--solo')) || '.');
const only = (opt('--solo') || 'gitleaks,semgrep,trivy,zizmor,propios').split(',');
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
const unlocked = unlockedDependencies(files);
let packages = null;
step('gitleaks', () => (tools.gitleaks ? runGitleaks(tools.gitleaks, root, repos, log) : []));
step('semgrep', () => (tools.semgrep ? runSemgrep(tools.semgrep, root, { rulesFile: RULES, packs: argv.includes('--sin-paquetes') ? [] : undefined, log }) : []));
step('trivy', () => { if (!tools.trivy) return []; const r = runTrivy(tools.trivy, root, log, { unlocked: unlocked.map((f) => f.file) }); packages = r.packages; return r.findings; });
// CI/CD: zizmor para GitHub Actions (con el token de gh, si hay, hace también las comprobaciones en línea) y reglas
// comunes para los pipelines de cualquier plataforma, más la confianza OIDC del Terraform del CI
const ci = detectCi(files);
// los repos donde zizmor dio un resultado válido: solo ahí se dejan de contar los avisos de GitHub Actions de Semgrep
let zizmorOk = new Set();
step('zizmor', () => {
  if (!tools.zizmor || !ci.sistemas.some((x) => x.ci === 'github-actions')) return [];
  const z = runZizmor(tools.zizmor, root, repos, { token: (credentials('github')?.authorization || '').replace(/^Bearer /, ''), log });
  zizmorOk = z.ok;
  return z.findings;
});
step('propios', () => [...sensitiveFiles(files, root), ...personalData(root, files), ...unlocked, ...ciLineFindings(root, ci.ficheros), ...oidcTerraformFindings(root, files)]);
// la lista de paquetes se guarda: con --solo sin Trivy se reutiliza la de la pasada anterior
if (packages) writeJSON(path.join(outDir, 'paquetes.json'), packages);
else packages = readJSON(path.join(outDir, 'paquetes.json'), []);

// lo que el mapa ignora a propósito (código generado, soluciones de ejemplo, librerías copiadas) tampoco cuenta aquí
const arch = readJSON(path.join(root, 'floorplan', 'architecture.json'), {});
const ignored = (arch.ignore || []).map(globToRegExp);
if (ignored.length) {
  const before = findings.length;
  findings = findings.filter((f) => !ignored.some((re) => re.test(f.file)));
  if (before > findings.length) console.log(`  (${before - findings.length} hallazgos en carpetas que el mapa ignora, fuera)`);
}

// con --solo se conserva lo que encontraron en la pasada anterior las herramientas que no se lanzan ahora
const TOOL_OF = { gitleaks: ['gitleaks'], semgrep: ['semgrep'], trivy: ['trivy'], zizmor: ['zizmor'], propios: ['lupa', 'lupa-ci'] };
const prevRun = readJSON(path.join(outDir, 'hallazgos.json'));
if (prevRun && only.length < Object.keys(TOOL_OF).length) {
  const ran = new Set(only.flatMap((s) => TOOL_OF[s] || []));
  const kept = prevRun.hallazgos.filter((f) => !ran.has(f.tool));
  findings.push(...kept);
  Object.assign(versions, Object.fromEntries(Object.entries(prevRun.herramientas || {}).filter(([n]) => !versions[n])));
  if (kept.length) console.log(`  (se conservan ${kept.length} hallazgos de la pasada anterior)`);
}

// ---------------------------------------------------------------- KEV, EPSS y tecnología
// cada CVE se cruza con el catálogo de la CISA (explotado ahora mismo) y con EPSS (probabilidad de ataque)
const s1 = Date.now();
const [eol, kev] = await Promise.all([loadEol(log), loadKev(log)]);
const epss = await loadEpss(findings.flatMap((f) => (f.cves || []).map((c) => c.id)), log);
for (const f of findings) {
  if (!f.cves || f.enriched) continue;
  f.enriched = true;
  for (const c of f.cves) { const k = kev?.get(c.id); if (k) c.kev = k; const e = epss.get(c.id); if (e) c.epss = e.percentil; }
  f.epssMax = Math.max(0, ...f.cves.map((c) => c.epss || 0));
  const kevs = f.cves.filter((c) => c.kev);
  if (!kevs.length) continue;
  f.kev = kevs.map((c) => c.id);
  f.severity = 'high';
  f.title = `Explotada ahora mismo (KEV): ${f.title}`;
  f.detail = `${f.kev.join(', ')} ${kevs.length > 1 ? 'están' : 'está'} en el catálogo KEV de la CISA: se ${kevs.length > 1 ? 'están' : 'está'} usando en ataques reales${kevs.some((c) => c.kev.ransomware) ? ', también en campañas de ransomware' : ''}. Es lo primero que hay que parchear. ${f.detail}`;
}
// la tecnología se recalcula siempre, también con --solo
findings = findings.filter((f) => f.cat !== 'tecnologia');
const inv = inventory({ root, files, scan, packages, eol });
const techF = techFindings(inv);
findings.push(...techF);
// CVE por componente, para la foto
const cvesOf = new Map();
for (const f of findings) if (f.cat === 'dependencias' && f.cves) cvesOf.set(`${f.pkg}@${f.version}`, { total: f.cves.length, graves: f.cves.filter((c) => c.sev === 'high').length, kev: (f.kev || []).length });
for (const c of inv.componentes) c.cves = cvesOf.get(`${c.nombre}@${c.version}`) || null;
// mapa de datos personales (dónde se guardan pasaportes, DNI, salud…) y ficheros que llaman a una IA
const dmap = dataMap(root, files);
const DATA_RULES = new Set(['guarda-cvv', 'tarjeta-sin-cifrar', 'datos-sensibles-sin-cifrar']);
findings = findings.filter((f) => !DATA_RULES.has(f.rule));
findings.push(...dataFindings(dmap));
const iaFiles = aiFiles(root, files);
inv.ficherosIA = iaFiles;
writeJSON(path.join(outDir, 'tecnologia.json'), { generadoEn: new Date().toISOString(), ...inv });
writeJSON(path.join(outDir, 'datos.json'), { generadoEn: new Date().toISOString(), ...dmap });
console.log(`  datos     ${String(dmap.ficheros.length).padStart(5)} modelos/tablas con datos personales (${Object.keys(dmap.resumen).join(', ') || 'ninguno'}) · ${iaFiles.length} ficheros llaman a una IA`);
// también las que ya venían marcadas de una pasada anterior (con --solo no se vuelven a cruzar)
const kevCount = findings.filter((f) => f.kev?.length).length;
console.log(`  tecnología ${String(inv.componentes.length).padStart(4)} piezas · ${techF.filter((f) => f.rule === 'sin-soporte').length} sin soporte · ${kevCount} librerías con CVE explotadas (KEV)  (${Math.round((Date.now() - s1) / 1000)} s)`);

// «respuesta del modelo pintada sin limpiar» solo tiene sentido en un repo que usa IA
const repoOf = (file) => (repos.length ? repos : [{ path: '.' }]).filter((r) => r.path === '.' || file.startsWith(r.path + '/')).sort((a, b) => b.path.length - a.path.length)[0]?.path || '.';
const aiRepos = new Set([...iaFiles, ...(inv.ia || []).map((a) => a.fichero)].map(repoOf));
const beforeIa = findings.length;
findings = findings.filter((f) => f.rule !== 'lupa.ia.respuesta-sin-limpiar' || aiRepos.has(repoOf(f.file)));
if (beforeIa > findings.length) console.log(`  (${beforeIa - findings.length} avisos de IA en repos que no usan IA, fuera)`);
// lo que el mapa ignora tampoco cuenta para la tecnología ni los datos, que se calculan después
if (ignored.length) findings = findings.filter((f) => !ignored.some((re) => re.test(f.file)));

// ---------------------------------------------------------------- servidores, red y vista desde internet
// Vienen de lo recogido aparte (servidores-ssm.mjs o lupa-servidor.py por ssh, y externo.mjs) y se
// recalculan siempre, como la tecnología. Cada servidor y cada objetivo público es una tarjeta propia.
const INFRA_TOOLS = new Set(['lupa-servidor', 'lupa-red', 'lupa-externo']);
findings = findings.filter((f) => !INFRA_TOOLS.has(f.tool));
const servers = loadServers(path.join(outDir, 'servidores'));
const awsNet = readJSON(path.join(outDir, 'red-aws.json'));
const ext = readJSON(path.join(outDir, 'externo.json'));
const srvF = servers.flatMap((h) => serverFindings(h, { eolData: eol }));
const netModel = networkModel(servers, awsNet);
const exposed = exposure(servers, awsNet);
const infraF = [...srvF, ...(servers.length || awsNet ? networkFindings(servers, netModel, exposed) : []), ...externalFindings(ext)].map((f) => ({ ...f, clave: f.clave || f.title }));
findings.push(...infraF);
if (servers.length || awsNet || ext) {
  const audited = new Set(servers.map((h) => h.aws?.id).filter(Boolean));
  writeJSON(path.join(outDir, 'infra.json'), {
    generadoEn: new Date().toISOString(), servidores: servers.map((h) => serverSummary(h, srvF, { eolData: eol })),
    sinAuditar: (awsNet?.instancias || []).filter((i) => !audited.has(i.id)).map((i) => ({ nombre: i.nombre, ip: i.ipPrivada })),
    red: netModel, expuesto: exposed,
    externo: ext ? { desde: ext.desde, generadoEn: ext.generadoEn, objetivos: ext.objetivos.map((t) => ({ objetivo: t.objetivo, ip: t.ip || '', privado: !!t.privado, error: t.error || '',
      puertos: (t.puertos || []).map((p) => ({ puerto: p.puerto, servicio: p.servicio, tls: p.tls ? { valido: p.tls.valido, caduca: p.tls.caduca, dias: p.tls.dias, emisor: p.tls.emisor, protocolo: p.tls.protocolo } : null, http: p.http ? { estado: p.http.estado, titulo: p.http.titulo } : null })) })) } : null,
  });
  console.log(`  infra     ${String(servers.length).padStart(5)} servidores por dentro · ${netModel.edges.length} conexiones · ${exposed.length} puertas a internet · vista externa: ${ext ? `${ext.objetivos.length} objetivos` : 'sin hacer'} (${infraF.length} avisos)`);
}

// ---------------------------------------------------------------- CI/CD y despliegue
// La plataforma (GitHub, Bitbucket), los logs y los roles de AWS vienen de cicd.mjs y se recalculan siempre.
// Lo de GitHub Actions lo cuenta zizmor con más contexto: si ha corrido, Semgrep no lo repite.
const CICD_TOOLS = new Set(['lupa-plataforma', 'lupa-aws']);
findings = findings.filter((f) => !CICD_TOOLS.has(f.tool));
// (con --solo sin zizmor, cuentan los repos con hallazgos suyos conservados de la pasada anterior)
for (const f of findings.filter((x) => x.tool === 'zizmor')) zizmorOk.add(repoOf(f.file));
findings = findings.filter((f) => !(/^yaml\.github-actions\./.test(f.rule) && zizmorOk.has(repoOf(f.file))));
const cicd = readJSON(path.join(outDir, 'cicd.json'));
const despliegue = deployModel(root, ci.ficheros);
// cada repositorio se mide con sus propios pipelines: un runner propio en el repo A no es un aviso para el B
const pipelinesOf = (ruta) => ci.ficheros.filter((f) => repoOf(f.fichero) === (ruta || '.'));
const cicdF = [...(cicd?.plataformas || []).flatMap((p) => platformFindings(p, deployModel(root, pipelinesOf(p.ruta)))), ...awsCiFindings(cicd?.aws)].map((f) => ({ ...f, clave: f.clave || f.title }));
findings.push(...cicdF);
if (ci.ficheros.length || cicd) {
  // las etapas del camino a producción se cuentan en merge.mjs, después de la criba de la IA
  writeJSON(path.join(outDir, 'cicd-resumen.json'), {
    generadoEn: new Date().toISOString(), sistemas: ci.sistemas, ficheros: ci.ficheros.length, despliegue, revisadoPorFuera: !!cicd,
    plataformas: (cicd?.plataformas || []).map((p) => ({ plataforma: p.plataforma, repo: p.repo, privado: p.privado, rama: p.ramaPrincipal, proteccion: p.proteccion, revisionReal: p.revisionReal,
      entornos: p.entornos || [], secretos: (p.secretos || []).length, logs: p.logs || null, huecos: p.huecos || [], error: p.error || null })),
    aws: cicd?.aws ? { cuenta: cicd.aws.cuenta || null, roles: (cicd.aws.roles || []).length, error: cicd.aws.error || null } : null,
  });
  console.log(`  cicd      ${String(ci.ficheros.length).padStart(5)} pipelines (${ci.sistemas.map((x) => x.nombre).join(', ') || 'ninguno'}) · plataforma: ${cicd ? (cicd.plataformas || []).map((p) => p.plataforma).join(', ') : 'sin revisar (cicd.mjs)'} · ${findings.filter((x) => x.cat === 'cicd').length} avisos`);
}

// el mismo aviso visto dos veces (dos reglas, o la misma con varias coincidencias) cuenta una vez
const seen = new Set();
findings = findings.filter((f) => { const k = `${f.cat}|${f.rule}|${f.file}|${f.line}|${f.pkg || f.clave || ''}`; if (seen.has(k)) return false; seen.add(k); return true; });
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
const iaSet = new Set(iaFiles);
// la ruta lleva un identificador («/solicitudes/:id», «{id}», «<int:pk>»…): candidata a ver datos de otro
const ID_IN_PATH = /\/:\w+|\{\w+\}|<(?:\w+:)?\w+>|\[\w+\]/;
// el manejador menciona campos de datos personales del mapa de datos
const piiNames = [...new Set(dmap.ficheros.flatMap((d) => d.campos.map((c) => c.campo)).filter((n) => n.length >= 5 && /^\w+$/.test(n)))];
const piiRe = piiNames.length ? new RegExp('\\b(?:' + piiNames.join('|') + ')\\b') : null;
const endpoints = [
  ...[...byHandler.values()].map((e) => {
    const paths = [...new Set(e.paths)].sort((a, b) => a.length - b.length);
    return { ref: e.refs[0], refs: e.refs, method: e.method, path: paths[0], realPath: commonRoute(paths), otherPaths: paths.slice(1), file: e.file, line: e.line, framework: '', floorplanOpen: e.refs.some((r) => fpOpen.has(r)) ? true : null };
  }),
  ...extraEndpoints(root, files, routeFiles).map((e) => ({ ref: 'f:' + e.file, method: e.method, path: e.path, file: e.file, line: e.line, framework: e.framework, authHint: e.authHint })),
].map((e) => ({ ...e, sensitive: SENSITIVE_PATH.test([e.path, ...(e.otherPaths || [])].join(' ')) }))
  .map((e) => {
    const text = (() => { try { return fs.readFileSync(path.join(root, e.file), 'utf8'); } catch { return ''; } })();
    // usa IA si el fichero, o uno que importa directamente, llama a un modelo
    const usaIA = iaSet.has(e.file) || (graph.links || []).some((l) => l.a === 'f:' + e.file && l.k === 'import' && iaSet.has(String(l.b).slice(2)));
    return { ...e, usaIA, parametroId: ID_IN_PATH.test(e.path), datosPersonales: !!piiRe && piiRe.test(text),
      huella: crypto.createHash('sha1').update(snippet(path.join(root, e.file), e.line, 3, 30)).digest('hex').slice(0, 12) };
  })
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
