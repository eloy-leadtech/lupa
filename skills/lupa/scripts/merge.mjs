#!/usr/bin/env node
// Lupa · pintar. Junta los hallazgos con la revisión de la IA y los mete en el mapa de floorplan:
// en su lista de Health, como mapa de calor sobre las tarjetas y en el panel de Lupa.
//
//   node merge.mjs <raíz>
//
// Hay que lanzarlo después de cada build de floorplan, porque el build reescribe el mapa sin Lupa.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { readJSON, writeJSON, SEV_RANK, plural } from './lib/util.mjs';
import { toIssues, endpointFindings, makeMapper, findingId, CATS, OUTSIDE_NODE, INFRA_NODE, INFRA_FILE } from './lib/issues.mjs';
import { loadAnswers, endpointKey, triageKey } from './lib/review.mjs';
import { buildReport } from './lib/report.mjs';
import { deliveryInfo } from './lib/entrega.mjs';
import { stageSummary } from './lib/cicd.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UI = path.join(HERE, '..', 'assets', 'lupa-ui.js');
const root = path.resolve(process.argv.slice(2).find((a) => !a.startsWith('--')) || '.');
const fp = path.join(root, 'floorplan');
const lupaDir = path.join(fp, 'lupa');

const rawGraph = fs.readFileSync(path.join(fp, 'graph.json'), 'utf8').trim();
const graph = JSON.parse(rawGraph);
const found = readJSON(path.join(lupaDir, 'hallazgos.json'));
const surface = readJSON(path.join(lupaDir, 'superficie.json'), { endpoints: [] });
const tech = readJSON(path.join(lupaDir, 'tecnologia.json'));
const datos = readJSON(path.join(lupaDir, 'datos.json'));
const infra = readJSON(path.join(lupaDir, 'infra.json'));
const cicdRaw = readJSON(path.join(lupaDir, 'cicd-resumen.json'));
if (!found) { console.error('No hay floorplan/lupa/hallazgos.json: lanza antes scan.mjs.'); process.exit(2); }
// el equipo que hace la pasada: se dice una vez con --equipo y se recuerda en ficha.json
const argv = process.argv.slice(2);
const equipoArg = argv.includes('--equipo') ? argv[argv.indexOf('--equipo') + 1] : null;
const ficha = { ...readJSON(path.join(lupaDir, 'ficha.json'), {}), ...(equipoArg ? { equipo: equipoArg } : {}) };
if (equipoArg) writeJSON(path.join(lupaDir, 'ficha.json'), ficha);
const answers = loadAnswers(path.join(lupaDir, 'revision'));

// Un mapa ya pintado por Lupa trae sus propios avisos: se quitan para no duplicarlos.
const fpIssues = (graph.health?.issues || []).filter((i) => !String(i.id).startsWith('lupa:'));
graph.nodes = graph.nodes.filter((n) => n.id !== OUTSIDE_NODE && n.id !== INFRA_NODE);
graph.files = graph.files.filter((f) => f.n !== OUTSIDE_NODE && f.n !== INFRA_NODE);

// ---------------------------------------------------------------- criba de la IA
const verdict = (id) => answers.findings.get(id);
const discarded = [];
let findings = found.hallazgos.filter((f) => {
  const v = verdict(triageKey(f));
  if (v?.veredicto === 'falso-positivo') { discarded.push({ ...f, motivo: v.motivo }); return false; }
  if (v?.severidad && ['alta', 'media', 'baja'].includes(v.severidad)) f.severity = { alta: 'high', media: 'medium', baja: 'low' }[v.severidad];
  if (v?.motivo) f.detail = `${f.detail}\n\nRevisión de la IA: ${v.motivo}`;
  return true;
});
const keptFp = fpIssues.filter((i) => {
  const v = verdict('fp:' + i.id);
  if (v?.veredicto === 'falso-positivo') { discarded.push({ id: 'fp:' + i.id, title: i.title, motivo: v.motivo, tool: 'floorplan' }); return false; }
  return true;
});

// lo que la IA encontró por su cuenta
for (const x of answers.extra) {
  const f = {
    tool: 'ia', cat: CATS[x.categoria] ? x.categoria : 'codigo', rule: 'revision-ia',
    severity: { alta: 'high', media: 'medium', baja: 'low' }[x.severidad] || 'medium',
    file: x.fichero || '', line: +x.linea || 1, title: x.titulo, detail: x.detalle || '', fix: x.arreglo || '',
  };
  f.id = findingId(f);
  findings.push(f);
}

// endpoints con la respuesta de la IA
// una revisión hecha sobre otro código (huella distinta) ya no vale: el endpoint sale como «sin revisar»
const reviewOf = (e) => { const a = answers.endpoints.get(endpointKey(e)); return a && (!a.huella || !e.huella || a.huella === e.huella) ? a : null; };
const endpoints = (surface.endpoints || []).map((e) => ({ ...e, shown: e.realPath || e.path, revision: reviewOf(e) }));
findings.push(...endpointFindings(endpoints));

// floorplan ya avisa de secretos; si Lupa tiene el mismo fichero, se queda el de Lupa (trae el historial)
const lupaSecretFiles = new Set(findings.filter((f) => f.cat === 'secretos').map((f) => f.file));
const finalFp = keptFp.filter((i) => !(i.kind === 'secret' && (i.locations || []).some((l) => lupaSecretFiles.has(l.file))));

// ---------------------------------------------------------------- al mapa
const mapper = makeMapper(graph);
const lupaIssues = toIssues(findings, mapper);

// lo que floorplan no dibuja cuelga de nodos propios: ficheros (Jenkinsfile, claves, ficheros de bloqueo…)
// y la infraestructura viva (cada servidor, la red y cada objetivo público es una tarjeta)
const outside = [
  { id: OUTSIDE_NODE, label: 'Fuera del mapa (Lupa)', files: [...mapper.outside].filter((p) => !INFRA_FILE.test(p)),
    summary: 'Ficheros con avisos de seguridad que floorplan no dibuja: pipelines, claves, copias de datos, ficheros de dependencias.', card: 'Fichero con avisos de seguridad que floorplan no dibuja. Lo cuelga aquí Lupa.' },
  { id: INFRA_NODE, label: 'Servidores y red (Lupa)', files: [...mapper.outside].filter((p) => INFRA_FILE.test(p)),
    summary: 'Los servidores del proyecto por dentro, cómo se comunican y lo que se ve desde internet.', card: 'Revisado por Lupa: un servidor por dentro, la red entre servidores o un objetivo visto desde internet.' },
];
const repos = (graph.meta?.repos || []).map((r) => r.path).filter((p) => p && p !== '.').sort((a, b) => b.length - a.length);
for (const o of outside.filter((x) => x.files.length)) {
  graph.nodes.push({ id: o.id, parent: null, label: o.label, kind: 'infra', summary: o.summary,
    details: 'Este nodo lo añade Lupa. Cada tarjeta tiene al menos un aviso.', tags: ['lupa'], paths: [], packages: [], hosts: [],
    stats: { files: o.files.length, loc: 0, langs: {} } });
  for (const p of o.files) graph.files.push({ p, n: o.id, r: INFRA_FILE.test(p) ? '.' : repos.find((r) => p.startsWith(r + '/')) || '.', l: null, loc: 0, name: path.posix.basename(p), d: o.card });
}

const issues = [...lupaIssues, ...finalFp].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
const count = (s, list = issues) => list.filter((i) => i.severity === s).length;
graph.health = { summary: { high: count('high'), medium: count('medium'), low: count('low') }, issues };

const perCat = {};
for (const i of lupaIssues) { const c = i.lupa.cat; perCat[c] ||= { high: 0, medium: 0, low: 0, avisos: 0 }; perCat[c][i.severity]++; perCat[c].avisos += i.lupa.count; }
const reviewed = endpoints.filter((e) => e.revision).length;
graph.lupa = {
  version: 1, generadoEn: new Date().toISOString(), herramientas: found.herramientas, avisos: found.avisos,
  categorias: perCat, nombres: CATS,
  endpoints: endpoints.map((e) => ({
    ref: e.ref, metodo: e.method, ruta: e.shown, fichero: e.file, linea: e.line, delicado: !!e.sensitive,
    publico: e.revision ? e.revision.publico : null, deberiaSerPublico: e.revision ? e.revision.deberiaSerPublico : null,
    severidad: e.revision?.severidad || '', motivo: e.revision?.motivo || '', datos: e.revision?.datos || [],
  })),
  revision: { endpoints: reviewed, endpointsTotal: endpoints.length, hallazgosCribados: answers.findings.size, descartados: discarded.length },
  descartados: discarded.slice(0, 200).map((d) => ({ titulo: d.title, fichero: d.file || '', motivo: d.motivo || '', herramienta: d.tool })),
  // librerías con CVE del catálogo KEV: lo primero que hay que parchear
  kev: findings.filter((f) => f.kev?.length).map((f) => ({
    paquete: f.pkg, version: f.version, cves: f.kev, fichero: f.file, epss: Math.max(0, ...(f.cves || []).filter((c) => c.kev).map((c) => c.epss || 0)),
    ransomware: (f.cves || []).some((c) => c.kev?.ransomware), arreglo: [...new Set((f.cves || []).filter((c) => c.kev && c.fixed).map((c) => c.fixed))].join(', '),
  })),
  tecnologia: tech ? {
    sinSoporte: tech.componentes.filter((c) => c.eol?.estado === 'sin-soporte').map((c) => ({ nombre: c.nombre, version: c.version, tipo: c.tipo, fichero: c.fichero, fin: c.eol.finSoporte })),
    piezas: tech.componentes.length, ia: [...new Set((tech.ia || []).map((a) => a.nombre))], ficherosIA: tech.ficherosIA || [],
  } : null,
  datos: datos ? { resumen: Object.fromEntries(Object.entries(datos.resumen).map(([k, v]) => [k, { campos: v.campos, ficheros: v.ficheros.length, especial: !!v.especial }])),
    ficheros: datos.ficheros.map((d) => ({ fichero: d.fichero, tipos: d.tipos, especial: d.especial, cifrado: d.cifrado })) } : null,
};

// ---------------------------------------------------------------- escribir
const json = JSON.stringify(graph);
fs.writeFileSync(path.join(fp, 'graph.json'), json);
const LS = String.fromCharCode(0x2028), PS = String.fromCharCode(0x2029); // separadores de línea de Unicode, que rompen un <script>
const BS = String.fromCharCode(92); // la barra invertida, escrita con su codigo para que ningun editor la toque
// como lo escribe el build de floorplan, para encontrarlo
const esc = (s) => s.replace(/<\/(script)/gi, '<' + BS + '/$1').split(LS).join(BS + 'u2028').split(PS).join(BS + 'u2029');
// como lo escribe Lupa: todo «<» como <, para que ni «</script» ni «<!--» dentro de un texto (un nombre
// de fichero de un servidor, por ejemplo) corten el bloque y dejen el mapa en blanco
const escFull = (s) => s.replace(/</g, BS + 'u003c').split(LS).join(BS + 'u2028').split(PS).join(BS + 'u2029');
let html = fs.readFileSync(path.join(fp, 'index.html'), 'utf8');
const [at, oldLen] = [escFull, esc].map((e) => [html.indexOf(e(rawGraph)), e(rawGraph).length]).find(([i]) => i >= 0) || [-1, 0];
if (at < 0) { console.error('No encuentro los datos del mapa dentro de index.html. Vuelve a lanzar el build de floorplan y luego merge.mjs.'); process.exit(3); }
html = html.slice(0, at) + escFull(json) + html.slice(at + oldLen);
html = html.replace(/<!--lupa:inicio-->[\s\S]*?<!--lupa:fin-->/g, '');
const ui = fs.readFileSync(UI, 'utf8').replace(/<\/script/gi, '<\\/script');
html = html.replace(/<\/body>(?![\s\S]*<\/body>)/, `<!--lupa:inicio--><script>/* Lupa */\n${ui}</script><!--lupa:fin-->\n</body>`);
html = html.replace(/<title>([^<]*)<\/title>/, (m, t) => `<title>${t.replace(/ · Lupa$/, '')} · Lupa</title>`);
fs.writeFileSync(path.join(fp, 'index.html'), html);
// el informe para quien evalúa: un solo HTML, sin nada externo, con la ficha de la pasada y los datos dentro
// el camino a producción, con lo que queda después de la criba (los falsos positivos ya no cuentan)
const cicd = cicdRaw ? { ...cicdRaw, etapas: stageSummary(findings) } : null;
const entrega = deliveryInfo({ root, graph, found, answers, endpoints, discarded, infra, cicd, equipo: ficha.equipo });
// El mapa del código viaja dentro del informe, comprimido: quien lo recibe no tiene floorplan/ ni Claude Code.
// La copia va sin la ruta de este equipo (sin ella tampoco salen los enlaces «abrir en el editor») y sin la
// barra de preguntas, que necesita Claude Code en local y en un fichero entregado solo pediría ejecutar comandos.
const mapJson = escFull(JSON.stringify({ ...graph, meta: { ...graph.meta, root: null } }));
const mapAt = html.indexOf(escFull(json));
let mapCopy = html.slice(0, mapAt) + mapJson + html.slice(mapAt + escFull(json).length);
for (const variant of new Set([root, root.replace(/\\/g, '\\\\'), root.replace(/\\/g, '/')])) mapCopy = mapCopy.split(variant).join(entrega.proyecto);
mapCopy = mapCopy.replace(/<\/head>/, '<style>/* Lupa: copia entregada */#ask{display:none!important}</style></head>');
// ni los avisos de floorplan que piden «Run the skill again»: quien lo recibe no tiene nada que ejecutar
mapCopy = mapCopy.replace(/<\/body>(?![\s\S]*<\/body>)/, '<script>new MutationObserver(()=>document.querySelectorAll(".callout").forEach((c)=>{if(/Run the skill/.test(c.textContent))c.remove()})).observe(document.documentElement,{childList:true,subtree:true})</script></body>');
const mapa = zlib.gzipSync(Buffer.from(mapCopy, 'utf8'), { level: 9 }).toString('base64');
const report = buildReport({ graph, tech, datos, infra, cicd, entrega, mapa });
fs.writeFileSync(path.join(lupaDir, 'informe.html'), report);
// la copia para mandar lleva el proyecto y la fecha en el nombre, para que no se pisen en el correo
const slug = (s) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase();
const sendName = `lupa-${[slug(ficha.equipo), slug(entrega.proyecto)].filter(Boolean).join('-')}-${entrega.generado.slice(0, 10)}.html`;
for (const old of fs.readdirSync(lupaDir).filter((n) => /^lupa-.*\.html$/.test(n))) fs.rmSync(path.join(lupaDir, old));
fs.writeFileSync(path.join(lupaDir, sendName), report);

// informe en texto, para pegar en un ticket o en el canal del equipo
const md = [`# Lupa · ${graph.project?.name || path.basename(root)}`, '', `Generado el ${new Date().toLocaleString('es-ES')}.`, '',
  '| Categoría | Graves | A mirar | Menores |', '|---|---:|---:|---:|',
  ...Object.entries(CATS).filter(([c]) => perCat[c]).map(([c, n]) => `| ${n} | ${perCat[c].high} | ${perCat[c].medium} | ${perCat[c].low} |`), '',
  `Endpoints: ${endpoints.length} · revisados por la IA: ${reviewed} · descartados como falsos positivos: ${discarded.length}.`, '',
  ...(infra ? [`Servidores revisados por dentro: ${infra.servidores?.length || 0} · conexiones vistas: ${infra.red?.edges?.length || 0} · puertas a internet: ${infra.expuesto?.length || 0} · vista desde internet: ${infra.externo ? `desde ${infra.externo.desde}` : 'no hecha'}.`, ''] : []),
  `Cobertura: ${entrega.completo ? 'completa' : entrega.huecos.join(' · ')}.`, '',
  '## Lo grave', '', ...issues.filter((i) => i.severity === 'high').slice(0, 40).map((i) => { const l = i.locations?.[0]; return `- **${i.title}**${l ? ` — \`${INFRA_FILE.test(l.file) ? l.file : `${l.file}:${l.line}`}\`` : ''}`; }), ''];
fs.writeFileSync(path.join(lupaDir, 'informe.md'), md.join('\n'));

console.log(`LUPA  ${plural(lupaIssues.length, 'aviso')} en el mapa (${count('high', lupaIssues)} graves · ${count('medium', lupaIssues)} a mirar · ${count('low', lupaIssues)} menores) + ${finalFp.length} de floorplan`);
console.log(`      endpoints revisados por la IA: ${reviewed}/${endpoints.length} · descartados: ${discarded.length}${mapper.outside.size ? ` · ${mapper.outside.size} ficheros colgados en «Fuera del mapa»` : ''}`);
if (reviewed < endpoints.length) console.log(`      ⚠ faltan ${endpoints.length - reviewed} endpoints por revisar: el mapa los enseña como «sin revisar».`);
console.log(`✓ mapa actualizado: ${path.relative(root, path.join(fp, 'index.html'))} · informe: floorplan/lupa/informe.html (y .md)`);
if (!entrega.completo) console.log(`      ⚠ pasada incompleta: ${entrega.huecos.join(' · ')}`);
console.log(`➜ Para mandar: floorplan/lupa/${sendName} (un solo fichero, sin nada externo)`);
