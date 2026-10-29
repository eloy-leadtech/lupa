// Pruebas de la parte de arquitectura de Lupa: las pistas, la hoja de trabajo, las propuestas y el informe.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { signals, writeArchWorksheet, loadProposals, diagram, archSection, archDir } from '../skills/lupa/scripts/lib/arquitectura.mjs';
import { buildReport } from '../skills/lupa/scripts/lib/report.mjs';
import { deliveryInfo } from '../skills/lupa/scripts/lib/entrega.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS = path.join(HERE, '..', 'skills', 'lupa', 'scripts');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-arq-'));

// un mapa pequeño: api y datos se importan el uno al otro, y util lo usa todo el mundo
const GRAPH = {
  project: { name: 'Visados' }, meta: { repos: [{ path: '.', name: 'visados' }] },
  nodes: [{ id: 'api', label: 'API' }, { id: 'datos', label: 'Datos' }, { id: 'util', label: 'Utilidades' }, { id: 'pruebas', label: 'Pruebas', kind: 'test' }],
  files: [
    { p: 'api/solicitudes.js', n: 'api', l: 'javascript', loc: 400 }, { p: 'api/documentos.js', n: 'api', l: 'javascript', loc: 250 },
    { p: 'datos/modelo.js', n: 'datos', l: 'javascript', loc: 120 }, { p: 'util/log.js', n: 'util', l: 'javascript', loc: 30 },
    { p: 'pruebas/modelo.test.js', n: 'pruebas', l: 'javascript', loc: 40 }, { p: '.github/dependabot.yml', n: 'unassigned', l: 'yaml', loc: 10 },
    { p: 'docs/adr/0001-postgres.md', n: 'unassigned', l: 'markdown', loc: 20 },
  ],
  routes: [], links: [
    { a: 'f:api/solicitudes.js', b: 'f:datos/modelo.js', k: 'import' }, { a: 'f:api/documentos.js', b: 'f:datos/modelo.js', k: 'import' },
    { a: 'f:datos/modelo.js', b: 'f:api/solicitudes.js', k: 'import' },
    { a: 'f:api/solicitudes.js', b: 'f:util/log.js', k: 'import' }, { a: 'f:api/documentos.js', b: 'f:util/log.js', k: 'import' }, { a: 'f:datos/modelo.js', b: 'f:util/log.js', k: 'import' },
    { a: 'f:pruebas/modelo.test.js', b: 'f:datos/modelo.js', k: 'import' },
  ],
};
const FINDINGS = ['a.js', 'b.js', 'c.js'].map((file, i) => ({ tool: 'semgrep', rule: 'sql-concatenado', cat: 'codigo', severity: i ? 'medium' : 'high', file, title: 'SQL armado con texto del usuario' }))
  .concat([{ tool: 'gitleaks', rule: 'aws', cat: 'secretos', severity: 'high', file: 'config.js', title: 'Clave de AWS' }]);
const ENDPOINTS = [
  { method: 'GET', path: '/solicitudes/:id', file: 'api/solicitudes.js', parametroId: true, revision: { publico: false, deberiaSerPublico: false, severidad: 'alta' } },
  { method: 'GET', path: '/documentos', file: 'api/documentos.js', revision: { publico: true, deberiaSerPublico: false, severidad: 'alta' } },
  { method: 'GET', path: '/salud', file: 'api/documentos.js', revision: { publico: true, deberiaSerPublico: true, severidad: 'ninguna' } },
];

test('las pistas: reglas repetidas, endpoints, enredos, lo más usado, módulos sin pruebas y lo ya decidido', () => {
  const s = signals({ root: tmp(), graph: GRAPH, findings: FINDINGS, endpoints: ENDPOINTS, aiFiles: ['api/chat.js'] });
  assert.equal(s.seguridad.repetidos.length, 1, 'solo la regla que sale en 3 sitios o más');
  assert.deepEqual([s.seguridad.repetidos[0].regla, s.seguridad.repetidos[0].sitios, s.seguridad.repetidos[0].gravedad], ['sql-concatenado', 3, 'high']);
  assert.equal(s.seguridad.endpoints.abiertosQueNoDeberian.length, 1);
  assert.equal(s.seguridad.endpoints.conIdentificadorYProblema.length, 1);
  assert.equal(s.seguridad.dependencias.actualizacionAutomatica, true);
  assert.deepEqual(s.general.enredos.map((e) => [e.a, e.b].sort()), [['API', 'Datos']]);
  assert.equal(s.general.masUsados[0].fichero, 'util/log.js');
  assert.equal(s.general.masUsados[0].n, 3, 'la prueba que lo importa no cuenta');
  const sin = s.general.pruebas.modulosSinPruebas.map((m) => m.modulo);
  assert.ok(sin.includes('API') && !sin.includes('Datos'), 'Datos tiene una prueba que lo importa');
  assert.deepEqual(s.decididos, ['docs/adr/0001-postgres.md']);
});

test('las zonas calientes salen del historial de git', () => {
  const d = tmp();
  const git = (...a) => spawnSync('git', ['-C', d, ...a], { encoding: 'utf8' });
  git('init', '-q'); git('config', 'user.email', 't@t'); git('config', 'user.name', 't'); git('config', 'commit.gpgsign', 'false');
  fs.mkdirSync(path.join(d, 'api'));
  const commit = (file, i) => { fs.writeFileSync(path.join(d, file), `// ${i}\n`); git('add', '-A'); git('commit', '-qm', `c${i}`); };
  for (let i = 0; i < 3; i++) commit('api/solicitudes.js', i);
  const short = signals({ root: d, graph: GRAPH });
  assert.equal(short.general.commits, 3);
  assert.deepEqual(short.general.calientes, [], 'con un historial corto no hay zonas calientes');
  for (let i = 3; i < 10; i++) commit('api/solicitudes.js', i);
  commit('api/documentos.js', 10);
  const s = signals({ root: d, graph: GRAPH });
  assert.deepEqual(s.general.calientes.slice(0, 2).map((c) => [c.fichero, c.cambios]), [['api/solicitudes.js', 10], ['api/documentos.js', 1]]);
});

test('la hoja de trabajo: pendiente, al día si nada cambia, y lo rechazado no se vuelve a proponer', () => {
  const d = tmp();
  const s = signals({ root: d, graph: GRAPH, findings: FINDINGS, endpoints: ENDPOINTS });
  assert.equal(writeArchWorksheet(d, s).estado, 'pendiente');
  const file = path.join(archDir(d), 'propuestas.json');
  assert.match(fs.readFileSync(path.join(archDir(d), 'pistas.md'), 'utf8'), /sql-concatenado/);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify({ ...j, hecho: true, propuestas: [{ titulo: 'Un ORM', tipo: 'seguridad', decision: { estado: 'rechazada', motivo: 'ya hay un ADR' } }] }));
  assert.equal(writeArchWorksheet(d, s).estado, 'al-dia');
  const after = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after.rechazadas, [{ titulo: 'Un ORM', motivo: 'ya hay un ADR' }]);
  assert.match(fs.readFileSync(path.join(archDir(d), 'pistas.md'), 'utf8'), /Rechazadas por el equipo:\n- Un ORM — ya hay un ADR/);
  // otra regla repetida: las pistas cambian y hay que revisar, sin perder lo que había
  const more = FINDINGS.concat(['x.js', 'y.js', 'z.js'].map((file) => ({ tool: 'semgrep', rule: 'xss', cat: 'codigo', severity: 'medium', file, title: 'XSS' })));
  assert.equal(writeArchWorksheet(d, signals({ root: d, graph: GRAPH, findings: more, endpoints: ENDPOINTS })).estado, 'cambiada');
  const changed = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(changed.hecho, false);
  assert.equal(changed.propuestas.length, 1);
});

const PROPUESTA = {
  id: 'Capa de Permisos', tipo: 'seguridad', fuerza: 'fuerte', titulo: 'Una sola capa que decide quién ve cada expediente <img src=x onerror=alert(1)>',
  problema: 'Cada endpoint comprueba el permiso a su manera.', quitaDeRaiz: ['IDOR en /solicitudes/:id'], ficheros: ['api/solicitudes.js'],
  antes: { cajas: [{ id: 'a', texto: 'GET /solicitudes/:id', marca: 'problema' }, { id: 'b', texto: 'Modelo' }], flechas: [['a', 'b'], ['b', 'a'], ['a', 'zz']] },
  despues: { cajas: [{ id: 'a', texto: 'Endpoints' }, { id: 'p', texto: 'Permisos', marca: 'nuevo' }, { id: 'b', texto: 'Modelo' }], flechas: [['a', 'p'], ['p', 'b']] },
  alternativas: [{ nombre: 'Middleware central', recomendada: true, esfuerzo: 'medio', aFavor: ['un solo sitio'], enContra: ['toca todas las rutas'] },
    { nombre: 'Políticas en la BD (RLS)', esfuerzo: 'alto', recomendada: true }, { nombre: 'Servicio de permisos', esfuerzo: 'enorme' }, { nombre: 'Una cuarta' }],
  porQue: 'Es lo más directo.', primerPaso: 'Crea lib/permisos.js y úsalo en las rutas de /solicitudes.',
};

test('las propuestas se normalizan: como mucho 3 alternativas, una sola recomendada y diagramas sin flechas rotas', () => {
  const d = tmp();
  fs.mkdirSync(archDir(d), { recursive: true });
  fs.writeFileSync(path.join(archDir(d), 'propuestas.json'), JSON.stringify({ hecho: true, porDondeEmpezar: { id: 'capa-de-permisos', motivo: 'quita el IDOR' },
    propuestas: [PROPUESTA, { titulo: 'Partir el módulo de solicitudes', tipo: 'raro', alternativas: [{ nombre: 'Solo una' }] }, { tipo: 'general' }] }));
  const a = loadProposals(d);
  assert.equal(a.propuestas.length, 2, 'la que no tiene título no entra');
  const [p, g] = a.propuestas;
  assert.equal(p.id, 'capa-de-permisos');
  assert.equal(p.alternativas.length, 3);
  assert.deepEqual(p.alternativas.map((x) => x.recomendada), [true, false, false]);
  assert.equal(p.alternativas[2].esfuerzo, 'medio', 'un esfuerzo desconocido queda en medio');
  assert.deepEqual(p.antes.flechas, [['a', 'b'], ['b', 'a']]);
  assert.equal(g.tipo, 'general');
  assert.ok(a.avisos.some((x) => /Partir el módulo/.test(x) && /2 o 3/.test(x)));
  assert.equal(a.porDondeEmpezar.id, 'capa-de-permisos');
});

test('el diagrama: una caja por elemento, la flecha de vuelta discontinua y los textos escapados', () => {
  const svg = diagram({ cajas: [{ id: 'a', texto: 'Rutas <script>', marca: 'problema' }, { id: 'b', texto: 'Modelo' }], flechas: [['a', 'b'], ['b', 'a']] }, 'Ahora');
  assert.equal((svg.match(/<rect /g) || []).length, 2);
  assert.match(svg, /class="ae back"/);
  assert.ok(!svg.includes('<script>'));
  assert.match(svg, /▲ Rutas/);
});

test('el informe separa seguridad y mantenibilidad, y sin propuestas la pasada sale incompleta', () => {
  const d = tmp();
  fs.mkdirSync(archDir(d), { recursive: true });
  fs.writeFileSync(path.join(archDir(d), 'propuestas.json'), JSON.stringify({ hecho: true, propuestas: [PROPUESTA, { ...PROPUESTA, id: 'partir', tipo: 'general', titulo: 'Partir solicitudes' }] }));
  const arch = loadProposals(d);
  const html = buildReport({ graph: { project: { name: 'Visados' }, nodes: [{ id: 'api', label: 'API', stats: { files: 1 } }], files: [], routes: [], meta: { repos: [] }, health: { issues: [] }, lupa: {} }, tech: null, datos: null, arch });
  const seg = html.indexOf('Arquitectura · seguridad de raíz'), gen = html.indexOf('Arquitectura · mantenibilidad'), sup = html.indexOf('<h2>Superficie de ataque');
  assert.ok(seg > 0 && seg < sup && gen > sup, 'seguridad junto a lo urgente; mantenibilidad al final');
  assert.ok(!html.includes('<img src=x'), 'el título va escapado');
  assert.match(html, /✓ Recomendada/);
  assert.ok(!archSection(null, 'general'), 'sin propuestas no hay bloque de mantenibilidad');
  assert.match(archSection(null, 'seguridad'), /Sin propuestas/);
  const e = deliveryInfo({ root: d, graph: { project: { name: 'Visados' }, meta: { repos: [] } }, found: { avisos: [] }, answers: { findings: new Map() }, endpoints: [], discarded: [], infra: null });
  assert.ok(e.huecos.includes('sin propuestas de arquitectura'));
  assert.ok(!deliveryInfo({ root: d, graph: { project: { name: 'Visados' }, meta: { repos: [] } }, found: { avisos: [] }, answers: { findings: new Map() }, endpoints: [], discarded: [], infra: null, arquitectura: arch }).huecos.includes('sin propuestas de arquitectura'));
});

test('arquitectura.mjs y merge.mjs: las propuestas llegan al mapa, al informe y a sus datos', () => {
  const d = tmp();
  const fp = path.join(d, 'floorplan');
  fs.mkdirSync(path.join(fp, 'lupa'), { recursive: true });
  const raw = JSON.stringify({ ...GRAPH, meta: {} });
  fs.writeFileSync(path.join(fp, 'graph.json'), raw);
  fs.writeFileSync(path.join(fp, 'index.html'), `<html><head><title>Visados</title></head><body><script>window.FLOORPLAN = ${raw};</script></body></html>`);
  fs.writeFileSync(path.join(fp, 'lupa', 'hallazgos.json'), JSON.stringify({ herramientas: {}, avisos: [], hallazgos: FINDINGS.map((f, i) => ({ ...f, id: 'h' + i, line: 1, detail: '', fix: '' })) }));
  let r = spawnSync(process.execPath, [path.join(SCRIPTS, 'arquitectura.mjs'), d], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /pendiente/);
  const file = path.join(archDir(d), 'propuestas.json');
  fs.writeFileSync(file, JSON.stringify({ ...JSON.parse(fs.readFileSync(file, 'utf8')), hecho: true, propuestas: [PROPUESTA] }));
  r = spawnSync(process.execPath, [path.join(SCRIPTS, 'arquitectura.mjs'), d], { encoding: 'utf8' });
  assert.match(r.stdout, /al día/);
  r = spawnSync(process.execPath, [path.join(SCRIPTS, 'merge.mjs'), d], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const g = JSON.parse(fs.readFileSync(path.join(fp, 'graph.json'), 'utf8'));
  assert.equal(g.lupa.arquitectura.propuestas[0].recomendada, 'Middleware central');
  const html = fs.readFileSync(path.join(fp, 'lupa', 'informe.html'), 'utf8');
  assert.match(html, /id="arq-capa-de-permisos"/);
  const data = JSON.parse(/<script type="application\/json" id="lupa-datos">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.equal(data.arquitectura[0].id, 'capa-de-permisos');
  assert.ok(!('ficheros' in data.arquitectura[0]), 'los datos llevan lo justo para comparar');
});
