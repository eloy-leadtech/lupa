// Pruebas de Lupa: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sensitiveFiles, personalData, extraEndpoints, unlockedDependencies } from '../skills/lupa/scripts/lib/own-checks.mjs';
import { toIssues, makeMapper, endpointFindings, OUTSIDE_NODE } from '../skills/lupa/scripts/lib/issues.mjs';
import { writeWorksheets, loadAnswers, endpointKey, triageKey } from '../skills/lupa/scripts/lib/review.mjs';
import { mask, normSeverity, tmpDir, globToRegExp } from '../skills/lupa/scripts/lib/util.mjs';
import { runGitleaks, runSemgrep } from '../skills/lupa/scripts/lib/scanners.mjs';
import { dataMap, dataFindings, aiFiles } from '../skills/lupa/scripts/lib/datamap.mjs';
import { eolStatus, cleanVersion, purlKey } from '../skills/lupa/scripts/lib/intel.mjs';
import { writeApps, EXPECTED_RULES } from './fixtures/apps.mjs';
import { findTool } from '../skills/lupa/scripts/lib/tools.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS = path.join(HERE, '..', 'skills', 'lupa', 'scripts');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-test-'));

test('los ficheros delicados se reconocen por su nombre', () => {
  const out = sensitiveFiles(['infra/terraform.tfstate', 'keys/id_rsa', 'db/backup.sql', 'src/app.ts', 'docs/ejemplo.sql']);
  const byFile = Object.fromEntries(out.map((f) => [f.file, f.severity]));
  assert.equal(byFile['infra/terraform.tfstate'], 'high');
  assert.equal(byFile['keys/id_rsa'], 'high');
  assert.equal(byFile['db/backup.sql'], 'medium');
  assert.equal(byFile['src/app.ts'], undefined);
  assert.equal(byFile['docs/ejemplo.sql'], undefined, 'una copia de BD de ejemplo en docs no es un aviso');
});

test('los datos personales solo cuentan si pasan la validación', () => {
  const d = tmp();
  // 12345678Z es un DNI válido; 12345678A no. El IBAN y la tarjeta son los de ejemplo de la documentación.
  fs.writeFileSync(path.join(d, 'clientes.csv'), 'nombre,dni,iban,tarjeta\n' + Array.from({ length: 6 }, () => 'Ana,12345678Z,ES9121000418450200051332,4111111111111111').join('\n'));
  fs.writeFileSync(path.join(d, 'falsos.csv'), 'dni\n12345678A\n87654321A\n');
  const out = personalData(d, ['clientes.csv', 'falsos.csv']);
  assert.equal(out.length, 1);
  assert.equal(out[0].file, 'clientes.csv');
  assert.equal(out[0].severity, 'high');
  assert.deepEqual(Object.keys(out[0].counts).sort(), ['card', 'dni', 'iban']);
  assert.ok(!JSON.stringify(out).includes('12345678Z'), 'nunca se copia un dato personal al hallazgo');
});

test('endpoints de Laravel, Django y PHP suelto, con pista de login', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, 'routes'));
  fs.writeFileSync(path.join(d, 'routes', 'web.php'), "<?php\nRoute::get('/admin/users', [UserController::class, 'index'])->middleware('auth');\nRoute::post('/contacto', [C::class, 'send']);\nRoute::middleware(['auth:sanctum'])->group(function () {\n  Route::delete('/cuenta', [C::class, 'borrar']);\n});\nRoute::get('/publico', [C::class, 'ver']);\n");
  fs.writeFileSync(path.join(d, 'urls.py'), "\"\"\"Ejemplo:\n    path('blog/', include('blog.urls'))\n\"\"\"\n# path('viejo/', views.viejo)\nurlpatterns = [\n  path('api/export/', views.export),\n]\n");
  fs.writeFileSync(path.join(d, 'borrar.php'), "<?php $id = $_POST['id']; mysqli_query($c, \"DELETE FROM u WHERE id=$id\");");
  const out = extraEndpoints(d, ['routes/web.php', 'urls.py', 'borrar.php']);
  const by = Object.fromEntries(out.map((e) => [`${e.method} ${e.path}`, e]));
  assert.equal(by['GET /admin/users'].authHint, true);
  assert.equal(by['POST /contacto'].authHint, false, 'el login de la ruta de arriba no cuenta para esta');
  assert.equal(by['DELETE /cuenta'].authHint, true, 'dentro de un grupo con auth');
  assert.equal(by['GET /publico'].authHint, false, 'fuera del grupo ya no');
  assert.equal(by['ANY /api/export/'].framework, 'django');
  assert.equal(by['ANY /api/export/'].line, 6, 'la línea no se mueve al quitar comentarios');
  assert.ok(!by['ANY /blog/'] && !by['ANY /viejo/'], 'las rutas de docstrings y comentarios no cuentan');
  assert.equal(by['POST /borrar.php'].framework, 'php');
});

test('los hallazgos se agrupan por fichero y caen en su tarjeta o en «Fuera del mapa»', () => {
  const graph = { files: [{ p: 'api/server.js', n: 'api' }], routes: [] };
  const mapper = makeMapper(graph);
  const f = (file, line, severity, cat = 'codigo') => ({ tool: 'semgrep', cat, rule: 'r' + line, file, line, severity, title: `t${line}`, detail: 'd', fix: 'x' });
  const issues = toIssues([f('api/server.js', 3, 'medium'), f('api/server.js', 9, 'high'), f('ci/Jenkinsfile', 2, 'low', 'infra')], mapper);
  assert.equal(issues.length, 2);
  assert.equal(issues[0].severity, 'high');
  assert.deepEqual(issues[0].items, ['f:api/server.js']);
  assert.match(issues[0].title, /2 problemas/);
  assert.ok(mapper.outside.has('ci/Jenkinsfile'));
  assert.equal(OUTSIDE_NODE, 'lupa-fuera');
});

test('la revisión de la IA convierte endpoints en avisos y respeta «ninguna»', () => {
  const eps = [
    { ref: 'r:0', method: 'GET', path: '/api/users', file: 'a.js', line: 1, revision: { publico: true, deberiaSerPublico: false, datos: ['emails'], severidad: 'alta', motivo: 'm', arreglo: 'x' } },
    { ref: 'r:1', method: 'POST', path: '/login', file: 'a.js', line: 9, revision: { publico: true, deberiaSerPublico: true, severidad: 'ninguna' } },
  ];
  const out = endpointFindings(eps);
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, 'high');
  assert.match(out[0].title, /no debería/);
});

test('los lotes recuerdan lo ya revisado', () => {
  const d = tmp();
  const dir = path.join(d, 'rev');
  const eps = [{ method: 'GET', path: '/a', file: 'x.js', line: 1 }, { method: 'POST', path: '/b', file: 'x.js', line: 5 }];
  const first = writeWorksheets({ root: d, dir, endpoints: eps, findings: [] });
  assert.equal(first.pendientesEndpoints, 2);
  const lote = JSON.parse(fs.readFileSync(path.join(dir, 'lote-01.json'), 'utf8'));
  lote.endpoints[0].severidad = 'ninguna';
  fs.writeFileSync(path.join(dir, 'lote-01.json'), JSON.stringify(lote));
  const second = writeWorksheets({ root: d, dir, endpoints: eps, findings: [] });
  assert.equal(second.pendientesEndpoints, 1);
  assert.equal(second.yaRevisados, 1);
  assert.ok(loadAnswers(dir).endpoints.has(endpointKey(eps[0])));
});

test('si el código de un endpoint cambia, su revisión caduca y se vuelve a pedir', () => {
  const d = tmp();
  const dir = path.join(d, 'rev');
  const ep = { method: 'GET', path: '/a', file: 'x.js', line: 1, huella: 'aaa' };
  writeWorksheets({ root: d, dir, endpoints: [ep], findings: [] });
  const lote = JSON.parse(fs.readFileSync(path.join(dir, 'lote-01.json'), 'utf8'));
  assert.equal(lote.endpoints[0].huella, 'aaa');
  lote.endpoints[0].severidad = 'ninguna';
  fs.writeFileSync(path.join(dir, 'lote-01.json'), JSON.stringify(lote));
  assert.equal(writeWorksheets({ root: d, dir, endpoints: [ep], findings: [] }).pendientesEndpoints, 0, 'mismo código: no se repite');
  const r = writeWorksheets({ root: d, dir, endpoints: [{ ...ep, huella: 'bbb' }], findings: [] });
  assert.equal(r.pendientesEndpoints, 1, 'código cambiado: se vuelve a revisar');
  assert.match(fs.readFileSync(path.join(dir, 'lote-01.md'), 'utf8'), /el código cambió/);
});

test('mapa de datos personales: pasaportes, salud y el CVV prohibido', () => {
  const d = tmp();
  writeApps(d);
  const m = dataMap(d, ['visados/models/application.js', 'visados/migrations/001_applicants.sql', 'visados/db.js']);
  assert.equal(m.ficheros.length, 2);
  assert.ok(m.resumen['pasaporte'] && m.resumen['salud'] && m.resumen['antecedentes penales']);
  const rules = dataFindings(m).map((f) => f.rule);
  assert.ok(rules.includes('guarda-cvv') && rules.includes('tarjeta-sin-cifrar') && rules.includes('datos-sensibles-sin-cifrar'));
  assert.deepEqual(aiFiles(d, ['chat/api/chat.ts', 'chat/agent/agent.py', 'visados/db.js']), ['chat/api/chat.ts', 'chat/agent/agent.py']);
});

test('mapa de datos personales: la «fingerprint» de un hallazgo es un hash, no una huella dactilar', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, 'app', 'schemas'), { recursive: true });
  fs.writeFileSync(path.join(d, 'app', 'schemas', 'findings.py'), 'from pydantic import BaseModel\nclass Finding(BaseModel):\n    rule_id: str\n    fingerprint: str\n');
  fs.writeFileSync(path.join(d, 'app', 'schemas', 'empleado.py'), 'from pydantic import BaseModel\nclass Empleado(BaseModel):\n    nombre: str\n    fingerprint_template: bytes\n');
  const m = dataMap(d, ['app/schemas/findings.py', 'app/schemas/empleado.py']);
  assert.deepEqual(m.ficheros.map((f) => f.fichero), ['app/schemas/empleado.py']);
  assert.ok(m.ficheros[0].tipos.includes('foto o biometría'));
});

test('reglas propias de IA y web: cada una pilla su fallo', { skip: !findTool('semgrep') && 'Semgrep no está instalado' }, () => {
  const d = tmp();
  writeApps(d);
  const got = new Set(runSemgrep(findTool('semgrep'), d, { rulesFile: path.join(HERE, '..', 'skills', 'lupa', 'rules', 'lupa.yml'), packs: [] }).map((f) => f.rule));
  for (const r of EXPECTED_RULES) assert.ok(got.has(r), `falta ${r}`);
});

test('versiones y ciclo de vida', () => {
  assert.equal(cleanVersion('^4.17.1'), '4.17.1');
  assert.equal(cleanVersion('14-alpine'), '14');
  const product = { name: 'nodejs', releases: [
    { name: '26', isEol: false, eolFrom: '2029-04-30', isLts: false, latest: { name: '26.1.0' } },
    { name: '24', isEol: false, eolFrom: '2028-04-30', isLts: true, latest: { name: '24.9.0' } },
    { name: '20', isEol: true, eolFrom: '2026-04-30', latest: { name: '20.19.5' } },
  ] };
  assert.equal(eolStatus(product, '20.11.0').estado, 'sin-soporte');
  assert.equal(eolStatus(product, '24.1.0').estado, 'al-dia', 'una LTS en vigor no está desactualizada');
  assert.equal(eolStatus(product, '12.0.0').estado, 'sin-soporte', 'más vieja que cualquier rama conocida');
  assert.equal(eolStatus(product, '99.0.0').estado, 'desconocido', 'una versión que el catálogo aún no tiene');
  assert.equal(purlKey('pkg:npm/%40angular/core@17.0.0'), 'npm/@angular/core');
});

test('la misma regla en el mismo fichero se criba una vez', () => {
  const a = { tool: 'semgrep', rule: 'r', file: 'f.js', line: 1 }, b = { ...a, line: 40 }, c = { ...a, file: 'g.js' };
  assert.equal(triageKey(a), triageKey(b));
  assert.notEqual(triageKey(a), triageKey(c));
});

test('los globs del mapa se traducen bien', () => {
  const ok = (g, p) => globToRegExp(g).test(p);
  assert.ok(ok('**/frontend/src/assets/**', 'juice-shop/frontend/src/assets/x/y.js'));
  assert.ok(ok('juice-shop/data/static/codefixes/**', 'juice-shop/data/static/codefixes/a.ts'));
  assert.ok(ok('**/*.min.js', 'a/b/c.min.js'));
  assert.ok(ok('**/*.min.js', 'c.min.js'));
  assert.ok(ok('dvwa/external', 'dvwa/external/lib/x.php'), 'sin comodines vale como carpeta');
  assert.ok(ok('src/*.{ts,tsx}', 'src/a.tsx'));
  assert.ok(!ok('src/*.{ts,tsx}', 'src/sub/a.tsx'));
  assert.ok(!ok('**/*.min.js', 'a/b/c.js'));
});

test('dependencias sin fichero de bloqueo, mirando también las carpetas de arriba', () => {
  const out = unlockedDependencies(['app/package.json', 'mono/package.json', 'mono/yarn.lock', 'mono/packages/ui/package.json', 'api/composer.json', 'api/composer.lock', 'test/fixtures/package.json']);
  assert.deepEqual(out.map((f) => f.file), ['app/package.json']);
});

test('utilidades: tapar secretos, severidades y carpeta temporal sin tildes', () => {
  assert.ok(!mask('sk_' + 'live_abcdefghijklmnop').includes('abcdefgh'));
  assert.equal(normSeverity('CRITICAL'), 'high');
  assert.equal(normSeverity('WARNING'), 'medium');
  assert.equal(normSeverity('INFO'), 'low');
  if (process.platform === 'win32') assert.ok(!/[^\x00-\x7F]/.test(fs.realpathSync.native(tmpDir())));
});

test('gitleaks: un secreto borrado del código sigue saliendo, marcado como «solo en el historial»', { skip: !findTool('gitleaks') && 'gitleaks no está instalado' }, () => {
  const d = tmp();
  const fakeKey = 'AKIA' + 'Q3EGR7XPLM2NKD4T'; // inventada; partida en dos para que los escáneres no salten con el propio Lupa
  const git = (...a) => spawnSync('git', ['-C', d, '-c', 'user.email=t@t', '-c', 'user.name=t', ...a], { encoding: 'utf8' });
  git('init', '-q');
  fs.writeFileSync(path.join(d, 'keys.js'), `const k = "${fakeKey}";\n`);
  git('add', '-A'); git('commit', '-qm', 'clave');
  fs.writeFileSync(path.join(d, 'keys.js'), 'const k = process.env.AWS_KEY;\n');
  git('commit', '-qam', 'fuera');
  const out = runGitleaks(findTool('gitleaks'), d, [{ path: '.' }]);
  assert.equal(out.length, 1);
  assert.equal(out[0].inHistoryOnly, true);
  assert.equal(out[0].severity, 'medium');
  assert.ok(!JSON.stringify(out).includes(fakeKey), 'el valor nunca aparece');
});

test('merge mete Lupa en el mapa y se puede repetir sin duplicar', () => {
  const d = tmp();
  const fp = path.join(d, 'floorplan');
  fs.mkdirSync(path.join(fp, 'lupa'), { recursive: true });
  const graph = { project: { name: 'Prueba' }, meta: {}, nodes: [{ id: 'api', label: 'API', kind: 'service' }], files: [{ p: 'api/server.js', n: 'api', name: 'server.js' }], routes: [{ f: 'api/server.js', m: 'GET', p: '/api/users', l: 3 }], health: { issues: [] } };
  const raw = JSON.stringify(graph);
  fs.writeFileSync(path.join(fp, 'graph.json'), raw);
  fs.writeFileSync(path.join(fp, 'index.html'), `<html><head><title>Prueba map</title></head><body><script>window.FLOORPLAN = ${raw};</script></body></html>`);
  fs.writeFileSync(path.join(fp, 'lupa', 'hallazgos.json'), JSON.stringify({ herramientas: {}, avisos: [], hallazgos: [
    { id: 'a1', tool: 'gitleaks', cat: 'secretos', rule: 'aws', severity: 'high', file: 'api/server.js', line: 2, title: 'Secreto', detail: 'd', fix: 'x' },
    { id: 'a2', tool: 'semgrep', cat: 'infra', rule: 'jenkins', severity: 'medium', file: 'Jenkinsfile', line: 4, title: 'Jenkins', detail: 'd', fix: 'x' },
  ] }));
  fs.writeFileSync(path.join(fp, 'lupa', 'superficie.json'), JSON.stringify({ endpoints: [{ ref: 'r:0', method: 'GET', path: '/api/users', file: 'api/server.js', line: 3 }] }));
  for (let i = 0; i < 2; i++) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, 'merge.mjs'), d], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  }
  const g = JSON.parse(fs.readFileSync(path.join(fp, 'graph.json'), 'utf8'));
  assert.equal(g.health.issues.filter((x) => x.id.startsWith('lupa:')).length, 2);
  assert.equal(g.nodes.filter((n) => n.id === OUTSIDE_NODE).length, 1, 'el nodo «Fuera del mapa» no se duplica');
  assert.ok(g.files.some((f) => f.p === 'Jenkinsfile' && f.n === OUTSIDE_NODE));
  const html = fs.readFileSync(path.join(fp, 'index.html'), 'utf8');
  assert.equal((html.match(/<!--lupa:inicio-->/g) || []).length, 1, 'la pieza de Lupa se inyecta una sola vez');
  assert.ok(html.includes(JSON.stringify(g)), 'el mapa lleva los datos nuevos');
  assert.match(html, /<title>Prueba map · Lupa<\/title>/);
  assert.ok(fs.existsSync(path.join(fp, 'lupa', 'informe.md')));
});
