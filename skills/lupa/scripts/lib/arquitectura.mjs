// La arquitectura: en vez de cuarenta arreglos sueltos, los pocos cambios de estructura que quitan los
// problemas de raíz. Lupa saca las pistas (lo que se repite en los avisos, las zonas que más cambian, los
// módulos que se enredan) y Claude, con el código delante, propone para cada problema 2 o 3 alternativas
// comparadas. Hay dos tipos y el informe los enseña por separado: «seguridad» (quitan avisos de raíz) y
// «general» (lo que hace el código difícil de cambiar y de probar). Ninguna cuenta para la nota.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { run, readJSON, writeJSON, posix, SEV_RANK, worst } from './util.mjs';
import { esc, SEV } from './report-ui.mjs';
import { firstSentence } from './issues.mjs';

export const TIPOS = { seguridad: 'Seguridad de raíz', general: 'Mantenibilidad' };
export const FUERZA = {
  fuerte: { word: 'Fuerte', css: 'f1', icon: '●●●' },
  'merece-la-pena': { word: 'Merece la pena', css: 'f2', icon: '●●○' },
  especulativa: { word: 'Especulativa', css: 'f3', icon: '●○○' },
};
const ESFUERZO = { bajo: 'Bajo', medio: 'Medio', alto: 'Alto' };
const DECISION = { aceptada: 'Aceptada', rechazada: 'Rechazada', 'en-curso': 'En curso' };

const TEST_PATH = /(^|\/)(__tests__|tests?|spec|specs|e2e|cypress|playwright)(\/|$)|[._-](test|spec)\.[a-z0-9]+$/i;
const NOT_CODE = /\.(lock|json|ya?ml|md|txt|css|scss|svg|png|jpe?g|gif|ico|map|snap)$|(^|\/)(package-lock|pnpm-lock|yarn\.lock|composer\.lock|go\.sum)/i;
const AUTO_UPDATES = /(^|\/)(\.github\/dependabot\.ya?ml|renovate\.json5?|\.renovaterc(\.json)?|\.github\/renovate\.json5?)$/i;
const ADR_DIR = /(^|\/)(docs?\/(adr|adrs|decisions|architecture\/decisions)|adr|adrs)\/[^/]+\.md$/i;

/** Dónde Lupa guarda las pistas y las propuestas. */
export const archDir = (root) => path.join(root, 'floorplan', 'lupa', 'arquitectura');

/** Cuántas veces ha cambiado cada fichero en el último año, en todos los repos del mapa, y cuántos commits hay. */
function churn(root, repos, since) {
  const out = new Map();
  let commits = 0;
  for (const r of repos.length ? repos : [{ path: '.' }]) {
    const dir = path.join(root, r.path || '.');
    const res = run('git', ['-C', dir, 'log', `--since=${since}`, '--no-merges', '--name-only', '--format=%x00'], { timeout: 120_000 });
    if (res.status !== 0) continue;
    commits += (res.stdout.match(/\0/g) || []).length;
    for (const line of res.stdout.split(/\r?\n/)) {
      const f = line.replace(/\0/g, '').trim(); if (!f) continue;
      const p = r.path && r.path !== '.' ? posix(path.join(r.path, f)) : f;
      out.set(p, (out.get(p) || 0) + 1);
    }
  }
  return { cambios: out, commits };
}
// con menos commits que esto (un clon superficial, un repo recién importado) no hay zonas calientes que ver
const MIN_COMMITS = 10;

/**
 * Las pistas para la IA. Nada de esto es una propuesta: son los sitios donde merece la pena mirar.
 * @param findings los hallazgos ya cribados (sin falsos positivos)
 * @param endpoints los endpoints con su revisión (`revision`), como los arma merge.mjs
 */
export function signals({ root, graph, findings = [], endpoints = [], datos = null, aiFiles = [], since = '12 months ago' }) {
  const files = graph.files || [];
  const fileNode = new Map(files.map((f) => [f.p, f.n]));
  const nodes = new Map((graph.nodes || []).map((n) => [n.id, n]));
  const label = (id) => nodes.get(id)?.label || id;

  // ---------------------------------------------------------------- seguridad
  // la misma regla en tres sitios o más no es un descuido: es que falta una pieza que lo haga bien para todos
  const byRule = new Map();
  for (const f of findings) {
    // los endpoints y lo que encontró la IA van aparte: cada uno es un problema distinto aunque compartan «regla»
    if (f.cat === 'dependencias' || f.cat === 'tecnologia' || f.tool === 'ia') continue;
    const k = `${f.tool}|${f.rule}`;
    if (!byRule.has(k)) byRule.set(k, { regla: f.rule, herramienta: f.tool, cat: f.cat, titulo: f.title, sitios: new Set(), sev: [] });
    const g = byRule.get(k);
    g.sitios.add(f.host || f.file); g.sev.push(f.severity);
  }
  const repetidos = [...byRule.values()].filter((g) => g.sitios.size >= 3)
    .map((g) => ({ regla: g.regla, herramienta: g.herramienta, cat: g.cat, titulo: g.titulo, gravedad: worst(g.sev), sitios: g.sitios.size, ejemplos: [...g.sitios].slice(0, 6) }))
    .sort((a, b) => SEV_RANK[a.gravedad] - SEV_RANK[b.gravedad] || b.sitios - a.sitios).slice(0, 12);

  const rev = endpoints.filter((e) => e.revision);
  const shown = (e) => `${e.method} ${e.realPath || e.path} · ${e.file}`;
  const abiertos = rev.filter((e) => e.revision.deberiaSerPublico === false && e.revision.publico !== false);
  const conId = rev.filter((e) => e.parametroId && ['alta', 'media'].includes(e.revision.severidad));
  const conProblema = rev.filter((e) => ['alta', 'media'].includes(e.revision.severidad));
  // dónde viven los endpoints: si están repartidos por muchos módulos, cada uno decide el permiso a su manera
  const modsEp = new Set(endpoints.map((e) => fileNode.get(e.file)).filter(Boolean));

  const deps = findings.filter((f) => f.cat === 'dependencias');
  const personal = datos?.ficheros || [];

  const seguridad = {
    repetidos,
    endpoints: { total: endpoints.length, revisados: rev.length, modulos: modsEp.size, conProblema: conProblema.length,
      problemas: conProblema.slice(0, 15).map((e) => `${shown(e)} — ${e.revision.titulo || firstSentence(e.revision.motivo) || 'con un problema'}`),
      abiertosQueNoDeberian: abiertos.slice(0, 12).map(shown), conIdentificadorYProblema: conId.slice(0, 12).map(shown) },
    ia: { ficheros: aiFiles.slice(0, 12), avisos: findings.filter((f) => f.cat === 'ia').length },
    datosPersonales: { modelos: personal.length, especiales: personal.filter((d) => d.especial).length,
      sinCifrar: personal.filter((d) => !d.cifrado && (d.especial || d.tipos.some((t) => ['pasaporte', 'documento de identidad', 'datos de pago'].includes(t)))).slice(0, 10).map((d) => `${d.fichero} (${d.tipos.join(', ')})`) },
    secretos: { ficheros: [...new Set(findings.filter((f) => f.cat === 'secretos').map((f) => f.file))].slice(0, 12) },
    dependencias: { conFallos: deps.length, graves: deps.filter((f) => f.severity === 'high').length, actualizacionAutomatica: files.some((f) => AUTO_UPDATES.test(f.p)) },
  };

  // ---------------------------------------------------------------- mantenibilidad
  const code = files.filter((f) => f.l && !NOT_CODE.test(f.p) && f.n !== 'unassigned');
  const isTest = (p) => TEST_PATH.test(p) || nodes.get(fileNode.get(p))?.kind === 'test';
  const { cambios: ch, commits } = churn(root, graph.meta?.repos || [], since);
  const calientes = commits < MIN_COMMITS ? [] : code.filter((f) => !isTest(f.p) && ch.get(f.p))
    .map((f) => ({ fichero: f.p, cambios: ch.get(f.p), lineas: f.loc || 0, modulo: label(f.n) }))
    .sort((a, b) => b.cambios - a.cambios || b.lineas - a.lineas).slice(0, 15);

  const imports = (graph.links || []).filter((l) => l.k === 'import' && l.a?.startsWith('f:') && l.b?.startsWith('f:'));
  const fanIn = new Map(), fanOut = new Map(), pair = new Map(), testedFiles = new Set();
  for (const l of imports) {
    const a = l.a.slice(2), b = l.b.slice(2);
    if (isTest(a)) { testedFiles.add(b); continue; }
    (fanIn.get(b) || fanIn.set(b, new Set()).get(b)).add(a);
    (fanOut.get(a) || fanOut.set(a, new Set()).get(a)).add(b);
    const na = fileNode.get(a), nb = fileNode.get(b);
    if (na && nb && na !== nb) pair.set(`${na}>${nb}`, (pair.get(`${na}>${nb}`) || 0) + 1);
  }
  // dos módulos que se importan el uno al otro no se pueden entender, probar ni cambiar por separado
  const enredos = [];
  for (const [k, n] of pair) {
    const [a, b] = k.split('>');
    if (a < b && pair.get(`${b}>${a}`)) enredos.push({ a: label(a), b: label(b), ida: n, vuelta: pair.get(`${b}>${a}`) });
  }
  enredos.sort((x, y) => (y.ida + y.vuelta) - (x.ida + x.vuelta));
  const top = (m, n = 8) => [...m].map(([f, s]) => ({ fichero: f, n: s.size, modulo: label(fileNode.get(f)) })).sort((a, b) => b.n - a.n).slice(0, n);
  const grandes = code.filter((f) => !isTest(f.p)).sort((a, b) => (b.loc || 0) - (a.loc || 0)).slice(0, 10).map((f) => ({ fichero: f.p, lineas: f.loc || 0, modulo: label(f.n) }));
  // módulos con código que ninguna prueba toca (ni tiene pruebas dentro)
  const tests = code.filter((f) => isTest(f.p));
  const modsWithCode = new Map();
  for (const f of code) if (!isTest(f.p)) modsWithCode.set(f.n, (modsWithCode.get(f.n) || 0) + (f.loc || 0));
  const tocados = new Set([...testedFiles].map((p) => fileNode.get(p)));
  const sinPruebas = [...modsWithCode].filter(([n]) => !tocados.has(n) && nodes.get(n)?.kind !== 'external').sort((a, b) => b[1] - a[1]).slice(0, 10).map(([n, l]) => ({ modulo: label(n), lineas: l }));

  const general = {
    commits, calientes, enredos: enredos.slice(0, 8), masUsados: top(fanIn), masDependientes: top(fanOut), grandes,
    pruebas: { ficheros: tests.length, modulosSinPruebas: sinPruebas },
  };

  // lo ya decidido, para no volver a proponerlo
  const decididos = files.filter((f) => ADR_DIR.test(f.p)).map((f) => f.p).slice(0, 40);
  const glosario = files.find((f) => /(^|\/)(GLOSSARY|GLOSARIO|CONTEXT)\.md$/i.test(f.p))?.p || null;
  return { seguridad, general, decididos, glosario };
}

/**
 * Huella de las pistas: si no cambia, las propuestas de la pasada anterior siguen valiendo y la IA no las
 * rehace. Solo cuenta lo que cambiaría una propuesta, no cada commit.
 */
export function signalsPrint(s) {
  const bucket = (n) => (n >= 20 ? '20+' : n >= 10 ? '10+' : n >= 5 ? '5+' : String(n));
  const key = {
    r: s.seguridad.repetidos.map((g) => `${g.herramienta}|${g.regla}|${bucket(g.sitios)}`).sort(),
    e: [bucket(s.seguridad.endpoints.abiertosQueNoDeberian.length), bucket(s.seguridad.endpoints.conIdentificadorYProblema.length), bucket(s.seguridad.endpoints.conProblema)],
    i: bucket(s.seguridad.ia.ficheros.length), d: bucket(s.seguridad.datosPersonales.sinCifrar.length), k: bucket(s.seguridad.secretos.ficheros.length),
    u: s.seguridad.dependencias.actualizacionAutomatica,
    c: s.general.calientes.slice(0, 5).map((x) => x.fichero).sort(), n: s.general.enredos.map((x) => `${x.a}|${x.b}`).sort(),
    a: s.decididos.slice().sort(),
  };
  return crypto.createHash('sha1').update(JSON.stringify(key)).digest('hex').slice(0, 12);
}

const list = (arr, fmt = (x) => x) => (arr.length ? arr.map((x) => `- ${fmt(x)}`).join('\n') : '- (nada)');

/** La hoja de trabajo para la IA: qué mirar, lo ya decidido y dónde contestar. */
export function writeArchWorksheet(root, s) {
  const dir = archDir(root);
  fs.mkdirSync(dir, { recursive: true });
  const huella = signalsPrint(s);
  const file = path.join(dir, 'propuestas.json');
  const prev = readJSON(file, null);
  const rechazadas = [...(prev?.rechazadas || []), ...(prev?.propuestas || []).filter((p) => p.decision?.estado === 'rechazada').map((p) => ({ titulo: p.titulo, motivo: p.decision.motivo || '' }))]
    .filter((r, i, a) => r?.titulo && a.findIndex((x) => x.titulo === r.titulo) === i);
  const S = s.seguridad, G = s.general;
  const md = [
    '# Lupa · arquitectura', '',
    'Rellena `propuestas.json`, en esta carpeta, siguiendo la sección «Arquitectura» del SKILL de Lupa. Estas son pistas, no conclusiones: abre el código antes de proponer nada.', '',
    '## Pistas de seguridad', '',
    '### La misma regla en muchos sitios', list(S.repetidos, (g) => `${SEV[g.gravedad].word} · ${g.sitios} sitios · ${g.herramienta}/${g.regla} (${g.cat}): «${g.titulo}». Ejemplos: ${g.ejemplos.join(', ')}`), '',
    '### Endpoints', `- ${S.endpoints.total} endpoints en ${S.endpoints.modulos} módulos; ${S.endpoints.revisados} revisados; ${S.endpoints.conProblema} con problemas de severidad alta o media:`,
    list(S.endpoints.problemas, (x) => `  ${x}`),
    `- Abiertos y no deberían (${S.endpoints.abiertosQueNoDeberian.length}):`, list(S.endpoints.abiertosQueNoDeberian, (x) => `  ${x}`),
    `- Con un identificador en la ruta y algún problema (¿se comprueba de quién es el recurso?) (${S.endpoints.conIdentificadorYProblema.length}):`, list(S.endpoints.conIdentificadorYProblema, (x) => `  ${x}`), '',
    '### IA', `- Ficheros que llaman a un modelo (${S.ia.ficheros.length}): ${S.ia.ficheros.join(', ') || 'ninguno'} · avisos de IA: ${S.ia.avisos}`, '',
    '### Datos personales', `- ${S.datosPersonales.modelos} modelos o tablas con datos personales, ${S.datosPersonales.especiales} con categorías especiales.`, `- Delicados sin pistas de cifrado:`, list(S.datosPersonales.sinCifrar, (x) => `  ${x}`), '',
    '### Secretos', `- Ficheros con secretos: ${S.secretos.ficheros.join(', ') || 'ninguno'}`, '',
    '### Dependencias', `- ${S.dependencias.conFallos} ficheros de dependencias con CVE (${S.dependencias.graves} graves). Actualización automática (Dependabot/Renovate): ${S.dependencias.actualizacionAutomatica ? 'sí' : 'no'}.`, '',
    '## Pistas de mantenibilidad', '',
    '### Lo que más cambia (último año)', G.commits < MIN_COMMITS ? `- Historial corto (${G.commits} commits en el último año): no hay zonas calientes que ver.` : list(G.calientes, (x) => `${x.fichero} · ${x.cambios} cambios · ${x.lineas} líneas · ${x.modulo}`), '',
    '### Módulos que se importan el uno al otro', list(G.enredos, (x) => `${x.a} ⇄ ${x.b} (${x.ida} y ${x.vuelta} imports)`), '',
    '### Los más usados (de cuántos ficheros se importan)', list(G.masUsados, (x) => `${x.fichero} · ${x.n} · ${x.modulo}`), '',
    '### Los que más dependen de otros', list(G.masDependientes, (x) => `${x.fichero} · ${x.n} · ${x.modulo}`), '',
    '### Los más grandes', list(G.grandes, (x) => `${x.fichero} · ${x.lineas} líneas · ${x.modulo}`), '',
    '### Pruebas', `- ${G.pruebas.ficheros} ficheros de pruebas. Módulos que ninguna prueba importa directamente (las de punta a punta, que van por HTTP o por el navegador, no cuentan aquí: mira qué cubren):`, list(G.pruebas.modulosSinPruebas, (x) => `  ${x.modulo} (${x.lineas} líneas)`), '',
    '## Ya decidido: no lo vuelvas a proponer', '',
    s.decididos.length ? `ADR del repo (léelos antes): ${s.decididos.join(', ')}` : 'No hay ADR en el repo.',
    s.glosario ? `Vocabulario del dominio: ${s.glosario} (usa sus nombres).` : '',
    rechazadas.length ? `Rechazadas por el equipo:\n${list(rechazadas, (r) => `${r.titulo}${r.motivo ? ` — ${r.motivo}` : ''}`)}` : '', '',
  ];
  fs.writeFileSync(path.join(dir, 'pistas.md'), md.join('\n'));
  // las mismas pistas que la última vez y propuestas hechas: no hay nada que rehacer
  if (prev?.hecho && prev.huella === huella) { writeJSON(file, { ...prev, rechazadas }); return { estado: 'al-dia', huella }; }
  // si cambiaron, se conservan las anteriores (y sus decisiones) para que la IA las revise en vez de empezar de cero
  writeJSON(file, { huella, hecho: false, resumen: prev?.resumen || '', porDondeEmpezar: prev?.porDondeEmpezar || null, propuestas: prev?.propuestas || [], rechazadas });
  return { estado: prev?.propuestas?.length ? 'cambiada' : 'pendiente', huella };
}

const str = (v, n = 600) => String(v ?? '').trim().slice(0, n);
const strs = (v, n = 6, len = 240) => (Array.isArray(v) ? v : v ? [v] : []).map((x) => str(x, len)).filter(Boolean).slice(0, n);
const slug = (s) => str(s, 80).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function normDiagram(d) {
  const cajas = (Array.isArray(d?.cajas) ? d.cajas : []).filter((c) => c && c.id != null && c.texto).slice(0, 12)
    .map((c) => ({ id: str(c.id, 40), texto: str(c.texto, 70), marca: ['problema', 'nuevo', 'externo'].includes(c.marca) ? c.marca : '' }));
  const ids = new Set(cajas.map((c) => c.id));
  const flechas = (Array.isArray(d?.flechas) ? d.flechas : []).filter((f) => Array.isArray(f) && ids.has(String(f[0])) && ids.has(String(f[1])) && f[0] !== f[1])
    .slice(0, 24).map((f) => [String(f[0]), String(f[1])]);
  return cajas.length ? { cajas, flechas } : null;
}

/** Lee propuestas.json y lo deja en una forma segura de pintar. Devuelve también lo que se ha corregido. */
export function loadProposals(root) {
  const raw = readJSON(path.join(archDir(root), 'propuestas.json'), null);
  if (!raw) return null;
  const avisos = [];
  const seen = new Set();
  const propuestas = [];
  for (const p of Array.isArray(raw.propuestas) ? raw.propuestas : []) {
    const titulo = str(p?.titulo, 160);
    if (!titulo) continue;
    let id = slug(p.id || titulo) || 'propuesta';
    while (seen.has(id)) id += '-2';
    seen.add(id);
    let alts = (Array.isArray(p.alternativas) ? p.alternativas : []).filter((a) => a && a.nombre).slice(0, 3).map((a) => ({
      nombre: str(a.nombre, 90), como: str(a.como, 500), aFavor: strs(a.aFavor), enContra: strs(a.enContra),
      esfuerzo: ESFUERZO[a.esfuerzo] ? a.esfuerzo : 'medio', recomendada: a.recomendada === true,
    }));
    if (alts.length < 2) avisos.push(`«${titulo}»: tiene ${alts.length} alternativa${alts.length === 1 ? '' : 's'}; hacen falta 2 o 3 comparadas`);
    // una y solo una recomendada
    const rec = alts.findIndex((a) => a.recomendada);
    alts = alts.map((a, i) => ({ ...a, recomendada: i === (rec >= 0 ? rec : 0) }));
    const dec = p.decision && DECISION[p.decision.estado] ? { estado: p.decision.estado, motivo: str(p.decision.motivo, 300), adr: str(p.decision.adr, 200), fecha: str(p.decision.fecha, 10) } : null;
    propuestas.push({
      id, titulo, tipo: TIPOS[p.tipo] ? p.tipo : 'general', fuerza: FUERZA[p.fuerza] ? p.fuerza : 'merece-la-pena',
      problema: str(p.problema, 900), quitaDeRaiz: strs(p.quitaDeRaiz, 8, 160), ficheros: strs(p.ficheros, 20, 200),
      antes: normDiagram(p.antes), despues: normDiagram(p.despues), alternativas: alts,
      porQue: str(p.porQue, 600), primerPaso: str(p.primerPaso, 600), decision: dec,
    });
  }
  for (const t of Object.keys(TIPOS)) {
    const n = propuestas.filter((p) => p.tipo === t).length;
    if (n > 6) avisos.push(`${n} propuestas de ${TIPOS[t].toLowerCase()}: se enseñan las 6 primeras`);
  }
  const keep = Object.keys(TIPOS).flatMap((t) => propuestas.filter((p) => p.tipo === t).slice(0, 6));
  const start = raw.porDondeEmpezar && keep.find((p) => p.id === slug(raw.porDondeEmpezar.id || raw.porDondeEmpezar)) ? { id: slug(raw.porDondeEmpezar.id || raw.porDondeEmpezar), motivo: str(raw.porDondeEmpezar.motivo, 400) } : null;
  return { hecho: raw.hecho === true, huella: str(raw.huella, 20), resumen: str(raw.resumen, 600), porDondeEmpezar: start, propuestas: keep, avisos };
}

// ---------------------------------------------------------------- dibujo de antes y después

/** Parte un texto en líneas de unos `n` caracteres, como mucho `max` líneas. */
function wrap(text, n = 22, max = 4) {
  const out = [];
  let line = '';
  for (const w of String(text).split(/\s+/)) {
    if (!line) line = w;
    else if ((line + ' ' + w).length <= n) line += ' ' + w;
    else { out.push(line); line = w; }
  }
  if (line) out.push(line);
  if (out.length > max) { out.length = max; out[max - 1] = out[max - 1].replace(/.{0,1}$/, '…'); }
  return out.map((l) => (l.length > n + 4 ? l.slice(0, n + 3) + '…' : l));
}

/** Las capas del diagrama, de izquierda a derecha. */
function layers(d) {
  const ins = new Map(d.cajas.map((c) => [c.id, []]));
  for (const [a, b] of d.flechas) ins.get(b).push(a);
  // capas: Kahn con desempate para romper ciclos; la capa de cada caja es una más que la de su predecesor más lejano
  const layer = new Map(), done = new Set(), order = [];
  const pending = new Set(d.cajas.map((c) => c.id));
  while (pending.size) {
    let next = [...pending].find((v) => ins.get(v).every((u) => done.has(u)));
    if (!next) next = [...pending].sort((a, b) => ins.get(a).filter((u) => !done.has(u)).length - ins.get(b).filter((u) => !done.has(u)).length)[0];
    layer.set(next, Math.max(0, ...ins.get(next).filter((u) => done.has(u)).map((u) => layer.get(u) + 1)));
    done.add(next); pending.delete(next); order.push(next);
  }
  return { layer, order, cols: Math.max(...layer.values()) + 1 };
}

/** Columnas que ocupa un diagrama: el antes y el después se dibujan al mismo ancho, para que el texto salga igual. */
export const diagramCols = (d) => (d?.cajas?.length ? layers(d).cols : 0);

let uid = 0;
/**
 * Un diagrama pequeño de cajas y flechas, de izquierda a derecha, en SVG. Las capas salen del camino más
 * largo desde las cajas sin entradas; si hay un ciclo (dos módulos enredados), la flecha de vuelta va
 * por debajo y discontinua. `minCols` ensancha el lienzo (centrando el dibujo) para igualar la escala con otro.
 */
export function diagram(d, label, minCols = 0) {
  if (!d?.cajas?.length) return '<p class="sub">Sin diagrama.</p>';
  const id = `ad${++uid}`;
  const BW = 150, GX = 36, PAD = 10, LH = 15, GY = 14;
  const { layer, order, cols } = layers(d);
  const span = Math.max(cols, minCols);
  const offX = ((span - cols) * (BW + GX)) / 2;
  const box = new Map();
  const colsH = [];
  for (let c = 0; c < cols; c++) {
    let y = 0;
    for (const v of order.filter((x) => layer.get(x) === c)) {
      const caja = d.cajas.find((x) => x.id === v);
      const icon = caja.marca === 'problema' ? '▲ ' : caja.marca === 'nuevo' ? '+ ' : '';
      const lines = wrap(icon + caja.texto);
      const h = 14 + lines.length * LH;
      box.set(v, { ...caja, lines, x: PAD + offX + c * (BW + GX), y, h });
      y += h + GY;
    }
    colsH.push(y - GY);
  }
  const H = Math.max(...colsH);
  // cada columna, centrada en vertical
  for (let c = 0; c < cols; c++) { const off = (H - colsH[c]) / 2; for (const b of box.values()) if (layer.get(b.id) === c) b.y += off + PAD; }
  const W = PAD * 2 + span * BW + (span - 1) * GX;
  const back = d.flechas.some(([a, b]) => layer.get(a) >= layer.get(b));
  const HH = H + PAD * 2 + (back ? 26 : 0);
  const edges = d.flechas.map(([a, b]) => {
    const A = box.get(a), B = box.get(b);
    if (layer.get(a) < layer.get(b)) {
      const x1 = A.x + BW, y1 = A.y + A.h / 2, x2 = B.x - 2, y2 = B.y + B.h / 2, mx = (x1 + x2) / 2;
      return `<path class="ae" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" marker-end="url(#${id}-p)"/>`;
    }
    // hacia atrás o en la misma columna: por debajo de las cajas
    const x1 = A.x + BW / 2, y1 = A.y + A.h, x2 = B.x + BW / 2, y2 = B.y + B.h + 2, low = H + PAD + 20;
    return `<path class="ae back" d="M${x1},${y1} C${x1},${low} ${x2},${low} ${x2},${y2}" marker-end="url(#${id}-p)"/>`;
  }).join('');
  const boxes = [...box.values()].map((b) => `<g class="ab ${b.marca}"><rect x="${b.x}" y="${b.y}" width="${BW}" height="${b.h}" rx="7"/>${b.lines.map((l, i) => `<text x="${b.x + 9}" y="${b.y + 19 + i * LH}">${esc(l)}</text>`).join('')}</g>`).join('');
  const aria = `${label}: ${d.cajas.map((c) => `${c.marca === 'problema' ? 'problema en ' : c.marca === 'nuevo' ? 'nuevo: ' : ''}${c.texto}`).join('; ')}`;
  return `<svg class="adg" viewBox="0 0 ${W} ${HH}" role="img" aria-label="${esc(aria)}"><defs><marker id="${id}-p" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="ah"/></marker></defs>${edges}${boxes}</svg>`;
}

// ---------------------------------------------------------------- informe

export const ARCH_CSS = `#arquitectura,#arquitectura-general,.arq{scroll-margin-top:64px}.arq{border-top:1px solid var(--grid);padding-top:16px;margin-top:16px}.arq:first-of-type{border-top:0;margin-top:6px;padding-top:4px}
.arq-top{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}.arq-top h3{margin:0;flex:1 1 320px}
.fz{display:inline-flex;gap:6px;align-items:center;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap;color:var(--ink);background:color-mix(in srgb,var(--acc) var(--fa),transparent)}
.fz span{color:var(--acc);letter-spacing:-1px}.fz.f1{--fa:22%}.fz.f2{--fa:13%}.fz.f3{--fa:6%}.fz.dec{background:var(--raise)}
.arq-d{margin:12px 0}.arq-d figure{margin:0;background:var(--raise);border-radius:12px;padding:10px 10px 6px}.arq-d figcaption{font-size:12.5px;color:var(--ink2);font-weight:600;margin-bottom:4px}
svg.adg{width:100%;height:auto;display:block;max-height:360px}.adg .ab rect{fill:var(--surface);stroke:var(--line);stroke-width:1.2}.adg .ab text{font-size:12.5px;fill:var(--ink)}
.arq-d.stack{grid-template-columns:1fr}.arq-d.stack svg.adg{max-height:220px}
@media (max-width:960px){.arq-d.grid2{grid-template-columns:1fr}}
.adg .ab.problema rect{fill:color-mix(in srgb,var(--crit) 14%,var(--surface));stroke:var(--crit);stroke-width:1.6}.adg .ab.nuevo rect{fill:color-mix(in srgb,var(--acc) 14%,var(--surface));stroke:var(--acc);stroke-width:1.6}
.adg .ab.externo rect{stroke-dasharray:4 3}.adg .ae{fill:none;stroke:var(--muted);stroke-width:1.4}.adg .ae.back{stroke-dasharray:4 3;stroke:var(--crit)}.adg .ah{fill:var(--muted)}
.alts{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;margin:10px 0}.alt{border:1px solid var(--ring);border-radius:12px;padding:12px 14px;font-size:13.5px}
.alt.rec{border:2px solid var(--acc)}.alt h4{margin:0 0 4px;font-size:14px}.alt .rec-b{font-size:12px;color:var(--acc);font-weight:600}.alt ul{margin:6px 0 0;padding-left:18px}.alt li{margin:2px 0}
.alt .pro::marker{content:"+ "}.alt .con::marker{content:"− "}.alt .ef{margin-top:8px;color:var(--ink2);font-size:12.5px}
.arq-start{background:color-mix(in srgb,var(--acc) 9%,transparent);border-radius:12px;padding:10px 14px;margin:4px 0 8px;font-size:14px}
.arq-key{display:flex;gap:14px;flex-wrap:wrap;font-size:12.5px;color:var(--ink2);margin-top:6px}`;

function card(p, n) {
  const fz = FUERZA[p.fuerza];
  const span = Math.max(diagramCols(p.antes), diagramCols(p.despues));
  const dec = p.decision ? `<span class="fz dec">${esc(DECISION[p.decision.estado])}${p.decision.adr ? ` · ${esc(p.decision.adr)}` : ''}</span>` : '';
  const alt = (a) => `<div class="alt${a.recomendada ? ' rec' : ''}">${a.recomendada ? '<div class="rec-b">✓ Recomendada</div>' : ''}<h4>${esc(a.nombre)}</h4><div>${esc(a.como)}</div>
<ul>${a.aFavor.map((x) => `<li class="pro">${esc(x)}</li>`).join('')}${a.enContra.map((x) => `<li class="con">${esc(x)}</li>`).join('')}</ul><div class="ef">Esfuerzo: <b>${esc(ESFUERZO[a.esfuerzo])}</b></div></div>`;
  return `<article class="arq" id="arq-${esc(p.id)}"><div class="arq-top"><h3>${n}. ${esc(p.titulo)}</h3><span class="fz ${fz.css}" title="Fuerza de la recomendación"><span aria-hidden="true">${fz.icon}</span> ${esc(fz.word)}</span>${dec}</div>
<p>${esc(p.problema)}</p>${p.quitaDeRaiz.length ? `<p class="sub">Quita de raíz: ${p.quitaDeRaiz.map((x) => `<span class="chip">${esc(x)}</span>`).join(' ')}</p>` : ''}
${p.antes || p.despues ? `<div class="grid2 arq-d${span > 3 ? ' stack' : ''}"><figure><figcaption>Ahora</figcaption>${diagram(p.antes, 'Ahora', span)}</figure><figure><figcaption>Con el cambio recomendado</figcaption>${diagram(p.despues, 'Con el cambio', span)}</figure></div>` : ''}
<div class="alts">${p.alternativas.map(alt).join('')}</div>
${p.porQue ? `<p><b>Por qué la recomendada:</b> ${esc(p.porQue)}</p>` : ''}${p.decision?.motivo ? `<p class="sub">Decisión del equipo: ${esc(p.decision.motivo)}</p>` : ''}
${p.primerPaso ? `<p class="sub">Primer paso, para pedírselo a Claude: <code>${esc(p.primerPaso)}</code></p>` : ''}
${p.ficheros.length ? `<details><summary>Ficheros (${p.ficheros.length})</summary><p class="w">${p.ficheros.map(esc).join('<br>')}</p></details>` : ''}</article>`;
}

/**
 * Una sección del informe por tipo: la de seguridad va junto a lo urgente y la de mantenibilidad al final,
 * para que quien evalúa la seguridad no tenga que separar una cosa de la otra.
 */
export function archSection(arch, tipo) {
  const KEY = '<div class="arq-key"><span>▲ caja roja: donde está el problema</span><span>+ caja azul: lo nuevo</span><span>flecha discontinua: dependencia de vuelta (enredo)</span></div>';
  const head = tipo === 'seguridad'
    ? ['Arquitectura · seguridad de raíz', 'Cambios de estructura que quitan de golpe muchos de los avisos de arriba, en vez de arreglarlos uno a uno. Cada uno trae 2 o 3 formas de hacerlo, comparadas. No cuenta para la nota.']
    : ['Arquitectura · mantenibilidad', 'No son fallos de seguridad: es lo que hace el código difícil de cambiar y de probar (módulos mal repartidos, enredos, zonas que cambian mucho sin pruebas). Cada uno trae 2 o 3 formas de hacerlo, comparadas. No cuenta para la nota.'];
  if (!arch?.hecho) return tipo === 'seguridad' ? `<section id="arquitectura"><h2>${head[0]}</h2><p class="lead">Sin propuestas: esta pasada no incluyó la revisión de arquitectura, que hace Claude (<code>/lupa</code> o <code>/lupa-arquitectura</code>).</p></section>` : '';
  const list = arch.propuestas.filter((p) => p.tipo === tipo);
  const start = arch.porDondeEmpezar && list.find((p) => p.id === arch.porDondeEmpezar.id);
  const body = list.length ? `${start ? `<div class="arq-start"><b>Por dónde empezar:</b> <a href="#arq-${esc(start.id)}">${esc(start.titulo)}</a>${arch.porDondeEmpezar.motivo ? `. ${esc(arch.porDondeEmpezar.motivo)}` : ''}</div>` : ''}${list.map((p, i) => card(p, i + 1)).join('')}${KEY}`
    : `<p>${tipo === 'seguridad' ? 'Ningún cambio de estructura merece la pena por seguridad: los avisos son puntuales y se arreglan uno a uno.' : 'Nada que merezca la pena cambiar de estructura.'}</p>`;
  return `<section id="${tipo === 'seguridad' ? 'arquitectura' : 'arquitectura-general'}"><h2>${head[0]} <span class="c">${list.length}</span></h2><p class="lead">${head[1]}${tipo === 'seguridad' && arch.resumen ? ` ${esc(arch.resumen)}` : ''}</p>${body}</section>`;
}

/** Lo que va al mapa y a los datos del informe: lo justo para listar y comparar. */
export const archSummary = (arch) => (arch ? {
  hecho: arch.hecho, resumen: arch.resumen, porDondeEmpezar: arch.porDondeEmpezar?.id || null,
  propuestas: arch.propuestas.map((p) => ({ id: p.id, tipo: p.tipo, titulo: p.titulo, fuerza: p.fuerza, recomendada: p.alternativas.find((a) => a.recomendada)?.nombre || '', ficheros: p.ficheros, decision: p.decision?.estado || null })),
} : null);
