// La revisión de la IA: prepara las hojas de trabajo (qué mirar y con qué código delante),
// recuerda lo ya revisado entre pasadas y lee las respuestas.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { readJSON, writeJSON, snippet } from './util.mjs';

export const endpointKey = (e) => `${e.method} ${e.path} @ ${e.file}`;
/** La respuesta de la IA para un endpoint, si sigue valiendo: hecha sobre el mismo código (misma huella). */
export const reviewOf = (answers, e) => { const a = answers.endpoints.get(endpointKey(e)); return a && (!a.huella || !e.huella || a.huella === e.huella) ? a : null; };
const LOTE_ENDPOINTS = 25;
const LOTE_HALLAZGOS = 40;

/** Todas las respuestas que ya hay en revision/lote-*.json, por endpoint y por hallazgo. */
export function loadAnswers(dir) {
  const endpoints = new Map(), findings = new Map(), extra = [];
  let files = [];
  try { files = fs.readdirSync(dir).filter((n) => /^lote-\d+\.json$/.test(n)); } catch {}
  for (const n of files) {
    const j = readJSON(path.join(dir, n), {});
    for (const e of j.endpoints || []) if (e.severidad) endpoints.set(e.clave, e);
    for (const h of j.hallazgos || []) if (h.veredicto) findings.set(h.id, h);
    for (const x of j.extra || []) if (x && x.titulo) extra.push(x);
  }
  return { endpoints, findings, extra };
}

/** La misma regla en el mismo fichero se criba una sola vez: la respuesta vale para todas sus líneas. */
export const triageKey = (f) => (f.tool === 'floorplan' ? f.id : 't:' + crypto.createHash('sha1').update(`${f.tool}|${f.rule}|${f.file}`).digest('hex').slice(0, 10));

function triageGroups(findings) {
  const groups = new Map();
  for (const f of findings) {
    const k = triageKey(f);
    if (!groups.has(k)) groups.set(k, { ...f, id: k, lines: [] });
    groups.get(k).lines.push(f.line);
  }
  return [...groups.values()];
}

/** Qué hallazgos merece la pena que la IA mire: los que suelen dar falsos positivos. */
export function needsTriage(f) {
  if (f.cat === 'dependencias') return false; // un CVE es un CVE
  if (/^lupa-(servidor|red|externo|aws)$/.test(f.tool)) return false; // medido en el servidor, desde internet o en la nube: es un hecho
  if (f.tool === 'lupa-plataforma') return f.rule === 'plataforma.posible-secreto-en-log'; // de la plataforma, solo lo dudoso
  if (f.cat === 'infra' && f.tool === 'trivy') return f.severity === 'high';
  return f.severity !== 'low';
}

/**
 * Escribe revision/lote-NN.md (lo que hay que mirar) y lote-NN.json (dónde contestar),
 * solo con lo que aún no tiene respuesta. Devuelve cuántos lotes y cuánto queda pendiente.
 */
export function writeWorksheets({ root, dir, endpoints, findings }) {
  fs.mkdirSync(dir, { recursive: true });
  const prev = loadAnswers(dir);
  for (const n of fs.readdirSync(dir)) if (/^lote-\d+\.(md|json)$/.test(n)) fs.rmSync(path.join(dir, n));
  // una respuesta vale mientras el código del endpoint no cambie (misma huella); las antiguas sin huella adoptan la de hoy
  const still = (e) => { const a = prev.endpoints.get(endpointKey(e)); return !!a && (!a.huella || !e.huella || a.huella === e.huella); };
  const changed = new Set(endpoints.filter((e) => prev.endpoints.has(endpointKey(e)) && !still(e)).map(endpointKey));
  // lo ya contestado se guarda en un lote 00, para que no se pierda al regenerar
  const keptE = endpoints.filter(still).map((e) => ({ ...prev.endpoints.get(endpointKey(e)), huella: e.huella || prev.endpoints.get(endpointKey(e)).huella }));
  const groups = triageGroups(findings.filter(needsTriage));
  const keptF = groups.filter((f) => prev.findings.has(f.id)).map((f) => prev.findings.get(f.id));
  if (keptE.length || keptF.length || prev.extra.length) writeJSON(path.join(dir, 'lote-00.json'), { revisado: true, endpoints: keptE, hallazgos: keptF, extra: prev.extra });

  const secretLines = new Map();
  for (const f of findings) if (f.cat === 'secretos') { if (!secretLines.has(f.file)) secretLines.set(f.file, new Set()); secretLines.get(f.file).add(f.line); }
  const hideIn = (file) => secretLines.get(file) || new Set();
  const pendE = endpoints.filter((e) => !still(e));
  const pendF = groups.filter((f) => !prev.findings.has(f.id));
  const lotes = [];
  for (let i = 0; i < pendE.length; i += LOTE_ENDPOINTS) lotes.push({ endpoints: pendE.slice(i, i + LOTE_ENDPOINTS), hallazgos: [] });
  for (let i = 0; i < pendF.length; i += LOTE_HALLAZGOS) lotes.push({ endpoints: [], hallazgos: pendF.slice(i, i + LOTE_HALLAZGOS) });

  lotes.forEach((lote, i) => {
    const num = String(i + 1).padStart(2, '0');
    const md = [`# Lupa · lote ${num}`, '', `Rellena \`lote-${num}.json\` (mismas claves, mismo orden). Lee primero la sección «Revisión» del SKILL de Lupa.`, ''];
    if (lote.endpoints.length) md.push('## Endpoints', '');
    for (const e of lote.endpoints) {
      md.push(`### ${e.method} ${e.realPath || e.path}`, `- clave: \`${endpointKey(e)}\``, `- fichero: ${e.file}:${e.line} · framework: ${e.framework || 'detectado por floorplan'}`,
        ...(e.otherPaths?.length ? [`- también montado en: ${e.otherPaths.slice(0, 8).join(', ')}${e.otherPaths.length > 8 ? ` y ${e.otherPaths.length - 8} más` : ''}`] : []),
        `- pistas: ${[
          changed.has(endpointKey(e)) ? '⚠ el código cambió desde la última revisión' : '',
          e.floorplanOpen ? 'floorplan no ve login' : e.floorplanOpen === false ? 'floorplan ve login' : '',
          e.authHint ? 'hay algo que parece un login cerca' : '', e.sensitive ? 'la ruta tiene nombre delicado' : '',
          e.parametroId ? 'lleva un identificador en la ruta: comprueba que solo da lo del propio usuario' : '',
          e.datosPersonales ? 'toca campos de datos personales del mapa de datos' : '',
          e.usaIA ? 'llama a un modelo de IA: aplica la lista de IA' : '',
        ].filter(Boolean).join(' · ') || 'ninguna'}`,
        '', '```', snippet(path.join(root, e.file), e.line, 3, 30, hideIn(e.file)), '```', '');
    }
    if (lote.hallazgos.length) md.push('## Hallazgos para cribar', '');
    for (const f of lote.hallazgos) {
      const lines = [...new Set(f.lines || [f.line])].sort((a, b) => a - b);
      md.push(`### ${f.id} · ${f.title}`, `- herramienta: ${f.tool} · regla: ${f.rule} · severidad: ${f.severity} · ${f.file}, línea${lines.length > 1 ? 's' : ''} ${lines.slice(0, 12).join(', ')}${lines.length > 12 ? '…' : ''}`, `- detalle: ${String(f.detail).slice(0, 400)}`);
      // los secretos no se copian aquí: si hace falta, se abre el fichero
      if (f.cat !== 'secretos') md.push('', '```', snippet(path.join(root, f.file), f.line, 4, 8, hideIn(f.file)), '```');
      md.push('');
    }
    fs.writeFileSync(path.join(dir, `lote-${num}.md`), md.join('\n'));
    writeJSON(path.join(dir, `lote-${num}.json`), {
      endpoints: lote.endpoints.map((e) => ({ clave: endpointKey(e), huella: e.huella || '', publico: null, deberiaSerPublico: null, datos: [], severidad: '', titulo: '', motivo: '', arreglo: '' })),
      hallazgos: lote.hallazgos.map((f) => ({ id: f.id, veredicto: '', severidad: '', motivo: '' })),
      extra: [],
    });
  });
  return { lotes: lotes.length, pendientesEndpoints: pendE.length, pendientesHallazgos: pendF.length, yaRevisados: keptE.length + keptF.length };
}
