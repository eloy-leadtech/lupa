// Convierte los hallazgos en "issues" con el formato del Health de floorplan, para que
// salgan en su lista, con «Ver en el mapa» y «Arreglar con Claude», y los coloca en el mapa.
import crypto from 'node:crypto';
import path from 'node:path';
import { worst, SEV_RANK, plural } from './util.mjs';

export const CATS = {
  endpoints: 'Endpoints',
  secretos: 'Secretos',
  exposicion: 'Configuración expuesta',
  datos: 'Datos y ficheros delicados',
  codigo: 'Fallos de código',
  infra: 'Servidores y despliegue',
  dependencias: 'Librerías con fallos',
  tecnologia: 'Tecnología obsoleta',
  ia: 'Inteligencia artificial',
};

export const findingId = (f) => crypto.createHash('sha1').update(`${f.tool}|${f.rule}|${f.file}|${f.line}|${f.pkg || ''}`).digest('hex').slice(0, 10);

/** Id del nodo donde Lupa cuelga lo que floorplan no dibuja (Jenkinsfile, claves, copias de BD…). */
export const OUTSIDE_NODE = 'lupa-fuera';

/**
 * Coloca cada fichero en el mapa. Si floorplan lo tiene, es su tarjeta; si no, lo apunta para
 * colgarlo del nodo «Fuera del mapa», que merge.mjs añade al grafo.
 */
export function makeMapper(graph) {
  const files = new Set((graph.files || []).map((f) => f.p));
  const outside = new Set();
  const routes = graph.routes || [];
  return {
    outside,
    item(file) {
      if (!file) return null;
      if (files.has(file)) return 'f:' + file;
      outside.add(file);
      return 'f:' + file;
    },
    route(file, line, method, p) {
      const i = routes.findIndex((r) => r.f === file && (r.l === line || (r.p === p && (!method || r.m === method))));
      return i >= 0 ? 'r:' + i : null;
    },
  };
}

const lineNote = (f) => `línea ${f.line}: ${f.title}`;

/** Agrupa por categoría y fichero, para no inundar la lista con cien avisos del mismo sitio. */
export function toIssues(findings, mapper) {
  const groups = new Map();
  for (const f of findings) {
    // la tecnología va una pieza por aviso: en un docker-compose, nginx y mongo son dos problemas distintos
    const key = `${f.cat}|${f.ref || f.file}${f.cat === 'tecnologia' && f.componente ? '|' + f.componente : ''}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const issues = [];
  for (const [key, list] of groups) {
    list.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.line - b.line);
    const f0 = list[0];
    const cat = f0.cat;
    const item = f0.ref || mapper.item(f0.file);
    const base = path.posix.basename(f0.file || '');
    const one = list.length === 1;
    const notes = item ? { [item]: list.slice(0, 6).map(lineNote).join(' · ') + (list.length > 6 ? ` · y ${list.length - 6} más` : '') } : {};
    issues.push({
      id: 'lupa:' + key,
      kind: 'lupa-' + cat,
      severity: worst(list.map((x) => x.severity)),
      title: one ? f0.title : `${CATS[cat] || cat}: ${plural(list.length, 'problema')} en ${base}`,
      detail: one ? f0.detail : list.slice(0, 8).map((x) => `• ${lineNote(x)}`).join('\n') + (list.length > 8 ? `\n• y ${list.length - 8} más` : ''),
      items: item ? [item] : [],
      notes,
      locations: list.slice(0, 50).map((x) => ({ file: x.file, line: x.line })).filter((l) => l.file),
      fix: one ? f0.fix : [
        `Arreglo de seguridad en ${f0.file}: hay ${list.length} avisos de «${CATS[cat] || cat}». No escribas ningún secreto en tus respuestas.`,
        ...list.slice(0, 25).map((x) => `- línea ${x.line} (${x.rule}): ${x.title}`),
        '',
        'Revisa cada uno en su contexto. Arregla los reales con el cambio mínimo, dime cuáles descartas y por qué, y explícame en pocas frases qué riesgo quitaba cada arreglo.',
      ].join('\n'),
      lupa: { cat, tools: [...new Set(list.map((x) => x.tool))], count: list.length, ids: list.map((x) => x.id) },
    });
  }
  return issues.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
}

/**
 * Un titular que diga el problema: la primera frase que habla de lo que falla («pero no comprueba…»,
 * «falta…», «cualquiera puede…»), sin el conector delante; si no hay, la primera. Recortado.
 */
function firstSentence(s) {
  const all = String(s || '').trim().split(/(?<=[.!?])\s+/);
  const BAD = /\b(pero|falta|faltan|no hay|no tiene|no comprueba|no limita|no valida|no pide|sin\s|se puede|se salta|cualquiera|permite|expone|deja|delata|filtra|suelta)\b/i;
  let t = (all.find((x) => BAD.test(x)) || all[0] || '').replace(/[.:;]$/, '');
  // «Lo básico está bien, pero falta X» → «Falta X»
  const cut = /(?:^|[,;:]\s*)(?:pero|lo que falta es|lo que falla es|el problema es que)\s+(.*)$/i.exec(t);
  if (cut) t = cut[1];
  t = t.charAt(0).toUpperCase() + t.slice(1);
  return t.length > 150 ? t.slice(0, 147).replace(/\s+\S*$/, '') + '…' : t;
}

/** Lo que dijo la IA de cada endpoint, convertido en hallazgos de la categoría «endpoints». */
export function endpointFindings(endpoints) {
  const out = [];
  for (let e of endpoints) {
    const v = e.revision;
    if (!v || !['alta', 'media', 'baja'].includes(v.severidad)) continue;
    const sev = { alta: 'high', media: 'medium', baja: 'low' }[v.severidad];
    const datos = (v.datos || []).filter(Boolean);
    e = { ...e, path: e.shown || e.realPath || e.path };
    const who = v.publico === false ? 'con login' : 'público';
    out.push({
      tool: 'ia', cat: 'endpoints', rule: 'revision-endpoint', severity: sev, file: e.file, line: e.line, ref: e.ref,
      // el titular sale de lo que dijo la IA: «datos» es lo que el endpoint toca, no siempre lo que filtra
      title: v.deberiaSerPublico === false && v.publico !== false
        ? `«${e.method} ${e.path}» está abierto a cualquiera y no debería`
        : `«${e.method} ${e.path}»: ${(v.titulo || '').trim() || firstSentence(v.motivo) || (who === 'público' ? 'público, con un problema de acceso' : 'tiene un problema de acceso')}`,
      detail: `${v.motivo || ''}${datos.length ? ` Datos expuestos: ${datos.join(', ')}.` : ''}`.trim(),
      fix: v.arreglo || `Revisa el control de acceso de ${e.method} ${e.path} en ${e.file}:${e.line}.`,
    });
  }
  return out;
}
