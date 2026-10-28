// Datos públicos que Lupa cruza con lo que encuentra, guardados en caché un día:
// - endoflife.date: qué versiones de cada tecnología siguen con soporte.
// - CISA KEV: los CVE que se están explotando de verdad ahora mismo.
// - FIRST EPSS: la probabilidad de que un CVE se explote en los próximos 30 días.
// Solo se envían nombres de producto y números de CVE; nunca código.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CACHE = path.join(os.homedir(), '.cache', 'lupa');
const DAY = 24 * 3600 * 1000;

async function cached(name, url, { ttl = DAY, log = () => {} } = {}) {
  const file = path.join(CACHE, name);
  let st = null; try { st = fs.statSync(file); } catch {}
  if (st && Date.now() - st.mtimeMs < ttl) return JSON.parse(fs.readFileSync(file, 'utf8'));
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(60_000), headers: { 'user-agent': 'lupa-security-audit' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    fs.mkdirSync(CACHE, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(data));
    return data;
  } catch (e) {
    if (st) { log(`${name}: sin conexión (${e.message}); uso la copia del ${new Date(st.mtimeMs).toLocaleDateString('es-ES')}`); return JSON.parse(fs.readFileSync(file, 'utf8')); }
    log(`${name}: no se pudo descargar (${e.message}); esa parte se queda sin mirar`);
    return null;
  }
}

// ---------------------------------------------------------------- endoflife.date
/** purl sin versión ni calificadores, en minúsculas: «pkg:npm/@angular/core» → «npm/@angular/core». */
export function purlKey(purl) {
  const m = /^pkg:([^/]+)\/(.+?)(?:@[^?#]*)?(?:[?#].*)?$/.exec(String(purl || ''));
  if (!m) return null;
  return `${m[1]}/${decodeURIComponent(m[2])}`.toLowerCase();
}

export async function loadEol(log) {
  const data = await cached('endoflife.json', 'https://endoflife.date/api/v1/products/full', { log });
  if (!data?.result) return null;
  const byPurl = new Map(), byName = new Map();
  for (const p of data.result) {
    byName.set(p.name, p);
    for (const id of p.identifiers || []) if (id.type === 'purl') { const k = purlKey(id.id); if (k && !byPurl.has(k)) byPurl.set(k, p); }
  }
  return { byPurl, byName };
}

/** «^4.17.1», «>=3.8», «14-alpine», «v1.2» → «4.17.1», «3.8», «14», «1.2». */
export function cleanVersion(v) {
  const m = /(\d+(?:\.\d+){0,3})/.exec(String(v || ''));
  return m ? m[1] : null;
}

/** El ciclo de vida de esa versión: la rama de endoflife.date cuyo nombre es el prefijo más largo. */
export function eolStatus(product, version, now = Date.now()) {
  const v = cleanVersion(version);
  if (!product || !v) return null;
  const rels = product.releases || [];
  let rel = null;
  for (const r of rels) {
    const n = String(r.name);
    if ((v === n || v.startsWith(n + '.')) && (!rel || n.length > String(rel.name).length)) rel = r;
  }
  if (!rel) {
    // más vieja que la rama más antigua del catálogo (Django 1.2, Node 0.10…): lleva años sin soporte
    const num = (s) => String(s).split('.').map((x) => parseInt(x, 10) || 0);
    const older = (a, b) => { const x = num(a), y = num(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0); } return false; };
    const oldest = rels.map((r) => r.name).filter((n) => /^\d/.test(n)).sort((a, b) => (older(a, b) ? -1 : 1))[0];
    const estado = oldest && older(v, oldest) ? 'sin-soporte' : 'desconocido';
    return { producto: product.name, etiqueta: product.label, categoria: product.category, version: v, estado, finSoporte: null, ultima: rels[0]?.latest?.name || rels[0]?.name || null, nota: estado === 'sin-soporte' ? 'más antigua que cualquier versión con datos' : '' };
  }
  const eol = rel.eolFrom ? Date.parse(rel.eolFrom) : null;
  const newestMajor = parseInt(String(rels[0]?.name), 10), thisMajor = parseInt(String(rel.name), 10);
  let estado = 'al-dia';
  if (rel.isEol || (eol && eol <= now)) estado = 'sin-soporte';
  else if (eol && eol - now < 180 * DAY) estado = 'caduca-pronto';
  else if (rel.isMaintained === false) estado = 'sin-mantenimiento';
  // una rama con soporte largo (LTS) en vigor no está «desactualizada» aunque haya otras más nuevas
  else if (!rel.isLts && Number.isFinite(newestMajor) && Number.isFinite(thisMajor) && newestMajor - thisMajor >= 3) estado = 'desactualizado';
  return {
    producto: product.name, etiqueta: product.label, categoria: product.category, version: v, rama: rel.name,
    estado, finSoporte: rel.eolFrom || null, ultimaDeSuRama: rel.latest?.name || null, ultima: rels[0]?.latest?.name || rels[0]?.name || null,
  };
}

// ---------------------------------------------------------------- KEV y EPSS
export async function loadKev(log) {
  const data = await cached('kev.json', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { log });
  if (!data?.vulnerabilities) return null;
  return new Map(data.vulnerabilities.map((v) => [v.cveID, { desde: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known', producto: `${v.vendorProject} ${v.product}`, accion: v.requiredAction, plazo: v.dueDate }]));
}

/** EPSS de una lista de CVE, en tandas de 100 (lo que admite la API). */
export async function loadEpss(cves, log) {
  const out = new Map();
  const list = [...new Set(cves.filter((c) => /^CVE-\d{4}-\d+$/.test(c)))];
  const cacheFile = path.join(CACHE, 'epss.json');
  let cache = {}; try { const c = JSON.parse(fs.readFileSync(cacheFile, 'utf8')); if (Date.now() - c.at < DAY) cache = c.data; } catch {}
  const missing = list.filter((c) => !(c in cache));
  for (let i = 0; i < missing.length; i += 100) {
    const batch = missing.slice(i, i + 100);
    try {
      const r = await fetch(`https://api.first.org/data/v1/epss?cve=${batch.join(',')}`, { signal: AbortSignal.timeout(60_000) });
      const j = await r.json();
      for (const c of batch) cache[c] = null;
      for (const d of j.data || []) cache[d.cve] = { epss: +d.epss, percentil: +d.percentile };
    } catch (e) { log(`EPSS: no se pudo consultar (${e.message})`); break; }
  }
  try { fs.mkdirSync(CACHE, { recursive: true }); fs.writeFileSync(cacheFile, JSON.stringify({ at: Date.now(), data: cache })); } catch {}
  for (const c of list) if (cache[c]) out.set(c, cache[c]);
  return out;
}
