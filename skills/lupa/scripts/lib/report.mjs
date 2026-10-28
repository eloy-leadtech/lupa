// El informe de Lupa: un solo fichero HTML, sin nada externo, que un dev genera y le manda a quien
// tenga que evaluarlo. Lleva la nota, la foto de dónde se pierde la seguridad, lo urgente, la
// superficie de ataque, los CVE explotados (KEV), la tecnología con su ciclo de vida y el mapa de
// datos personales. Se lee igual en claro y en oscuro, y se imprime a PDF desde el navegador.

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV = {
  high: { word: 'Grave', css: 'crit', icon: '▲' },
  medium: { word: 'A mirar', css: 'serious', icon: '◆' },
  low: { word: 'Menor', css: 'warn', icon: '●' },
};
const STATE = {
  'sin-soporte': { word: 'Sin soporte', css: 'crit', icon: '▲' },
  'caduca-pronto': { word: 'Caduca pronto', css: 'serious', icon: '◆' },
  'sin-mantenimiento': { word: 'Sin mantenimiento', css: 'serious', icon: '◆' },
  desactualizado: { word: 'Desactualizado', css: 'warn', icon: '●' },
  'al-dia': { word: 'Con soporte', css: 'good', icon: '✓' },
  desconocido: { word: 'Sin datos', css: 'muted', icon: '·' },
};
const RANK = { alta: 0, media: 1, baja: 2 };
const pill = (s) => `<span class="pill ${s.css}"><span aria-hidden="true">${s.icon}</span> ${esc(s.word)}</span>`;
const fmt = (n) => Number(n || 0).toLocaleString('es-ES');

/** Squarified treemap (Bruls et al.): rectángulos lo más cuadrados posible. */
function squarify(items, x, y, w, h) {
  const total = items.reduce((a, b) => a + b.value, 0) || 1;
  const scaled = items.map((it) => ({ ...it, area: (it.value / total) * w * h })).sort((a, b) => b.area - a.area);
  const out = [];
  let row = [], rx = x, ry = y, rw = w, rh = h;
  const worstRatio = (r, side) => { const s = r.reduce((a, b) => a + b.area, 0); const mx = Math.max(...r.map((i) => i.area)), mn = Math.min(...r.map((i) => i.area)); return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn)); };
  const layout = (r) => {
    const s = r.reduce((a, b) => a + b.area, 0);
    if (rw >= rh) { const cw = s / rh; let cy = ry; for (const i of r) { const ch = i.area / cw; out.push({ ...i, x: rx, y: cy, w: cw, h: ch }); cy += ch; } rx += cw; rw -= cw; }
    else { const ch = s / rw; let cx = rx; for (const i of r) { const cw = i.area / ch; out.push({ ...i, x: cx, y: ry, w: cw, h: ch }); cx += cw; } ry += ch; rh -= ch; }
  };
  for (const it of scaled) {
    const side = Math.min(rw, rh);
    if (!row.length || worstRatio([...row, it], side) <= worstRatio(row, side)) row.push(it);
    else { layout(row); row = [it]; }
  }
  if (row.length) layout(row);
  return out;
}

/** Nota de 0 a 100 y su letra. La fórmula va escrita en el propio informe. */
export function score({ kevExpuestas, kevOtras, endpointsGraves, graves, aMirar, sinSoporte }) {
  const quita = [
    ['CVE explotadas (KEV) en apps expuestas', Math.min(36, 12 * kevExpuestas)],
    ['Otras CVE explotadas (KEV)', Math.min(18, 6 * kevOtras)],
    ['Endpoints graves abiertos que no deberían', Math.min(24, 4 * endpointsGraves)],
    ['Otros avisos graves', Math.min(30, 2 * graves)],
    ['Avisos a mirar', Math.min(15, Math.round(aMirar / 2))],
    ['Runtimes, frameworks y bases de datos sin soporte', Math.min(15, 3 * sinSoporte)],
  ];
  const n = Math.max(0, 100 - quita.reduce((a, [, v]) => a + v, 0));
  const letra = n >= 90 ? 'A' : n >= 75 ? 'B' : n >= 60 ? 'C' : n >= 45 ? 'D' : n >= 30 ? 'E' : 'F';
  return { n, letra, quita };
}

export function buildReport({ graph, tech, datos, generado = new Date() }) {
  const L = graph.lupa || {};
  const issues = graph.health?.issues || [];
  const lupaIssues = issues.filter((i) => String(i.id).startsWith('lupa:'));
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const fileNode = new Map(graph.files.map((f) => [f.p, f.n]));
  const repos = (graph.meta?.repos || []).filter((r) => r.path);
  const repoOf = (file) => repos.filter((r) => r.path === '.' || file.startsWith(r.path + '/')).sort((a, b) => b.path.length - a.path.length)[0];
  const appName = (file) => { const r = repoOf(file || ''); return r ? (r.path === '.' ? r.name : r.path) : '—'; };

  // ---------------------------------------------------------------- exposición y KEV
  const E = L.endpoints || [];
  const exposedApps = new Set(E.filter((e) => e.publico === true).map((e) => appName(e.fichero)));
  const depIssues = lupaIssues.filter((i) => i.lupa?.cat === 'dependencias');
  const kevRows = [];
  for (const f of (L.kev || [])) kevRows.push({ ...f, app: appName(f.fichero), expuesta: exposedApps.has(appName(f.fichero)) });
  kevRows.sort((a, b) => (+b.expuesta - +a.expuesta) || (b.epss || 0) - (a.epss || 0));
  const shouldNot = E.filter((e) => e.deberiaSerPublico === false && e.publico !== false);
  const graveEndpoints = shouldNot.filter((e) => e.severidad === 'alta');
  const comps = tech?.componentes || [];
  const eolUnique = new Map();
  for (const c of comps) if (c.eol?.estado === 'sin-soporte' && c.tipo !== 'libreria') eolUnique.set(`${c.eol.producto}@${c.eol.rama}`, c);
  const count = (s, list = issues) => list.filter((i) => i.severity === s).length;
  const sc = score({
    kevExpuestas: kevRows.filter((k) => k.expuesta).length, kevOtras: kevRows.filter((k) => !k.expuesta).length,
    endpointsGraves: graveEndpoints.length, graves: Math.max(0, count('high') - graveEndpoints.length - kevRows.length), aMirar: count('medium'), sinSoporte: eolUnique.size,
  });
  const specialModels = (datos?.ficheros || []).filter((d) => d.especial || d.tipos.some((t) => ['pasaporte', 'documento de identidad', 'datos de pago'].includes(t)));

  // ---------------------------------------------------------------- calor por módulo
  const ownerChain = (item) => {
    let n = null;
    if (item.startsWith('f:')) n = fileNode.get(item.slice(2));
    else if (item.startsWith('r:')) n = fileNode.get(graph.routes[+item.slice(2)]?.f);
    else if (item.startsWith('n:')) n = item.slice(2);
    const out = []; while (n && nodes.has(n)) { out.push(n); n = nodes.get(n).parent; }
    return out;
  };
  const heat = new Map(), heatOwn = new Map(); // con lo de dentro / solo lo del propio nodo
  const bump = (m, n, s) => { const h = m.get(n) || { high: 0, medium: 0, low: 0 }; h[s]++; m.set(n, h); };
  for (const i of issues) for (const it of i.items || []) {
    const chain = ownerChain(it);
    for (const n of new Set(chain)) bump(heat, n, i.severity);
    if (chain[0]) bump(heatOwn, chain[0], i.severity);
  }
  const tops = graph.nodes.filter((n) => !n.parent && n.kind !== 'external');
  const W = 960, H = 460, HEAD = 22;
  const topRects = squarify(tops.map((n) => ({ id: n.id, value: Math.max(1, n.stats?.files || 1) })), 0, 0, W, H);
  const cells = [];
  for (const t of topRects) {
    const kids = graph.nodes.filter((n) => n.parent === t.id && n.kind !== 'external');
    // el código que cuelga directamente del nodo (no de sus partes) también es un bloque: «… · resto»
    const ownFiles = Math.max(0, (nodes.get(t.id).stats?.files || 0) - kids.reduce((a, k) => a + (k.stats?.files || 0), 0));
    const parts = [...kids.map((n) => ({ id: n.id, value: Math.max(1, n.stats?.files || 1) })), ...(kids.length && (ownFiles || heatOwn.get(t.id)) ? [{ id: t.id, own: true, value: Math.max(1, ownFiles) }] : [])];
    const inner = kids.length ? squarify(parts, t.x + 2, t.y + HEAD, Math.max(1, t.w - 4), Math.max(1, t.h - HEAD - 2)) : [{ id: t.id, x: t.x + 2, y: t.y + HEAD, w: t.w - 4, h: t.h - HEAD - 2 }];
    cells.push({ top: true, ...t });
    for (const c of inner) cells.push(c);
  }
  const sevOf = (h) => (!h ? 'good' : h.high ? 'crit' : h.medium ? 'serious' : h.low ? 'warn' : 'good');
  const label = (id) => (id === 'unassigned' ? 'Sin asignar' : nodes.get(id)?.label === 'Unassigned' ? 'Sin asignar' : nodes.get(id)?.label || id);
  const svgCells = cells.map((c) => {
    const h = c.own ? heatOwn.get(c.id) : heat.get(c.id);
    const name = c.own ? `${label(c.id)} · resto` : label(c.id);
    if (c.top) return `<g><rect class="tm-top" x="${c.x + 1}" y="${c.y + 1}" width="${Math.max(0, c.w - 2)}" height="${Math.max(0, c.h - 2)}" rx="6"/><text class="tm-h" x="${c.x + 8}" y="${c.y + 15}">${esc(label(c.id)).slice(0, Math.floor(c.w / 7))}</text></g>`;
    const s = sevOf(h);
    const t = h ? `${h.high} graves · ${h.medium} a mirar · ${h.low} menores` : 'sin avisos';
    const fits = c.w > 70 && c.h > 34;
    return `<g class="tm-cell" data-tip="${esc(name)}: ${esc(t)}"><rect class="tm ${s}" x="${c.x + 1}" y="${c.y + 1}" width="${Math.max(0, c.w - 2)}" height="${Math.max(0, c.h - 2)}" rx="4"/>${fits ? `<text class="tm-l" x="${c.x + 8}" y="${c.y + 18}">${esc(name).slice(0, Math.floor(c.w / 7))}</text><text class="tm-v" x="${c.x + 8}" y="${c.y + 33}">${h ? `${SEV[h.high ? 'high' : h.medium ? 'medium' : 'low'].icon} ${h.high ? `${h.high} graves` : h.medium ? `${h.medium} a mirar` : `${h.low} menores`}` : '✓ sin avisos'}</text>` : ''}</g>`;
  }).join('');
  const heatRows = [...heat.entries()].filter(([id]) => nodes.get(id)?.parent || tops.length === 1).sort((a, b) => b[1].high - a[1].high || b[1].medium - a[1].medium).slice(0, 25);

  // ---------------------------------------------------------------- barras por tipo
  const cats = Object.entries(L.nombres || {}).filter(([c]) => L.categorias?.[c]);
  const maxCat = Math.max(1, ...cats.map(([c]) => { const k = L.categorias[c]; return k.high + k.medium + k.low; }));
  const bars = cats.map(([c, name]) => {
    const k = L.categorias[c]; const tot = k.high + k.medium + k.low;
    const seg = ['high', 'medium', 'low'].filter((s) => k[s]).map((s) => `<span class="seg ${SEV[s].css}" style="flex:${k[s]}" data-tip="${esc(name)}: ${k[s]} ${SEV[s].word.toLowerCase()}${k[s] === 1 ? '' : 's'}"></span>`).join('');
    return `<div class="bar-row"><div class="bar-l">${esc(name)}</div><div class="bar-t"><div class="bar" style="width:${(tot / maxCat) * 100}%">${seg}</div><span class="bar-v">${fmt(tot)}</span></div></div>`;
  }).join('');

  // ---------------------------------------------------------------- lo urgente
  const urgent = [
    ...kevRows.filter((k) => k.expuesta).map((k) => ({ sev: 'high', t: `${k.paquete} ${k.version}: ${k.cves.join(', ')} se está explotando (KEV) y la app está expuesta`, w: `${k.fichero}`, a: k.app })),
    ...graveEndpoints.map((e) => ({ sev: 'high', t: `${e.metodo} ${e.ruta}: abierto a cualquiera y no debería${e.datos?.length ? ` (suelta ${e.datos.slice(0, 3).join(', ')})` : ''}`, w: `${e.fichero}:${e.linea}`, a: appName(e.fichero) })),
    ...lupaIssues.filter((i) => i.severity === 'high' && ['secretos', 'datos', 'ia', 'exposicion'].includes(i.lupa?.cat)).map((i) => ({ sev: 'high', t: i.title, w: i.locations?.[0] ? `${i.locations[0].file}:${i.locations[0].line}` : '', a: appName(i.locations?.[0]?.file) })),
    ...kevRows.filter((k) => !k.expuesta).map((k) => ({ sev: 'high', t: `${k.paquete} ${k.version}: ${k.cves.join(', ')} se está explotando (KEV)`, w: k.fichero, a: k.app })),
  ];
  // en un proyecto sin nada grave, lo más importante es lo que hay que mirar: endpoints, IA, datos y secretos
  if (urgent.length < 6) urgent.push(
    ...lupaIssues.filter((i) => i.severity === 'high' && !['secretos', 'datos', 'ia', 'exposicion'].includes(i.lupa?.cat)).map((i) => ({ sev: 'high', t: i.title, w: i.locations?.[0] ? `${i.locations[0].file}:${i.locations[0].line}` : '', a: appName(i.locations?.[0]?.file) })),
    ...lupaIssues.filter((i) => i.severity === 'medium' && ['endpoints', 'ia', 'datos', 'secretos', 'exposicion'].includes(i.lupa?.cat)).map((i) => ({ sev: 'medium', t: i.title, w: i.locations?.[0] ? `${i.locations[0].file}:${i.locations[0].line}` : '', a: appName(i.locations?.[0]?.file) })),
  );
  urgent.splice(12);
  // endpoints con algún problema, tengan login o no, lo más grave primero
  const withIssues = E.filter((e) => RANK[e.severidad] != null).sort((a, b) => RANK[a.severidad] - RANK[b.severidad] || (+(b.deberiaSerPublico === false && b.publico !== false) - +(a.deberiaSerPublico === false && a.publico !== false)));

  // ---------------------------------------------------------------- tecnología
  const TYPES = [['runtime', 'Runtimes'], ['framework', 'Frameworks'], ['base-de-datos', 'Bases de datos'], ['imagen', 'Imágenes Docker'], ['infra', 'Infraestructura'], ['libreria', 'Librerías con ciclo de vida']];
  const ORDER = ['sin-soporte', 'caduca-pronto', 'sin-mantenimiento', 'desactualizado', 'desconocido', 'al-dia'];
  const techGroups = TYPES.map(([t, name]) => {
    const uniq = new Map();
    for (const c of comps.filter((x) => x.tipo === t)) { const k = `${c.nombre}@${c.version}`; if (!uniq.has(k)) uniq.set(k, { ...c, donde: new Set() }); uniq.get(k).donde.add(appName(c.fichero)); }
    const list = [...uniq.values()].sort((a, b) => ORDER.indexOf(a.eol?.estado || 'desconocido') - ORDER.indexOf(b.eol?.estado || 'desconocido'));
    if (!list.length) return '';
    return `<h3>${esc(name)} <span class="c">${list.length}</span></h3><table class="t"><thead><tr><th>Pieza</th><th>Versión</th><th>Estado</th><th>Fin de soporte</th><th>Última</th><th>Dónde</th></tr></thead><tbody>${list.slice(0, 40).map((c) => `<tr><td>${esc(c.nombre)}${c.nota ? `<div class="sub">${esc(c.nota)}</div>` : ''}</td><td class="num">${esc(c.version || '—')}</td><td>${pill(STATE[c.eol?.estado || 'desconocido'])}</td><td class="num">${esc(c.eol?.finSoporte || '—')}</td><td class="num">${esc(c.eol?.ultima || '—')}</td><td>${esc([...c.donde].join(', '))}</td></tr>`).join('')}</tbody></table>${list.length > 40 ? `<p class="sub">y ${list.length - 40} más</p>` : ''}`;
  }).join('');
  const langs = (tech?.lenguajes || []).slice(0, 8);
  const maxL = Math.max(1, ...langs.map((l) => l.lineas));
  const langBars = langs.map((l) => `<div class="bar-row"><div class="bar-l">${esc(l.lenguaje)}</div><div class="bar-t"><div class="bar" style="width:${Math.max(1, (l.lineas / maxL) * 100)}%"><span class="seg acc" style="flex:1" data-tip="${esc(l.lenguaje)}: ${fmt(l.lineas)} líneas en ${fmt(l.ficheros)} ficheros"></span></div><span class="bar-v">${fmt(l.lineas)}</span></div></div>`).join('');
  const ecos = Object.entries(tech?.ecosistemas || {}).map(([k, v]) => `<div class="tile small"><div class="tl">${esc(k)}</div><div class="tv">${fmt(v.total)}</div><div class="sub">${fmt(v.directas)} directas</div></div>`).join('');
  const chips = (arr) => arr.map((x) => `<span class="chip">${esc(x)}</span>`).join(' ');

  // ---------------------------------------------------------------- HTML
  const repoLine = repos.map((r) => `${esc(r.name || r.path)}${r.branch ? ` · ${esc(r.branch)}` : ''}${r.head ? `@${esc(String(r.head).slice(0, 8))}` : ''}`).join(' &nbsp;|&nbsp; ');
  const R = L.revision || {};
  const tile = (label, value, sub, css = '') => `<div class="tile ${css}"><div class="tl">${esc(label)}</div><div class="tv">${fmt(value)}</div><div class="sub">${sub}</div></div>`;
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lupa · ${esc(graph.project?.name || 'informe')}</title>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--raise:#f3f2ee;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--line:#c3c2b7;--acc:#2a78d6;--crit:#d03b3b;--serious:#ec835a;--warn:#fab219;--good:#0ca30c;--ring:rgba(11,11,11,.10)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--raise:#232321;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--line:#383835;--acc:#3987e5;--ring:rgba(255,255,255,.10)}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--raise:#232321;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--line:#383835;--acc:#3987e5;--ring:rgba(255,255,255,.10)}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header .k{color:var(--muted);font-size:13px;letter-spacing:.04em;text-transform:uppercase}h1{font-size:30px;margin:4px 0 6px;font-weight:650}
.meta{color:var(--ink2);font-size:13px}section{background:var(--surface);border:1px solid var(--ring);border-radius:16px;padding:22px 22px 18px;margin-top:18px}
h2{font-size:19px;margin:0 0 4px;font-weight:620}h3{font-size:15px;margin:18px 0 8px;font-weight:600}.lead{color:var(--ink2);margin:0 0 14px;font-size:14px}
.c{color:var(--muted);font-weight:500}.sub{color:var(--muted);font-size:12.5px}
.hero{display:grid;grid-template-columns:minmax(180px,220px) 1fr;gap:18px;align-items:stretch}
.grade{border-radius:14px;padding:18px;background:var(--raise);display:flex;flex-direction:column;justify-content:center}
.grade .g{font-size:64px;line-height:1;font-weight:700}.grade .n{color:var(--ink2);font-size:14px;margin-top:6px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--raise);border-radius:12px;padding:12px 14px;border-top:3px solid transparent}.tile .tl{font-size:12.5px;color:var(--ink2)}.tile .tv{font-size:28px;font-weight:650;line-height:1.15;margin:2px 0}
.tile.crit{border-top-color:var(--crit)}.tile.serious{border-top-color:var(--serious)}.tile.warn{border-top-color:var(--warn)}.tile.good{border-top-color:var(--good)}.tile.small .tv{font-size:20px}
.pill{display:inline-flex;gap:5px;align-items:center;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;white-space:nowrap;background:color-mix(in srgb,var(--pc) 16%,transparent);color:var(--ink)}
.pill.crit{--pc:var(--crit)}.pill.serious{--pc:var(--serious)}.pill.warn{--pc:var(--warn)}.pill.good{--pc:var(--good)}.pill.muted{--pc:var(--muted)}
.pill span{color:var(--pc)}
svg.tmap{width:100%;height:auto;display:block}.tm-top{fill:var(--raise)}.tm-h{fill:var(--ink2);font-size:12px;font-weight:600}
.tm{stroke:var(--surface);stroke-width:2}.tm.crit{fill:color-mix(in srgb,var(--crit) 34%,var(--surface))}.tm.serious{fill:color-mix(in srgb,var(--serious) 30%,var(--surface))}.tm.warn{fill:color-mix(in srgb,var(--warn) 26%,var(--surface))}.tm.good{fill:color-mix(in srgb,var(--good) 14%,var(--surface))}
.tm-l{fill:var(--ink);font-size:12px;font-weight:600}.tm-v{fill:var(--ink2);font-size:11.5px}.tm-cell:hover rect{filter:brightness(1.06)}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0 0;font-size:12.5px;color:var(--ink2)}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.bar-row{display:grid;grid-template-columns:200px 1fr;gap:12px;align-items:center;margin:7px 0}.bar-l{font-size:13.5px;color:var(--ink2);text-align:right}
.bar-t{display:flex;align-items:center;gap:8px}.bar{display:flex;gap:2px;height:16px;min-width:4px}.bar-v{font-size:12.5px;color:var(--ink2);font-variant-numeric:tabular-nums}
.bar-t .bar{max-width:calc(100% - 56px)}.seg{height:100%;display:block}.seg:first-child{border-radius:0}.seg:last-child{border-radius:0 4px 4px 0}.seg.crit{background:var(--crit)}.seg.serious{background:var(--serious)}.seg.warn{background:var(--warn)}.seg.acc{background:var(--acc);border-radius:0 4px 4px 0}
table.t{width:100%;border-collapse:collapse;font-size:13.5px}.t th{text-align:left;font-weight:600;color:var(--ink2);font-size:12.5px;border-bottom:1px solid var(--line);padding:6px 8px}
.t td{border-bottom:1px solid var(--grid);padding:7px 8px;vertical-align:top}.t td.num{font-variant-numeric:tabular-nums;white-space:nowrap}.t code,.w{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ink2);word-break:break-all}
.urg{list-style:none;margin:0;padding:0}.urg li{display:grid;grid-template-columns:auto 1fr;gap:10px;padding:9px 0;border-bottom:1px solid var(--grid)}.urg li:last-child{border:0}
.chip{display:inline-block;background:var(--raise);border-radius:6px;padding:1px 7px;font-size:12px;margin:1px 0}
details{margin-top:10px}summary{cursor:pointer;color:var(--acc);font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12.5px;padding:6px 9px;border-radius:8px;opacity:0;transition:opacity .1s;max-width:320px;z-index:9}
footer{color:var(--muted);font-size:12px;margin-top:22px}
@media (max-width:720px){.hero,.grid2{grid-template-columns:1fr}.bar-row{grid-template-columns:110px 1fr}.t{font-size:12.5px}section{padding:16px}}
@media print{:root{color-scheme:light}body{background:#fff}section{break-inside:avoid;border-color:#ddd}#tip,details summary{display:none}details>*{display:block}}
</style></head><body><main>
<header><div class="k">Lupa · informe de seguridad</div><h1>${esc(graph.project?.name || 'Proyecto')}</h1>
<div class="meta">${esc(generado.toLocaleString('es-ES', { dateStyle: 'long', timeStyle: 'short' }))} &nbsp;|&nbsp; ${repoLine || '—'}</div></header>

<section><div class="hero"><div class="grade"><div class="sub">Nota</div><div class="g">${sc.letra}</div><div class="n">${sc.n} sobre 100</div></div>
<div class="tiles">
${tile('Avisos graves', count('high', lupaIssues), `${fmt(count('medium', lupaIssues))} a mirar · ${fmt(count('low', lupaIssues))} menores`, count('high', lupaIssues) ? 'crit' : 'good')}
${tile('Explotadas ahora (KEV)', kevRows.length, `${kevRows.filter((k) => k.expuesta).length} en apps expuestas`, kevRows.length ? 'crit' : 'good')}
${tile('Abiertos y no deberían', shouldNot.length, `de ${fmt(E.length)} endpoints · ${graveEndpoints.length} graves`, shouldNot.length ? 'crit' : 'good')}
${tile('Tecnología sin soporte', eolUnique.size, 'runtimes, frameworks, BD e imágenes', eolUnique.size ? 'serious' : 'good')}
${tile('Modelos con datos sensibles', specialModels.length, `${fmt((datos?.ficheros || []).length)} con datos personales`, specialModels.length ? 'warn' : 'good')}
</div></div></section>

<section><h2>Dónde se pierde la seguridad</h2><p class="lead">Cada bloque es una parte del proyecto, del tamaño de su código. El color dice lo peor que tiene dentro.</p>
<svg class="tmap" viewBox="0 0 ${W} ${H}" role="img" aria-label="Mapa de calor de seguridad por módulo">${svgCells}</svg>
<div class="legend"><span><i style="background:var(--crit)"></i>▲ Hay algo grave</span><span><i style="background:var(--serious)"></i>◆ Hay algo a mirar</span><span><i style="background:var(--warn)"></i>● Solo menores</span><span><i style="background:var(--good)"></i>✓ Sin avisos</span></div>
<details><summary>Ver como tabla</summary><table class="t"><thead><tr><th>Parte</th><th>Graves</th><th>A mirar</th><th>Menores</th></tr></thead><tbody>${heatRows.map(([id, h]) => `<tr><td>${esc(label(id))}</td><td class="num">${h.high}</td><td class="num">${h.medium}</td><td class="num">${h.low}</td></tr>`).join('')}</tbody></table></details></section>

<section><h2>Lo más importante</h2><p class="lead">Por orden: lo que ya se está explotando en apps expuestas, los endpoints abiertos que no deberían, los secretos o datos al aire y, si no hay nada grave, lo que hay que mirar.</p>
<ul class="urg">${urgent.map((u) => `<li>${pill(SEV[u.sev])}<div>${esc(u.t)}<div class="w">${esc(u.a)} · ${esc(u.w)}</div></div></li>`).join('') || '<li><span></span><div>Nada importante pendiente.</div></li>'}</ul></section>

<section><h2>Por tipo de problema</h2><p class="lead">Número de avisos de cada tipo, partidos por gravedad.</p>${bars}
<div class="legend"><span><i style="background:var(--crit)"></i>▲ Graves</span><span><i style="background:var(--serious)"></i>◆ A mirar</span><span><i style="background:var(--warn)"></i>● Menores</span></div>
<details><summary>Ver como tabla</summary><table class="t"><thead><tr><th>Tipo</th><th>Graves</th><th>A mirar</th><th>Menores</th></tr></thead><tbody>${cats.map(([c, n]) => `<tr><td>${esc(n)}</td><td class="num">${L.categorias[c].high}</td><td class="num">${L.categorias[c].medium}</td><td class="num">${L.categorias[c].low}</td></tr>`).join('')}</tbody></table></details></section>

<section><h2>Superficie de ataque</h2><p class="lead">${fmt(E.length)} endpoints, ${fmt(R.endpoints || 0)} revisados uno a uno por la IA. ${fmt(E.filter((e) => e.publico === true).length)} se pueden llamar sin login; ${fmt(shouldNot.length)} de ellos no deberían.</p>
<h3>Endpoints con algún problema <span class="c">${withIssues.length}</span></h3>
<table class="t"><thead><tr><th></th><th>Endpoint</th><th>Acceso</th><th>App</th><th>Qué pasa</th></tr></thead><tbody>${withIssues.slice(0, 50).map((e) => `<tr><td>${pill(SEV[{ alta: 'high', media: 'medium', baja: 'low' }[e.severidad]])}</td><td><code>${esc(e.metodo)} ${esc(e.ruta)}</code></td><td>${e.publico === true ? `Sin login${e.deberiaSerPublico === false ? '<div class="sub">y no debería</div>' : ''}` : e.publico === false ? 'Con login' : 'Dudoso'}</td><td>${esc(appName(e.fichero))}</td><td>${esc(e.motivo)}${e.datos?.length ? `<div class="sub">Suelta: ${esc(e.datos.join(', '))}</div>` : ''}</td></tr>`).join('') || '<tr><td colspan="5">Ninguno.</td></tr>'}</tbody></table>${withIssues.length > 50 ? `<p class="sub">y ${withIssues.length - 50} más en el mapa.</p>` : ''}</section>

<section><h2>Librerías con fallos que se están explotando (KEV)</h2><p class="lead">CVE que el catálogo KEV de la CISA da como explotados en ataques reales. «Expuesta» quiere decir que esa app tiene endpoints que cualquiera puede llamar. EPSS es la probabilidad de explotación en 30 días, en percentil.</p>
<table class="t"><thead><tr><th>Librería</th><th>CVE</th><th>App</th><th>Expuesta</th><th>EPSS</th><th>Arreglo</th></tr></thead><tbody>${kevRows.map((k) => `<tr><td>${esc(k.paquete)} <span class="sub">${esc(k.version)}</span>${k.ransomware ? '<div class="sub">usada en ransomware</div>' : ''}</td><td><code>${esc(k.cves.join(', '))}</code></td><td>${esc(k.app)}</td><td>${k.expuesta ? pill(SEV.high).replace('Grave', 'Sí') : pill(STATE.desconocido).replace('Sin datos', 'No consta')}</td><td class="num">${k.epss ? Math.round(k.epss * 100) + '%' : '—'}</td><td>${esc(k.arreglo || 'sin versión arreglada')}</td></tr>`).join('') || '<tr><td colspan="6">Ninguna librería con CVE del catálogo KEV.</td></tr>'}</tbody></table>
<p class="sub">${fmt(depIssues.length)} ficheros de dependencias con avisos en total.</p></section>

<section><h2>Tecnología</h2><p class="lead">Qué usa el proyecto y si cada pieza sigue recibiendo parches de seguridad (según endoflife.date).</p>
<div class="grid2"><div><h3>Lenguajes (líneas de código)</h3>${langBars}</div><div><h3>Dependencias por ecosistema</h3><div class="tiles">${ecos || '<p class="sub">Sin datos de dependencias.</p>'}</div>
<h3>También usa</h3><p>${tech?.ia?.length ? `<b>IA:</b> ${chips([...new Set(tech.ia.map((a) => a.nombre))].slice(0, 10))}<br>` : ''}${tech?.basesDeDatos?.length ? `<b>Bases de datos:</b> ${chips(tech.basesDeDatos.map((d) => d.nombre))}<br>` : ''}${tech?.ci?.length ? `<b>CI/CD:</b> ${chips([...new Set(tech.ci.map((c) => c.sistema))])}<br>` : ''}${Object.keys(tech?.nube || {}).length ? `<b>Nube (Terraform):</b> ${chips(Object.entries(tech.nube).map(([k, v]) => `${k} · ${v.recursos} recursos`))}` : ''}</p></div></div>
${techGroups}</section>

<section><h2>Datos personales</h2><p class="lead">Modelos, tablas y migraciones que guardan datos de personas. Salud, antecedentes, biometría u origen son categorías especiales del RGPD (art. 9).</p>
<table class="t"><thead><tr><th>Dónde</th><th>Qué guarda</th><th>Cifrado</th></tr></thead><tbody>${(datos?.ficheros || []).sort((a, b) => +b.especial - +a.especial).slice(0, 40).map((d) => `<tr><td><span class="w">${esc(d.fichero)}</span>${d.especial ? `<div>${pill(SEV.medium).replace('A mirar', 'Categoría especial')}</div>` : ''}</td><td>${chips(d.tipos)}<div class="sub">${esc(d.campos.map((c) => c.campo).slice(0, 12).join(', '))}</div></td><td>${d.cifrado ? pill(STATE['al-dia']).replace('Con soporte', 'Hay pistas') : pill(STATE.desconocido).replace('Sin datos', 'No consta')}</td></tr>`).join('') || '<tr><td colspan="3">No se han encontrado modelos con datos personales.</td></tr>'}</tbody></table></section>

<section><h2>Cómo se ha hecho</h2>
<p class="lead">Herramientas: ${esc(Object.entries(L.herramientas || {}).map(([n, v]) => `${n} ${String(v).split(' ').pop()}`).join(' · ') || '—')}. Revisión de la IA: ${fmt(R.endpoints || 0)} de ${fmt(R.endpointsTotal || 0)} endpoints y ${fmt(R.hallazgosCribados || 0)} grupos de avisos; ${fmt(R.descartados || 0)} falsos positivos quitados.</p>
${(L.avisos || []).length ? `<h3>Lo que no se pudo mirar entero</h3><ul>${L.avisos.map((a) => `<li class="sub">${esc(a)}</li>`).join('')}</ul>` : ''}
<h3>La nota</h3><table class="t"><tbody>${sc.quita.map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">−${v}</td></tr>`).join('')}<tr><td><b>Resultado</b> (sobre 100; A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 45 · E ≥ 30 · F &lt; 30)</td><td class="num"><b>${sc.n} → ${sc.letra}</b></td></tr></tbody></table>
<p class="sub">Lupa es una auditoría automática del código, la configuración y las dependencias, con revisión por IA. No sustituye a un pentest: no ejecuta la aplicación ni prueba ataques reales.</p></section>
<footer>Generado por Lupa. El mapa interactivo está en floorplan/index.html; el detalle de cada aviso, con su arreglo, en su Health.</footer>
</main><div id="tip" role="tooltip"></div>
<script>(()=>{const t=document.getElementById('tip');document.addEventListener('mousemove',e=>{const el=e.target.closest('[data-tip]');if(!el){t.style.opacity=0;return}t.textContent=el.dataset.tip;t.style.opacity=1;const x=Math.min(e.clientX+14,innerWidth-t.offsetWidth-8),y=e.clientY+16;t.style.left=x+'px';t.style.top=y+'px'})})();</script>
</body></html>`;
}
