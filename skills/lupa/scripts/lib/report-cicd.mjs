// La sección de CI/CD del informe: el camino del código a producción en cinco etapas (código, pipeline,
// credenciales, artefactos y destino), cada una del color de lo peor que tiene, y el detalle de la plataforma.
import { esc, SEV, STATE, tag, fmt } from './report-ui.mjs';

const PLATAFORMA = { github: 'GitHub', 'bitbucket-cloud': 'Bitbucket Cloud', 'bitbucket-server': 'Bitbucket Server', gitlab: 'GitLab', otra: 'otra', desconocida: 'desconocida' };
const worst = (e) => (!e ? 'good' : e.high ? 'crit' : e.medium ? 'serious' : e.low ? 'warn' : 'good');
const cut = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));

/** Las cinco etapas, con lo que se vio en cada una. */
function stages(r) {
  const p = r.plataformas?.[0] || null, d = r.despliegue || {};
  const prot = p?.proteccion;
  const rama = !p ? 'plataforma sin revisar' : !prot?.conocida ? 'protección no visible' : prot.existe ? `${p.rama}: protegida` : `${p.rama}: SIN proteger`;
  const rev = p?.revisionReal ? `revisados: ${p.revisionReal.aprobados} de ${p.revisionReal.cambios}` : 'revisión no visible';
  const prod = (p?.entornos || []).filter((e) => e.produccion || /prod/i.test(e.nombre));
  const logs = p?.logs ? `logs: ${p.logs.revisadas} ejecuciones, ${p.logs.hallazgos?.length || 0} secretos` : 'logs sin revisar';
  return [
    { key: 'codigo', t: 'Código', l: [rama, rev] },
    { key: 'ci', t: 'Pipeline', l: [(r.sistemas || []).map((s) => s.nombre).join(', ') || 'sin CI', `${fmt(r.ficheros)} ficheros de pipeline`] },
    { key: 'credenciales', t: 'Credenciales', l: [{ oidc: 'entra en la nube con OIDC', 'claves-fijas': 'claves fijas de la nube', mixto: 'OIDC y claves fijas', 'no-se-ve': 'no se ve cómo entra' }[d.credenciales] || '—', logs] },
    { key: 'artefactos', t: 'Artefactos', l: [d.publicaImagenes ? `imágenes ${d.firma ? 'firmadas' : 'SIN firmar'}` : 'no publica imágenes', d.sbom ? 'con SBOM' : 'sin SBOM'] },
    { key: 'destino', t: 'Destino', l: [cut((d.destinos || []).join(', ') || 'no se ve', 34), prod.length ? `producción ${prod.every((e) => e.aprobacion) ? 'con' : 'SIN'} aprobación` : 'sin entorno de producción'] },
  ];
}

function chain(r) {
  const W = 960, H = 170, n = 5, gap = 26, bw = (W - gap * (n - 1)) / n;
  const st = stages(r);
  const boxes = st.map((s, i) => {
    const x = i * (bw + gap), css = worst(r.etapas?.[s.key]);
    const e = r.etapas?.[s.key];
    const tip = e ? `${s.t}: ${e.high} graves, ${e.medium} a mirar, ${e.low} menores${e.titulos?.length ? ' · ' + e.titulos.map((x) => x.titulo).join(' · ') : ''}` : `${s.t}: sin avisos`;
    return `<g data-tip="${esc(tip)}"><rect class="cc-box" x="${x}" y="10" width="${bw}" height="${H - 20}" rx="12"/><rect class="cc-band ${css}" x="${x}" y="10" width="${bw}" height="8" rx="4"/>
<text class="cc-t" x="${x + 14}" y="44">${esc(s.t)}</text>${s.l.map((l, j) => `<text class="cc-l" x="${x + 14}" y="${70 + j * 20}">${esc(cut(l, 30))}</text>`).join('')}
<text class="cc-c ${css}" x="${x + 14}" y="${H - 22}">${e ? `${e.high ? `▲ ${e.high} ${e.high === 1 ? 'grave' : 'graves'}` : e.medium ? `◆ ${e.medium} a mirar` : `● ${e.low} ${e.low === 1 ? 'menor' : 'menores'}`}` : '✓ sin avisos'}</text></g>`;
  }).join('');
  const arrows = st.slice(1).map((_, i) => { const x = (i + 1) * (bw + gap) - gap; return `<path class="cc-arrow" d="M${x + 4},${H / 2} L${x + gap - 6},${H / 2}" marker-end="url(#cc-head)"/>`; }).join('');
  return `<svg class="cc" viewBox="0 0 ${W} ${H}" role="img" aria-label="El camino del código a producción"><defs><marker id="cc-head" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="cc-head"/></marker></defs>${arrows}${boxes}</svg>`;
}

export const CICD_CSS = `svg.cc{width:100%;height:auto;display:block;margin:6px 0 4px}.cc-box{fill:var(--raise);stroke:var(--ring)}.cc-band.crit{fill:var(--crit)}.cc-band.serious{fill:var(--serious)}.cc-band.warn{fill:var(--warn)}.cc-band.good{fill:var(--good)}
.cc-t{fill:var(--ink);font-size:15px;font-weight:650}.cc-l{fill:var(--ink2);font-size:12.5px}.cc-c{font-size:12.5px;font-weight:600}.cc-c.crit{fill:var(--crit)}.cc-c.serious{fill:var(--serious)}.cc-c.warn{fill:var(--ink2)}.cc-c.good{fill:var(--good)}
.cc-arrow{stroke:var(--muted);stroke-width:2;fill:none}.cc-head{fill:var(--muted)}`;

export function cicdSection(r) {
  if (!r) return '';
  const p = r.plataformas || [];
  const ETAPA = { codigo: 'Código', ci: 'Pipeline', credenciales: 'Credenciales', artefactos: 'Artefactos', destino: 'Destino' };
  const worstList = Object.entries(r.etapas || {}).flatMap(([k, e]) => (e.titulos || []).map((x) => [k, x.titulo, x.gravedad])).sort((a, b) => (a[2] === 'high' ? 0 : 1) - (b[2] === 'high' ? 0 : 1)).slice(0, 10);
  const rows = p.map((x) => {
    const pr = x.proteccion || {};
    const prot = x.error ? esc(x.error) : !pr.conocida ? 'no visible' : !pr.existe ? tag(SEV.high, 'sin proteger') : [pr.exigePR ? 'solo por PR' : pr.exigePR === false ? 'sin exigir PR' : '', pr.aprobaciones != null ? `${pr.aprobaciones} aprobación(es)` : '', pr.forcePush === false ? 'sin force push' : pr.forcePush ? 'con force push' : ''].filter(Boolean).join(' · ');
    const prod = (x.entornos || []).filter((e) => e.produccion || /prod/i.test(e.nombre));
    return `<tr><td><b>${esc(x.repo)}</b><div class="sub">${esc(PLATAFORMA[x.plataforma] || x.plataforma)}${x.privado === false ? ' · público' : x.privado ? ' · privado' : ''}</div></td>
<td>${esc(x.rama || '—')}<div class="sub">${prot}</div></td>
<td class="num">${x.revisionReal ? `${x.revisionReal.aprobados} de ${x.revisionReal.cambios}` : '—'}</td>
<td>${prod.length ? prod.map((e) => `${esc(e.nombre)}: ${e.aprobacion ? tag(STATE['al-dia'], 'con aprobación') : tag(SEV.medium, 'sin aprobación')}`).join('<br>') : '<span class="sub">sin entorno de producción</span>'}</td>
<td class="num">${x.logs ? `${fmt(x.logs.revisadas)} ejecuciones<div class="sub">${fmt(x.logs.hallazgos?.length || 0)} secretos</div>` : '—'}</td></tr>`;
  }).join('');
  const gaps = p.flatMap((x) => (x.huecos || []).map((h) => `${x.repo}: ${h}`));
  return `<section><h2>CI/CD y despliegue</h2><p class="lead">Cómo llega el código a producción y por dónde se podría colar alguien en ese camino. ${(r.sistemas || []).map((s) => esc(s.nombre)).join(', ') || 'No se ha encontrado CI'}${r.ficheros ? ` (${fmt(r.ficheros)} ficheros de pipeline)` : ''}${p.length ? ` en ${[...new Set(p.map((x) => PLATAFORMA[x.plataforma] || x.plataforma))].join(', ')}` : ''}.</p>
${chain(r)}
<div class="legend"><span><i style="background:var(--crit)"></i>Algo grave en esa etapa</span><span><i style="background:var(--serious)"></i>Algo a mirar</span><span><i style="background:var(--good)"></i>Sin avisos</span><span>Pasa el ratón por una etapa para ver sus avisos.</span></div>
${worstList.length ? `<h3>Lo más grave del camino</h3><ul class="urg">${worstList.map(([k, t, s]) => `<li>${tag(SEV[s], ETAPA[k] || k)}<div>${esc(t)}</div></li>`).join('')}</ul>` : ''}
${!r.revisadoPorFuera ? `<p class="sub">La plataforma (protección de la rama, revisión de verdad, secretos, entornos y logs de las ejecuciones) no se ha revisado: solo los ficheros del repositorio.</p>` : `<h3>La plataforma</h3><table class="t"><thead><tr><th>Repositorio</th><th>Rama principal</th><th>Cambios revisados</th><th>Producción</th><th>Logs</th></tr></thead><tbody>${rows}</tbody></table>`}
${r.aws ? `<p class="sub">AWS ${esc(r.aws.cuenta || '')}: ${r.aws.error ? `no se pudo leer (${esc(r.aws.error)})` : `${fmt(r.aws.roles)} roles con confianza en el CI revisados`}.</p>` : ''}
${gaps.length ? `<details><summary>Lo que no se ha podido ver (${gaps.length})</summary><ul>${gaps.map((g) => `<li class="sub">${esc(g)}</li>`).join('')}</ul></details>` : ''}
</section>`;
}
