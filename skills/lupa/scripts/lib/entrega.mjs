// La entrega: el informe es un solo HTML que el equipo manda a quien evalúa. Para que sirva de algo lleva
// la ficha de la pasada (quién, cuándo, sobre qué commit, con qué herramientas), lo que NO se miró
// (para que un informe incompleto no pase por bueno) y los datos en JSON dentro, con su huella SHA-256.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run, readJSON } from './util.mjs';
import { esc, fmt, tag, SEV, STATE } from './report-ui.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN = path.join(HERE, '..', '..', '..', '..', '.claude-plugin', 'plugin.json');
const FIJADO = path.join(HERE, '..', '..', '..', 'floorplan', 'FIJADO.md');

/** Una URL de remoto sin credenciales: https://token@github.com/x → https://github.com/x */
export const cleanRemote = (u) => String(u || '').replace(/^(https?:\/\/)[^@/]+@/, '$1').trim();

/** Respuestas de la revisión que siguen vacías en los lotes. */
function pendingReview(dir) {
  let e = 0, h = 0;
  try {
    for (const n of fs.readdirSync(dir).filter((x) => /^lote-(?!00)\d+\.json$/.test(x))) {
      const j = readJSON(path.join(dir, n), {});
      e += (j.endpoints || []).filter((x) => !x.severidad).length;
      h += (j.hallazgos || []).filter((x) => !x.veredicto).length;
    }
  } catch {}
  return { endpoints: e, hallazgos: h };
}

export function deliveryInfo({ root, graph, found, answers, endpoints, discarded, infra, cicd = null, equipo }) {
  const git = (dir, args) => run('git', ['-C', dir, ...args], { timeout: 30_000 }).stdout.trim();
  const repos = (graph.meta?.repos || []).map((r) => {
    const dir = path.join(root, r.path || '.');
    return { nombre: r.name || r.path, rama: r.branch || git(dir, ['rev-parse', '--abbrev-ref', 'HEAD']), commit: String(r.head || git(dir, ['rev-parse', 'HEAD'])).slice(0, 12),
      remoto: cleanRemote(git(dir, ['remote', 'get-url', 'origin'])), sinCommitear: git(dir, ['status', '--porcelain', '--untracked-files=no']).split('\n').filter(Boolean).length };
  });
  const pend = pendingReview(path.join(root, 'floorplan', 'lupa', 'revision'));
  const faltan = (found.avisos || []).filter((a) => /^falta \w+/.test(a)).map((a) => a.split(':')[0].replace(/^falta /, ''));
  const reviewed = endpoints.filter((e) => e.revision).length;
  const huecos = [
    ...faltan.map((t) => `sin ${t}`),
    ...(endpoints.length - reviewed ? [`${endpoints.length - reviewed} endpoints sin revisar`] : []),
    ...(pend.hallazgos ? [`${pend.hallazgos} avisos sin cribar`] : []),
    ...((infra?.sinAuditar || []).length ? [`${infra.sinAuditar.length} servidores sin auditar por dentro`] : []),
    ...(infra && !infra.externo ? ['sin vista desde internet'] : []),
    ...(!infra ? ['sin servidores ni red'] : []),
    // el CI/CD: si hay pipelines, la plataforma tiene que estar revisada, y con credenciales
    ...(cicd?.ficheros && !cicd.revisadoPorFuera ? ['sin revisar la plataforma de CI/CD'] : []),
    ...(cicd?.plataformas || []).filter((p) => p.error).map((p) => `${p.repo}: plataforma sin revisar (${p.error})`),
    ...((cicd?.plataformas || []).some((p) => (p.huecos || []).length) ? [`${(cicd.plataformas || []).reduce((a, p) => a + (p.huecos || []).length, 0)} cosas de la plataforma sin ver por permisos`] : []),
    ...repos.filter((r) => r.sinCommitear).map((r) => `${r.nombre}: ${r.sinCommitear} cambios sin commitear`),
  ];
  const quien = git(root, ['config', 'user.name']) || os.userInfo().username;
  return {
    lupa: readJSON(PLUGIN, {}).version || '?', floorplan: (/commit\s+([0-9a-f]{7,})/i.exec(fs.existsSync(FIJADO) ? fs.readFileSync(FIJADO, 'utf8') : '') || [])[1]?.slice(0, 7) || '?',
    equipo: equipo || '', proyecto: graph.project?.name || path.basename(root), quien, email: git(root, ['config', 'user.email']), generado: new Date().toISOString(),
    repos, herramientas: found.herramientas || {}, faltan,
    revision: { endpoints: reviewed, endpointsTotal: endpoints.length, cribados: answers.findings.size, pendientes: pend.hallazgos, descartados: discarded.length },
    cicd: cicd ? { sistemas: (cicd.sistemas || []).map((s) => s.nombre), plataformas: (cicd.plataformas || []).map((p) => `${p.plataforma}:${p.repo}`), revisadoPorFuera: !!cicd.revisadoPorFuera } : null,
    servidores: { revisados: infra?.servidores?.length || 0, sinAuditar: (infra?.sinAuditar || []).map((x) => x.nombre), externo: infra?.externo ? { desde: infra.externo.desde, objetivos: infra.externo.objetivos.length } : null },
    huecos, completo: !huecos.length,
  };
}

/** Los datos del informe en JSON, para comparar equipos o cargarlos en otra herramienta. Nunca llevan secretos. */
export function deliveryData({ entrega, graph, score }) {
  const issues = (graph.health?.issues || []).filter((i) => String(i.id).startsWith('lupa:'));
  const datos = {
    lupa: entrega.lupa, entrega: { ...entrega }, nota: score,
    resumen: { graves: issues.filter((i) => i.severity === 'high').length, aMirar: issues.filter((i) => i.severity === 'medium').length, menores: issues.filter((i) => i.severity === 'low').length, porCategoria: graph.lupa?.categorias || {} },
    avisos: issues.map((i) => ({ id: i.id, categoria: i.lupa?.cat, gravedad: i.severity, titulo: i.title, detalle: String(i.detail || '').slice(0, 600), donde: (i.locations || []).slice(0, 5) })),
    descartados: graph.lupa?.descartados || [],
  };
  const body = JSON.stringify(datos);
  return { ...datos, huella: crypto.createHash('sha256').update(body).digest('hex') };
}

/** Trozos del informe: la ficha de la cabecera, el detalle de «Cómo se ha hecho» y el bloque de datos. */
export function deliverySection(entrega, mode) {
  if (!entrega) return '';
  if (mode === 'cabecera') return `<div class="ficha">${entrega.equipo ? `<span class="chip">Equipo: ${esc(entrega.equipo)}</span>` : ''}<span class="chip">Lo ejecutó: ${esc(entrega.quien)}</span><span class="chip">Lupa ${esc(entrega.lupa)}</span>${entrega.completo ? '<span class="chip good">✓ Pasada completa</span>' : `<span class="chip serious">◆ Pasada incompleta: ${esc(entrega.huecos.slice(0, 3).join(' · '))}${entrega.huecos.length > 3 ? '…' : ''}</span>`}</div>`;
  if (mode === 'datos') return entrega.datos ? `<script type="application/json" id="lupa-datos">${JSON.stringify(entrega.datos).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')}</script>` : '';
  const R = entrega.revision, S = entrega.servidores;
  const row = (k, v) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`;
  return `<h3>Ficha de la pasada</h3><table class="t"><tbody>
${row('Equipo y proyecto', `${esc(entrega.equipo || '—')} · ${esc(entrega.proyecto)}`)}
${row('Lo ejecutó', `${esc(entrega.quien)}${entrega.email ? ` <span class="sub">${esc(entrega.email)}</span>` : ''} · ${esc(new Date(entrega.generado).toLocaleString('es-ES', { dateStyle: 'long', timeStyle: 'short' }))}`)}
${row('Código', entrega.repos.map((r) => `${esc(r.nombre)} · ${esc(r.rama)} @ <code>${esc(r.commit)}</code>${r.remoto ? ` <span class="sub">${esc(r.remoto)}</span>` : ''}${r.sinCommitear ? ` ${tag(SEV.medium, `${r.sinCommitear} cambios sin commitear`)}` : ''}`).join('<br>') || '—')}
${row('Herramientas', `${esc(Object.entries(entrega.herramientas).map(([n, v]) => `${n} ${String(v).split(' ').pop()}`).join(' · ') || '—')}${entrega.faltan.length ? ` ${tag(SEV.medium, `faltan: ${entrega.faltan.join(', ')}`)}` : ''} <span class="sub">· Lupa ${esc(entrega.lupa)} · floorplan ${esc(entrega.floorplan)}</span>`)}
${row('Revisión de la IA', `${fmt(R.endpoints)} de ${fmt(R.endpointsTotal)} endpoints · ${fmt(R.cribados)} grupos de avisos cribados${R.pendientes ? ` · ${tag(SEV.medium, `${R.pendientes} sin cribar`)}` : ''} · ${fmt(R.descartados)} falsos positivos quitados`)}
${row('Servidores y red', S.revisados ? `${fmt(S.revisados)} servidores por dentro${S.sinAuditar.length ? ` · ${tag(SEV.medium, `${S.sinAuditar.length} sin auditar`)} <span class="sub">${esc(S.sinAuditar.join(', '))}</span>` : ''} · vista desde internet: ${S.externo ? `${fmt(S.externo.objetivos)} objetivos desde ${esc(S.externo.desde || '—')}` : tag(SEV.medium, 'no hecha')}` : tag(SEV.medium, 'no se revisaron servidores'))}
${row('Cobertura', entrega.completo ? tag(STATE['al-dia'], 'Completa') : entrega.huecos.map((h) => tag(SEV.medium, h)).join(' '))}
${entrega.datos ? row('Huella de los datos', `<code>${esc(entrega.datos.huella)}</code> <span class="sub">SHA-256 de los datos JSON que van dentro de este fichero (id «lupa-datos»)</span>`) : ''}
</tbody></table>`;
}
