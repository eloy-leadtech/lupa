// La sección de infraestructura del informe: cada servidor por dentro, cómo se comunican (diagrama) y
// qué se ve desde internet, según AWS y según lo que se probó desde fuera.
import { esc, SEV, STATE, pill, tag, fmt, tile } from './report-ui.mjs';

const DETECTION = new Set(['Wazuh', 'Wazuh (manager)', 'CrowdStrike', 'Microsoft Defender', 'osquery', 'Falco', 'CrowdSec']);
const ADMIN = new Set([22, 23, 445, 1515, 2375, 2376, 3306, 3333, 3389, 5432, 5900, 6379, 9200, 11211, 15672, 27017, 55000]);
const chips = (arr, css = '') => arr.map((x) => `<span class="chip ${css}">${esc(x)}</span>`).join(' ');
const worstCss = (s) => (s?.graves ? 'crit' : s?.aMirar ? 'serious' : 'good');

/** Diagrama circular: servidores, internet y servicios de AWS; las conexiones como curvas. */
function diagram(red, servers) {
  // todos los endpoints de AWS en un solo nodo: si no, el dibujo es una estrella de SSM y GuardDuty
  const agg = (n) => (n.tipo === 'aws' && /^(AWS |Endpoint de VPC)/.test(n.nombre) ? 'aws' : n.id);
  const nodes = new Map();
  for (const n of red.nodes) {
    const id = agg(n);
    if (!nodes.has(id)) nodes.set(id, id === 'aws' ? { id, nombre: 'Servicios de AWS', tipo: 'aws' } : n);
  }
  const edges = new Map();
  for (const e of red.edges) {
    const a = agg({ ...red.nodes.find((n) => n.id === e.from), id: e.from }), b = agg({ ...red.nodes.find((n) => n.id === e.to), id: e.to });
    if (a === b) continue;
    const k = `${a}|${b}`;
    const x = edges.get(k) || { a, b, puertos: new Set(), claro: false, internet: 0, admin: false };
    x.puertos.add(e.puerto); x.claro ||= !!e.claro; x.internet = Math.max(x.internet, e.origenesInternet || 0); x.admin ||= a === 'internet' && ADMIN.has(e.puerto);
    edges.set(k, x);
  }
  const used = new Set([...edges.values()].flatMap((e) => [e.a, e.b]));
  const order = { internet: 0, aws: 3, desconocido: 4 };
  const list = [...nodes.values()].filter((n) => used.has(n.id) || n.tipo === 'servidor')
    .sort((p, q) => (order[p.tipo] ?? (p.nombre.startsWith('Balanceador') ? 1 : 2)) - (order[q.tipo] ?? (q.nombre.startsWith('Balanceador') ? 1 : 2)) || p.nombre.localeCompare(q.nombre));
  const W = 960, H = 640, cx = W / 2, cy = H / 2 + 6, R = Math.min(250, 120 + list.length * 7);
  const pos = new Map(list.map((n, i) => { const t = -Math.PI / 2 + (2 * Math.PI * i) / list.length; return [n.id, { x: cx + R * Math.cos(t), y: cy + R * Math.sin(t), t, i }]; }));
  const sum = new Map(servers.map((s) => [s.nombre, s]));
  const name = (id) => nodes.get(id)?.nombre || id;
  const paths = [...edges.values()].filter((e) => pos.has(e.a) && pos.has(e.b)).map((e) => {
    const p = pos.get(e.a), q = pos.get(e.b);
    const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2, kx = mx + (cx - mx) * 0.45, ky = my + (cy - my) * 0.45;
    const css = e.admin ? 'crit' : e.claro || e.a === 'internet' ? 'serious' : '';
    const ports = [...e.puertos].sort((x, y) => x - y).join(', ');
    const tip = `${name(e.a)} → ${name(e.b)} · puerto${e.puertos.size > 1 ? 's' : ''} ${ports}${e.claro ? ' · sin cifrar' : ''}${e.internet ? ` · ${fmt(e.internet)} IP de internet` : ''}`;
    return `<path class="ed ${css}" data-a="${pos.get(e.a).i}" data-b="${pos.get(e.b).i}" data-tip="${esc(tip)}" d="M${p.x.toFixed(1)},${p.y.toFixed(1)} Q${kx.toFixed(1)},${ky.toFixed(1)} ${q.x.toFixed(1)},${q.y.toFixed(1)}"/>`;
  }).join('');
  const dots = list.map((n) => {
    const p = pos.get(n.id); const c = Math.cos(p.t);
    const anchor = c > 0.25 ? 'start' : c < -0.25 ? 'end' : 'middle';
    const lx = p.x + Math.cos(p.t) * 14, ly = p.y + Math.sin(p.t) * 14 + (Math.abs(c) <= 0.25 ? (Math.sin(p.t) > 0 ? 8 : -2) : 4);
    const s = sum.get(n.nombre);
    const css = n.tipo === 'internet' ? 'int' : n.tipo === 'aws' ? 'aws' : n.tipo === 'desconocido' ? 'unk' : n.auditado === false ? 'srv off' : 'srv';
    const fill = n.tipo === 'servidor' && s ? ` style="fill:var(--${{ crit: 'crit', serious: 'serious', good: 'good' }[worstCss(s)]})"` : '';
    const tip = n.tipo === 'servidor' ? `${n.nombre} · ${n.ip || ''}${n.ipPublica ? ` · IP pública ${n.ipPublica}` : ''}${s ? ` · ${s.graves} graves, ${s.aMirar} a mirar` : n.auditado === false ? ' · sin auditar por dentro' : ''}` : n.nombre;
    return `<g class="nd ${css}" data-id="${p.i}" data-tip="${esc(tip)}"><circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${n.tipo === 'internet' ? 10 : 7}"${fill}/><text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}">${esc(n.nombre.length > 26 ? n.nombre.slice(0, 25) + '…' : n.nombre)}</text></g>`;
  }).join('');
  return `<svg class="net" viewBox="0 0 ${W} ${H}" role="img" aria-label="Diagrama de comunicaciones entre servidores">${paths}${dots}</svg>
<div class="legend"><span><i style="background:var(--crit)"></i>Internet, o conexión a un puerto de administración desde internet</span><span><i style="background:var(--serious)"></i>Desde internet o sin cifrar</span><span><i style="background:var(--line)"></i>Conexión interna</span><span><i style="background:var(--muted)"></i>Servicios de AWS</span><span>Servidor: color de su peor aviso · borde punteado: sin auditar por dentro</span></div>
<script>(()=>{const s=document.querySelector('svg.net');if(!s)return;s.addEventListener('mouseover',e=>{const n=e.target.closest('.nd');if(!n)return;const id=n.dataset.id;s.classList.add('dim');s.querySelectorAll('.on').forEach(x=>x.classList.remove('on'));n.classList.add('on');s.querySelectorAll('.ed').forEach(x=>{if(x.dataset.a===id||x.dataset.b===id){x.classList.add('on');const o=x.dataset.a===id?x.dataset.b:x.dataset.a;s.querySelector('.nd[data-id="'+o+'"]')?.classList.add('on')}})});s.addEventListener('mouseleave',()=>s.classList.remove('dim'))})();</script>`;
}

/** Lo que se vio abierto desde internet para un objetivo, si se hizo la vista externa. */
function seenFromOutside(ext, x) {
  if (!ext) return '<span class="sub">sin probar</span>';
  const t = ext.objetivos.find((o) => o.objetivo === x.ip || o.ip === x.ip || o.objetivo === x.ip?.replace(/\.$/, ''));
  if (!t) return '<span class="sub">sin probar</span>';
  const open = new Set((t.puertos || []).map((p) => p.puerto));
  return x.puertos.map((p) => (open.has(p.puerto) ? tag(SEV.high, `${p.puerto} abierto`) : tag(STATE['al-dia'], `${p.puerto} cerrado`))).join(' ');
}

export function infraSection(infra, issues = []) {
  if (!infra) return '';
  const S = infra.servidores || [];
  const red = infra.red || { nodes: [], edges: [] };
  const exp = infra.expuesto || [];
  const ext = infra.externo;
  const patches = S.reduce((a, s) => a + (s.parchesSeguridad || 0), 0);
  const noDet = S.filter((s) => !s.agentes.some((a) => DETECTION.has(a)));
  const redIssues = issues.filter((i) => i.lupa?.cat === 'red');
  const openAdmin = redIssues.filter((i) => i.severity === 'high').length;
  const rows = [...S].sort((a, b) => b.graves - a.graves || b.aMirar - a.aMirar || a.nombre.localeCompare(b.nombre)).map((s) => `<tr>
<td><b>${esc(s.nombre)}</b><div class="sub">${esc(s.ip)}${s.ipPublica ? ` · pública ${esc(s.ipPublica)}` : ''}</div></td>
<td>${esc(s.so)}<div>${s.soEstado && s.soEstado !== 'al-dia' && s.soEstado !== 'desconocido' ? pill(STATE[s.soEstado]) : ''}</div></td>
<td class="num">${s.parchesSeguridad == null ? '—' : s.parchesSeguridad ? tag(s.parchesSeguridad >= 10 ? SEV.high : SEV.medium, `${s.parchesSeguridad}`) : '0'}${s.listasViejas ? '<div class="sub">listas sin refrescar</div>' : ''}${s.reinicio ? '<div class="sub">reinicio pendiente</div>' : ''}</td>
<td>${s.automaticas ? 'Sí' : s.automaticas === false ? tag(SEV.low, 'No') : '—'}</td>
<td>${chips(s.agentes.filter((a) => DETECTION.has(a)), 'good') || tag(SEV.medium, 'Sin detección')}</td>
<td class="num">${s.graves ? tag(SEV.high, `${s.graves} graves`) : ''} ${s.aMirar ? tag(SEV.medium, `${s.aMirar} a mirar`) : ''}${!s.graves && !s.aMirar ? tag(STATE['al-dia'], 'Bien') : ''}</td></tr>`).join('');
  const expRows = exp.map((x) => `<tr><td>${esc(x.host)}</td><td>${esc(x.via)}<div class="sub w">${esc(x.ip)}</div></td><td>${x.puertos.map((p) => `${esc(p.puerto)} <span class="sub">${esc(p.servicio)}</span>`).join('<br>')}<div class="sub">grupo ${esc(x.grupo)} · ${x.abiertoATodos === false ? 'origen restringido' : '0.0.0.0/0'}</div></td><td>${x.puertos.map((p) => esc(p.escucha ?? 'nada escucha')).join('<br>')}</td><td>${seenFromOutside(ext, x)}</td></tr>`).join('');
  const name = (id) => red.nodes.find((n) => n.id === id)?.nombre || id;
  const flowRows = red.edges.filter((e) => !/^a:AWS |^a:Endpoint/.test(e.to)).map((e) => `<tr><td>${esc(name(e.from))}</td><td>${esc(name(e.to))}</td><td class="num">${esc(e.puerto)} <span class="sub">${esc(e.servicio)}</span></td><td class="sub">${esc(e.procesos.join(', '))}</td><td>${e.claro ? tag(SEV.medium, 'sin cifrar') : ''}${e.origenesInternet ? tag(SEV.medium, `${fmt(e.origenesInternet)} IP de internet`) : ''}${e.destinos?.length ? `<div class="sub">${esc(e.destinos.slice(0, 4).join(', '))}</div>` : ''}</td></tr>`).join('');
  const extRows = (ext?.objetivos || []).map((t) => `<tr><td>${esc(t.objetivo)}<div class="sub">${esc(t.ip || '')}</div></td><td>${t.error ? esc(t.error) : t.privado ? 'Solo IP internas: no se ve desde internet' : t.puertos.length ? t.puertos.map((p) => `${esc(p.puerto)}${p.tls ? ' 🔒' : ''} <span class="sub">${esc(p.servicio)}</span>`).join('<br>') : tag(STATE['al-dia'], 'nada abierto')}</td><td>${(t.puertos || []).filter((p) => p.tls).map((p) => `${esc(p.puerto)}: ${p.tls.valido ? 'válido' : 'no confiable'} hasta ${esc(p.tls.caduca)} (${esc(p.tls.emisor)})`).join('<br>') || '—'}</td><td>${(t.puertos || []).filter((p) => p.http).map((p) => `${esc(p.puerto)}: ${esc(p.http.estado)}${p.http.titulo ? ` «${esc(p.http.titulo)}»` : ''}`).join('<br>') || '—'}</td></tr>`).join('');
  return `<section><h2>Servidores y red</h2><p class="lead">${fmt(S.length)} servidores revisados por dentro (solo lectura), ${fmt(red.edges.length)} conexiones vistas entre ellos y ${fmt(exp.length)} puertas a internet según la nube.${ext ? ` Vista desde internet hecha desde ${esc(ext.desde || 'IP desconocida')}.` : ' La vista desde internet no se ha hecho.'}</p>
<div class="tiles">
${tile('Parches de seguridad pendientes', patches, `${fmt(S.filter((s) => s.parchesSeguridad).length)} servidores · ${fmt(S.filter((s) => s.listasViejas).length)} sin refrescar listas`, patches ? 'crit' : 'good')}
${tile('Sin agente de detección', noDet.length, noDet.length ? esc(noDet.map((s) => s.nombre).slice(0, 4).join(', ')) + (noDet.length > 4 ? '…' : '') : 'todos vigilados', noDet.length ? 'serious' : 'good')}
${tile('Graves en la red', openAdmin, `${fmt(redIssues.length)} avisos de red en total`, openAdmin ? 'crit' : 'good')}
${tile('Sin auditar por dentro', (infra.sinAuditar || []).length, (infra.sinAuditar || []).map((x) => esc(x.nombre)).slice(0, 3).join(', ') || 'ninguno', (infra.sinAuditar || []).length ? 'warn' : 'good')}
</div>
<h3>Cada servidor</h3><table class="t"><thead><tr><th>Servidor</th><th>Sistema</th><th>Parches seg.</th><th>Se actualiza solo</th><th>Detección</th><th>Avisos</th></tr></thead><tbody>${rows || '<tr><td colspan="6">No se ha revisado ningún servidor por dentro.</td></tr>'}</tbody></table>
${red.edges.length ? `<h3>Cómo se comunican</h3><p class="lead">Conexiones abiertas en el momento de la foto, vistas desde los dos extremos cuando ambos están revisados. Pasa el ratón por un nodo para ver solo las suyas.</p>${diagram(red, S)}
<details><summary>Ver todas las conexiones</summary><table class="t"><thead><tr><th>Desde</th><th>Hacia</th><th>Puerto</th><th>Procesos</th><th>Nota</th></tr></thead><tbody>${flowRows}</tbody></table></details>` : ''}
${exp.length ? `<h3>Puertas a internet</h3><p class="lead">Lo que la nube deja alcanzar desde internet (IP públicas con grupos abiertos y balanceadores públicos), qué hay detrás y si se vio abierto desde fuera.</p><table class="t"><thead><tr><th>Servidor</th><th>Por dónde</th><th>Puertos</th><th>Qué escucha</th><th>Desde fuera</th></tr></thead><tbody>${expRows}</tbody></table>` : ''}
${ext ? `<h3>Vista desde internet</h3><table class="t"><thead><tr><th>Objetivo</th><th>Abierto</th><th>Certificado</th><th>Web</th></tr></thead><tbody>${extRows}</tbody></table><p class="sub">Comprobado desde ${esc(ext.desde || '—')}: si esa IP está en alguna lista permitida, desde otro sitio se ve menos. Solo conexiones y peticiones normales, sin ataques.</p>` : ''}
</section>`;
}
