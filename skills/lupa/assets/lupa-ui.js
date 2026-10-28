// Lupa dentro del mapa de floorplan: mapa de calor sobre las tarjetas, botón «Lupa» con el
// resumen por categorías, la superficie de ataque (endpoints) y lo que dijo la IA de cada uno.
// Habla con el visor solo a través de window.Floorplan, igual que las extensiones de floorplan.
(() => {
  const SC = window.Floorplan;
  const L = SC && SC.graph.lupa;
  if (!L) return;
  const { h } = SC;
  const COLOR = { high: '#ff6b6b', medium: '#f0c36b', low: '#8ab4f8' };
  const WORD = { high: 'graves', medium: 'a mirar', low: 'menores' };
  const issues = SC.graph.health?.issues || [];
  const lupaIssues = issues.filter((i) => String(i.id).startsWith('lupa:'));
  const norm = (id) => (id.startsWith('m:') ? 'f:' + id.slice(2) : id);

  SC.icons.lupa = '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5 21 21"/>';

  // calor de cada tarjeta: los avisos de lo que tiene dentro, contados por severidad
  const heat = new Map();
  for (const i of issues) for (const it of i.items || []) {
    if (!SC.exists(it)) continue;
    for (const id of new Set([it, ...SC.chain(it)])) {
      const x = heat.get(id) || { high: 0, medium: 0, low: 0 };
      x[i.severity]++; heat.set(id, x);
    }
  }

  const style = document.createElement('style');
  style.textContent = `
    .card.lp-h { box-shadow: inset 0 0 0 2px ${COLOR.high}, 0 0 28px -8px ${COLOR.high}; }
    .card.lp-m { box-shadow: inset 0 0 0 2px ${COLOR.medium}, 0 0 22px -10px ${COLOR.medium}; }
    .card.lp-l { box-shadow: inset 0 0 0 1.5px color-mix(in srgb, ${COLOR.low} 70%, transparent); }
    .lp-b { position: absolute; top: 10px; right: 10px; min-width: 22px; height: 22px; padding: 0 7px; border-radius: 11px; font: 600 12px/22px Inter, sans-serif; text-align: center; color: #1a0d0d; }
    .lp-b.lp-h { background: ${COLOR.high}; box-shadow: none; } .lp-b.lp-m { background: ${COLOR.medium}; box-shadow: none; } .lp-b.lp-l { background: ${COLOR.low}; box-shadow: none; }
    .card.lp-d { box-shadow: inset 0 0 0 2px #9085e9, 0 0 24px -8px #9085e9; } .lp-b.lp-d { background: #9085e9; color: #120d2a; box-shadow: none; }
    .lp-modes { display: inline-flex; background: var(--raise); border-radius: 10px; padding: 3px; gap: 2px; margin-top: 10px; }
    .lp-modes button { border: 0; background: transparent; color: var(--text-2); font: 500 12.5px Inter, sans-serif; padding: 5px 10px; border-radius: 8px; cursor: pointer; }
    .lp-modes button.on { background: var(--surface-hover, rgba(255,255,255,.08)); color: var(--text-1, #fff); }
    #btn-lupa .badge { background: ${COLOR.high}; color: #1a0d0d; }
    #btn-lupa.off svg.i { opacity: .5; }
    .lp-k { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 10px; }
    .lp-k div { padding: 10px 12px; border-radius: 14px; background: var(--raise); }
    .lp-k b { display: block; font-size: 20px; font-weight: 600; }
    .lp-k span { color: var(--text-3); font-size: 12px; }
    .lp-v { margin-top: 10px; padding: 10px 12px; border-radius: 14px; font-size: 13px; line-height: 1.55; background: color-mix(in srgb, var(--c) 10%, transparent); }
    .lp-v .lp-t { color: var(--c); font-size: 11.5px; font-weight: 600; margin-bottom: 3px; }
    .lp-sw { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
    .lp-sw .btn { height: 30px; padding: 0 12px; font-size: 12.5px; gap: 6px; }
    .lp-small { color: var(--text-3); font-size: 12px; line-height: 1.5; margin-top: 8px; }
  `;
  document.head.appendChild(style);

  // capa de datos personales: cuántos ficheros con datos de personas hay dentro de cada tarjeta
  const D = L.datos?.ficheros || [];
  const pii = new Map();
  for (const d of D) {
    const id = 'f:' + d.fichero; if (!SC.exists(id)) continue;
    for (const x of new Set([id, ...SC.chain(id)])) { const v = pii.get(x) || { n: 0, especial: 0 }; v.n++; if (d.especial) v.especial++; pii.set(x, v); }
  }
  // modo del mapa: riesgo (calor por severidad), datos (dónde viven los datos personales) o nada
  let mode = SC.store.get('lupa-modo', 'riesgo');
  let heatOn = mode !== 'nada';
  function paint() {
    for (const [id, g] of SC.state.chipEls || []) {
      const card = g.querySelector('.card'); if (!card) continue;
      card.classList.remove('lp-h', 'lp-m', 'lp-l', 'lp-d');
      card.querySelector('.lp-b')?.remove();
      if (mode === 'datos') {
        const v = pii.get(norm(id)); if (!v) continue;
        card.classList.add('lp-d');
        const b = document.createElement('span');
        b.className = 'lp-b lp-d'; b.textContent = `DP ${v.n}`; b.title = `${v.n} ficheros con datos personales${v.especial ? ` (${v.especial} con categorías especiales)` : ''}`;
        card.appendChild(b);
        continue;
      }
      if (!heatOn) continue;
      const x = heat.get(norm(id)); if (!x) continue;
      const s = x.high ? 'high' : x.medium ? 'medium' : 'low';
      const cls = { high: 'lp-h', medium: 'lp-m', low: 'lp-l' }[s];
      card.classList.add(cls);
      const b = document.createElement('span');
      b.className = 'lp-b ' + cls; b.textContent = String(x[s]); b.title = `${x.high} graves · ${x.medium} a mirar · ${x.low} menores`;
      card.appendChild(b);
    }
  }
  SC.on('render', () => setTimeout(paint, 0));

  // ---------------------------------------------------------------- tableros
  function board(title, question, list, notes) {
    const items = [];
    const seen = new Set();
    for (const [id, note] of list) if (SC.exists(id) && !seen.has(id)) { seen.add(id); items.push({ id, note: note || notes || '' }); }
    if (!items.length) { SC.toast('Nada de esto está en el mapa.'); return; }
    SC.showBoard({ kind: 'Lupa', icon: 'lupa', title, question, items: items.slice(0, 60) });
  }
  const showCat = (cat) => {
    const list = lupaIssues.filter((i) => i.lupa?.cat === cat);
    board(L.nombres[cat] || cat, `${list.length} avisos. Las tarjetas en rojo son graves.`, list.flatMap((i) => (i.items || []).map((it) => [it, `${i.severity === 'high' ? '🔴' : i.severity === 'medium' ? '🟠' : '🔵'} ${i.title}`])));
  };
  const E = L.endpoints || [];
  const shouldNot = E.filter((e) => e.deberiaSerPublico === false && e.publico !== false);
  const pub = E.filter((e) => e.publico === true);
  const pending = E.filter((e) => !e.severidad);
  const epNote = (e) => `${e.metodo} ${e.ruta}${e.motivo ? ` — ${e.motivo}` : ''}`;
  const showEp = (title, list) => board(title, `${list.length} endpoints`, list.map((e) => [e.ref, epNote(e)]));

  // ---------------------------------------------------------------- panel
  const total = (s) => lupaIssues.filter((i) => i.severity === s).length;
  function panelHtml() {
    const cats = Object.keys(L.nombres).filter((c) => L.categorias[c]);
    const R = L.revision || {};
    return `<div class="sec"><h3>Lupa · seguridad de todo el proyecto</h3>
      <div class="lp-k"><div><b style="color:${COLOR.high}">${total('high')}</b><span>graves</span></div><div><b style="color:${COLOR.medium}">${total('medium')}</b><span>a mirar</span></div><div><b style="color:${COLOR.low}">${total('low')}</b><span>menores</span></div></div>
      <div class="lp-small">IA: ${R.endpoints || 0} de ${R.endpointsTotal || 0} endpoints revisados · ${R.descartados || 0} falsos positivos quitados</div>
      <div class="lp-modes" role="group" aria-label="Qué pinta el mapa">${[['riesgo', 'Riesgo'], ['datos', 'Datos personales'], ['nada', 'Nada']].map(([k, n]) => `<button data-lp-mode="${k}" class="${mode === k ? 'on' : ''}">${n}</button>`).join('')}</div>
      <div class="lp-sw"><a class="btn soft" href="lupa/informe.html" target="_blank" rel="noopener">${SC.iconI('lupa')}Abrir el informe</a></div></div>
      ${(L.kev || []).length || L.tecnologia?.sinSoporte?.length || D.length ? `<div class="sec"><h3>Lo más vigilado</h3><div class="list">
        ${(L.kev || []).length ? `<a class="row" data-lp-x="kev"><span class="dot" style="background:${COLOR.high}"></span><span class="rt"><div class="rn">Explotadas ahora (KEV)</div><div class="rd">${L.kev.length} librerías con CVE que se usan en ataques reales</div></span><span class="rc">${SC.iconI('right')}</span></a>` : ''}
        ${L.tecnologia?.sinSoporte?.length ? `<a class="row" data-lp-x="eol"><span class="dot" style="background:${COLOR.medium}"></span><span class="rt"><div class="rn">Tecnología sin soporte</div><div class="rd">${L.tecnologia.sinSoporte.length} piezas sin parches de seguridad</div></span><span class="rc">${SC.iconI('right')}</span></a>` : ''}
        ${D.length ? `<a class="row" data-lp-x="datos"><span class="dot" style="background:#9085e9"></span><span class="rt"><div class="rn">Datos personales</div><div class="rd">${D.length} modelos o tablas · ${Object.keys(L.datos.resumen || {}).slice(0, 4).join(', ')}</div></span><span class="rc">${SC.iconI('right')}</span></a>` : ''}
      </div></div>` : ''}
      <div class="sec"><h3>Por tipo</h3><div class="list">${cats.map((c) => {
        const k = L.categorias[c]; const s = k.high ? 'high' : k.medium ? 'medium' : 'low';
        return `<a class="row" data-lp-cat="${h(c)}"><span class="dot" style="background:${COLOR[s]}"></span><span class="rt"><div class="rn">${h(L.nombres[c])}</div><div class="rd">${['high', 'medium', 'low'].filter((x) => k[x]).map((x) => `${k[x]} ${WORD[x]}`).join(' · ')}</div></span><span class="rc">${SC.iconI('right')}</span></a>`;
      }).join('')}</div></div>
      <div class="sec"><h3>Superficie de ataque <span class="c">${E.length}</span></h3><div class="list">
        <a class="row" data-lp-ep="no"><span class="dot" style="background:${COLOR.high}"></span><span class="rt"><div class="rn">Abiertos y no deberían</div><div class="rd">${shouldNot.length} endpoints que cualquiera puede llamar</div></span><span class="rc">${SC.iconI('right')}</span></a>
        <a class="row" data-lp-ep="pub"><span class="dot" style="background:${COLOR.medium}"></span><span class="rt"><div class="rn">Públicos</div><div class="rd">${pub.length} sin login (bien o mal, según el motivo)</div></span><span class="rc">${SC.iconI('right')}</span></a>
        ${pending.length ? `<a class="row" data-lp-ep="pend"><span class="dot" style="background:var(--text-3)"></span><span class="rt"><div class="rn">Sin revisar por la IA</div><div class="rd">${pending.length} pendientes</div></span><span class="rc">${SC.iconI('right')}</span></a>` : ''}
      </div></div>
      <div class="sec"><div class="lp-small">Herramientas: ${Object.entries(L.herramientas || {}).map(([n, v]) => `${h(n)} ${h(String(v).split(' ').pop())}`).join(' · ')}<br>Informe para tickets: floorplan/lupa/informe.md</div></div>`;
  }
  function bindPanel(el) {
    el.querySelectorAll('[data-lp-cat]').forEach((x) => x.addEventListener('click', (ev) => { ev.preventDefault(); showCat(x.dataset.lpCat); }));
    el.querySelectorAll('[data-lp-ep]').forEach((x) => x.addEventListener('click', (ev) => {
      ev.preventDefault();
      const k = x.dataset.lpEp;
      if (k === 'no') showEp('Abiertos y no deberían', shouldNot);
      else if (k === 'pub') showEp('Endpoints públicos', pub);
      else showEp('Sin revisar por la IA', pending);
    }));
    el.querySelectorAll('[data-lp-mode]').forEach((x) => x.addEventListener('click', () => { mode = x.dataset.lpMode; heatOn = mode !== 'nada'; SC.store.set('lupa-modo', mode); paint(); openPanel(); btn.classList.toggle('off', !heatOn); }));
    el.querySelectorAll('[data-lp-x]').forEach((x) => x.addEventListener('click', (ev) => {
      ev.preventDefault();
      const k = x.dataset.lpX;
      if (k === 'kev') board('Explotadas ahora (KEV)', 'Librerías con CVE del catálogo KEV de la CISA: lo primero que hay que parchear.', L.kev.map((f) => ['f:' + f.fichero, `${f.paquete} ${f.version} · ${f.cves.join(', ')}${f.arreglo ? ` · arreglado en ${f.arreglo}` : ''}`]));
      else if (k === 'eol') board('Tecnología sin soporte', 'Piezas que ya no reciben parches de seguridad.', L.tecnologia.sinSoporte.map((c) => ['f:' + c.fichero, `${c.nombre} ${c.version} (${c.tipo})${c.fin ? ` · sin soporte desde ${c.fin}` : ''}`]));
      else { mode = 'datos'; SC.store.set('lupa-modo', mode); board('Datos personales', 'Dónde se guardan datos de personas. «Especial» = salud, antecedentes, biometría u origen (RGPD art. 9).', D.map((d) => ['f:' + d.fichero, `${d.tipos.join(', ')}${d.especial ? ' · especial' : ''}${d.cifrado ? '' : ' · sin pistas de cifrado'}`])); }
    }));
  }
  const openPanel = () => SC.showPanel(panelHtml(), bindPanel);

  const btn = SC.addHeaderButton({ id: 'btn-lupa', label: 'Lupa', icon: 'lupa', title: 'Seguridad de todo el proyecto', onClick: openPanel });
  if (!heatOn) btn.classList.add('off');
  if (total('high')) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = total('high') > 99 ? '99+' : String(total('high')); btn.appendChild(b); }

  // un endpoint seleccionado: lo que dijo la IA
  SC.addPanelSection('item', (id) => {
    const e = E.find((x) => x.ref === norm(id));
    if (!e) return '';
    if (!e.severidad) return { top: true, html: `<div class="sec"><div class="lp-v" style="--c:var(--text-3)"><div class="lp-t">Lupa · sin revisar</div>La IA todavía no ha mirado este endpoint.</div></div>` };
    const c = e.severidad === 'alta' ? COLOR.high : e.severidad === 'media' ? COLOR.medium : e.severidad === 'baja' ? COLOR.low : '#6fd7a8';
    const who = e.publico === true ? 'Público (sin login)' : e.publico === false ? 'Pide login' : 'Acceso dudoso';
    const ok = e.deberiaSerPublico === false && e.publico !== false ? ' · no debería ser público' : '';
    return { top: true, html: `<div class="sec"><div class="lp-v" style="--c:${c}"><div class="lp-t">Lupa · ${h(who)}${h(ok)}</div>${h(e.motivo || 'Sin problemas.')}${e.datos?.length ? `<div class="lp-small">Datos que suelta: ${h(e.datos.join(', '))}</div>` : ''}</div></div>` };
  });

  SC.addPanelSection('overview', () => ({
    top: true,
    html: `<div class="sec"><h3>Lupa</h3><div class="list"><a class="row" data-lp-open><span class="dot" style="background:${total('high') ? COLOR.high : total('medium') ? COLOR.medium : '#6fd7a8'}"></span><span class="rt"><div class="rn">${total('high')} graves · ${total('medium')} a mirar · ${total('low')} menores</div><div class="rd">${E.length} endpoints · ${shouldNot.length} abiertos que no deberían</div></span><span class="rc">${SC.iconI('right')}</span></a></div></div>`,
    bind: (el) => el.querySelector('[data-lp-open]')?.addEventListener('click', (ev) => { ev.preventDefault(); openPanel(); }),
  }));

  window.Lupa = { heat, paint, open: openPanel };
})();
