// El mapa del código dentro del informe: una pestaña con el mapa interactivo de floorplan (con el calor de
// Lupa), guardado comprimido (gzip + base64) en el propio fichero y descomprimido por el navegador al abrir
// la pestaña. Así el informe es un solo fichero que se abre con doble clic, sin servidor ni nada que instalar.

export const MAP_CSS = `.tabs{position:sticky;top:0;z-index:20;display:flex;gap:4px;padding:10px 16px;background:color-mix(in srgb,var(--page) 88%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--ring);justify-content:center}
.tabs button{font:600 14px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink2);background:none;border:0;border-radius:999px;padding:7px 16px;cursor:pointer}
.tabs button[aria-selected="true"]{background:var(--raise);color:var(--ink)}.tabs button:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
#tab-mapa{position:fixed;inset:51px 0 0 0;background:var(--page)}#tab-mapa iframe{width:100%;height:100%;border:0;display:block}
.link{font:inherit;font-size:13.5px;color:var(--acc);background:none;border:0;padding:0;cursor:pointer;text-align:left}.link:hover{text-decoration:underline}
#mapa-msg{position:absolute;inset:0;display:grid;place-items:center;color:var(--ink2);font-size:14px;text-align:center;padding:16px;pointer-events:none}#mapa-msg[hidden]{display:none}
@media print{.tabs,#tab-mapa{display:none!important}main{display:block!important}}`;

export function mapNav(mapa) {
  if (!mapa) return '';
  return `<nav class="tabs" role="tablist" aria-label="Partes del informe"><button type="button" role="tab" aria-selected="true" data-tab="informe">Informe</button><button type="button" role="tab" aria-selected="false" data-tab="mapa">Mapa del código</button></nav>`;
}

export function mapPanel(mapa) {
  if (!mapa) return '';
  return `<div id="tab-mapa" role="tabpanel" hidden><div id="mapa-msg">Abriendo el mapa…</div><iframe id="mapa" title="Mapa interactivo del código"></iframe></div>
<script type="application/octet-stream" id="lupa-mapa">${mapa}</script>
<script>(()=>{
const main=document.querySelector('main'),panel=document.getElementById('tab-mapa'),frame=document.getElementById('mapa'),msg=document.getElementById('mapa-msg');
let loaded=false;
async function load(){
  if(loaded)return;loaded=true;
  try{
    if(!('DecompressionStream' in window))throw new Error('este navegador no sabe descomprimir: ábrelo con Chrome, Edge, Firefox o Safari al día');
    const b=atob(document.getElementById('lupa-mapa').textContent.trim()),bytes=new Uint8Array(b.length);
    for(let i=0;i<b.length;i++)bytes[i]=b.charCodeAt(i);
    const html=await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    frame.src=URL.createObjectURL(new Blob([html],{type:'text/html'}));
    frame.addEventListener('load',()=>{msg.hidden=true},{once:true});
  }catch(e){loaded=false;msg.textContent='No se pudo abrir el mapa: '+e.message}
}
function show(tab){
  document.querySelectorAll('.tabs button').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.tab===tab)));
  main.hidden=tab!=='informe';panel.hidden=tab!=='mapa';
  if(tab==='mapa')load();
  if(location.hash!=='#'+tab)history.replaceState(null,'','#'+tab);
}
document.querySelector('.tabs').addEventListener('click',e=>{const b=e.target.closest('button[data-tab]');if(b)show(b.dataset.tab)});
document.querySelectorAll('[data-abre-mapa]').forEach(el=>el.addEventListener('click',()=>{show('mapa');scrollTo(0,0)}));
if(location.hash==='#mapa')show('mapa');
})();</script>`;
}
