// Piezas del informe que comparten sus secciones: escapar texto, las gravedades, píldoras y números.
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const SEV = {
  high: { word: 'Grave', css: 'crit', icon: '▲' },
  medium: { word: 'A mirar', css: 'serious', icon: '◆' },
  low: { word: 'Menor', css: 'warn', icon: '●' },
};
export const STATE = {
  'sin-soporte': { word: 'Sin soporte', css: 'crit', icon: '▲' },
  'caduca-pronto': { word: 'Caduca pronto', css: 'serious', icon: '◆' },
  'sin-mantenimiento': { word: 'Sin mantenimiento', css: 'serious', icon: '◆' },
  desactualizado: { word: 'Desactualizado', css: 'warn', icon: '●' },
  'al-dia': { word: 'Con soporte', css: 'good', icon: '✓' },
  desconocido: { word: 'Sin datos', css: 'muted', icon: '·' },
};
export const pill = (s) => `<span class="pill ${s.css}"><span aria-hidden="true">${s.icon}</span> ${esc(s.word)}</span>`;
/** Una píldora con texto propio y el color de una gravedad o estado. */
export const tag = (base, word) => pill({ ...base, word });
export const fmt = (n) => Number(n || 0).toLocaleString('es-ES');
export const tile = (label, value, sub, css = '') => `<div class="tile ${css}"><div class="tl">${esc(label)}</div><div class="tv">${typeof value === 'number' ? fmt(value) : esc(value)}</div><div class="sub">${sub}</div></div>`;
