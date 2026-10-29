#!/usr/bin/env node
// Lupa · comprobar herramientas. Dice qué escáneres hay, con qué versión, y cómo instalar los que faltan.
//
//   node doctor.mjs              solo mira
//   node doctor.mjs --instalar   descarga los que falten (versión fijada, comprobada por SHA-256)
//                                en ~/.cache/lupa/bin, sin tocar el sistema
import { findAll, installHint } from './lib/tools.mjs';
import { installTools, toolsHome, MANIFEST, isPinned } from './lib/install.mjs';

const [major] = process.versions.node.split('.').map(Number);
console.log(`node      ${process.versions.node}${major < 20 ? '  ⚠ hace falta Node 20 o más' : ''}`);
let tools = findAll();

if (process.argv.includes('--instalar')) {
  // también si hay otra versión en el sistema: así todos los equipos escanean con lo mismo y los informes se comparan
  const missing = Object.keys(MANIFEST).filter((n) => n !== '_nota' && !isPinned(tools[n]));
  if (missing.length) {
    console.log(`Descargo en ${toolsHome()}: ${missing.map((n) => `${n} ${MANIFEST[n].version}`).join(', ')}`);
    const res = await installTools(missing, { log: (m) => console.log('  · ' + m) });
    for (const [n, r] of Object.entries(res)) console.log(`  ${n.padEnd(9)} ${r === 'ok' ? '✓ instalado' : '✗ ' + r}`);
    tools = findAll();
  }
}

let missing = 0;
for (const [name, t] of Object.entries(tools)) {
  if (t) console.log(`${name.padEnd(9)} ${t.version}  (${t.path})`);
  else { missing++; console.log(`${name.padEnd(9)} FALTA${name === 'git' ? '' : `  →  ${installHint(name)}`}`); }
}
console.log(missing ? `\n${missing} herramienta(s) sin instalar: Lupa funciona sin ellas, pero esa parte se queda sin mirar.` : '\n✓ todo listo');
process.exit(0);
