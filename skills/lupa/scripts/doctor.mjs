#!/usr/bin/env node
// Lupa · comprobar herramientas. Dice qué escáneres hay, con qué versión, y cómo instalar los que faltan.
import { findAll, installHint } from './lib/tools.mjs';

const [major] = process.versions.node.split('.').map(Number);
console.log(`node      ${process.versions.node}${major < 18 ? '  ⚠ hace falta Node 18 o más' : ''}`);
const tools = findAll();
let missing = 0;
for (const [name, t] of Object.entries(tools)) {
  if (t) console.log(`${name.padEnd(9)} ${t.version}  (${t.path})`);
  else { missing++; console.log(`${name.padEnd(9)} FALTA${name === 'git' ? '' : `  →  ${installHint(name)}`}`); }
}
console.log(missing ? `\n${missing} herramienta(s) sin instalar: Lupa funciona sin ellas, pero esa parte se queda sin mirar.` : '\n✓ todo listo');
process.exit(0);
