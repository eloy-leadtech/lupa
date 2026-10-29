#!/usr/bin/env node
// Lupa · la vista desde internet. Mira los servidores y dominios públicos del proyecto como lo haría
// cualquiera: puertos abiertos, certificados, cabeceras y una docena de rutas delicadas. Sin ataques.
//
//   node externo.mjs <raíz> [--objetivos dominio.com,1.2.3.4]
//
// Si hay floorplan/lupa/red-aws.json (servidores-ssm.mjs), añade solas las IP públicas y los balanceadores
// públicos. Escribe floorplan/lupa/externo.json; scan.mjs y merge.mjs lo meten en el informe.
// Mira SOLO lo que es del proyecto: no lo apuntes a sistemas de otros.
import path from 'node:path';
import { readJSON, writeJSON } from './lib/util.mjs';
import { probeTarget, egressIp, PORTS } from './lib/externo.mjs';
import { loadServers } from './lib/servidores.mjs';

const argv = process.argv.slice(2);
const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const root = path.resolve(argv.find((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--')) || '.');
const red = readJSON(path.join(root, 'floorplan', 'lupa', 'red-aws.json'));
// de la red de AWS, solo lo del proyecto: las IP públicas de los servidores auditados y los balanceadores que
// llevan a ellos. En una VPC compartida, lo de otros equipos no se mira.
const audited = new Set(loadServers(path.join(root, 'floorplan', 'lupa', 'servidores')).map((h) => h.aws?.id).filter(Boolean));
const targets = [...new Set([
  ...(opt('--objetivos') || '').split(',').map((s) => s.trim()).filter(Boolean),
  ...(red?.instancias || []).filter((i) => audited.has(i.id)).map((i) => i.ipPublica).filter(Boolean),
  ...(red?.balanceadores || []).filter((b) => b.esquema === 'internet-facing' && b.destinos.some((d) => audited.has(d.destino) || (red.instanciasExternas || []).some((x) => x.id === d.destino))).map((b) => b.dns),
])];
if (!targets.length) { console.error('No hay nada que mirar: pasa --objetivos dominio,ip o recoge antes la red con servidores-ssm.mjs.'); process.exit(2); }

const t0 = Date.now();
const desde = await egressIp();
console.log(`LUPA  vista desde internet de ${targets.length} objetivo(s), ${PORTS.length} puertos cada uno, desde ${desde || 'IP desconocida'}`);
const objetivos = [];
for (const t of targets) {
  const r = await probeTarget(t, { log: (m) => console.log('  · ' + m) });
  objetivos.push(r);
  if (r.error) console.log(`  ✗ ${t}: ${r.error}`);
  else if (r.privado) console.log(`  · ${t}: solo IP internas (${r.ips.join(', ')}), no se ve desde internet`);
  else console.log(`  ✓ ${t}: ${r.puertos.length ? r.puertos.map((p) => p.puerto + (p.tls ? '🔒' : '')).join(' ') : 'nada abierto'}`);
}
writeJSON(path.join(root, 'floorplan', 'lupa', 'externo.json'), { generadoEn: new Date().toISOString(), desde, puertosProbados: PORTS, objetivos });
console.log(`✓ ${Math.round((Date.now() - t0) / 1000)} s · floorplan/lupa/externo.json. Si ${desde || 'tu IP'} está en alguna lista permitida, desde otro sitio se verá menos.`);
