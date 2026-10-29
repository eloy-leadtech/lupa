#!/usr/bin/env node
// Lupa · arquitectura. Prepara las pistas para que Claude proponga cambios de estructura: los de seguridad,
// que quitan avisos de raíz, y los de mantenibilidad. Escribe floorplan/lupa/arquitectura/pistas.md y deja
// propuestas.json listo para rellenar. Si nada ha cambiado desde la última vez, lo dice y no hay que rehacer nada.
//
//   node arquitectura.mjs <raíz>
//
// Funciona con solo el mapa (floorplan/graph.json); con una pasada de Lupa (scan.mjs y la revisión) las pistas
// de seguridad salen completas.
import path from 'node:path';
import { readJSON } from './lib/util.mjs';
import { loadAnswers, reviewOf, triageKey } from './lib/review.mjs';
import { endpointFindings } from './lib/issues.mjs';
import { signals, writeArchWorksheet, archDir } from './lib/arquitectura.mjs';

const root = path.resolve(process.argv.slice(2).find((a) => !a.startsWith('--')) || '.');
const lupaDir = path.join(root, 'floorplan', 'lupa');
const graph = readJSON(path.join(root, 'floorplan', 'graph.json'));
if (!graph) { console.error('No hay floorplan/graph.json: haz antes el mapa (paso «El mapa» del SKILL de Lupa).'); process.exit(2); }

const found = readJSON(path.join(lupaDir, 'hallazgos.json'));
const answers = loadAnswers(path.join(lupaDir, 'revision'));
// lo mismo que pinta merge.mjs: sin los falsos positivos y con los endpoints revisados
const findings = (found?.hallazgos || []).filter((f) => answers.findings.get(triageKey(f))?.veredicto !== 'falso-positivo');
const endpoints = (readJSON(path.join(lupaDir, 'superficie.json'), { endpoints: [] }).endpoints || []).map((e) => ({ ...e, shown: e.realPath || e.path, revision: reviewOf(answers, e) }));
findings.push(...endpointFindings(endpoints));
const tech = readJSON(path.join(lupaDir, 'tecnologia.json'));

const s = signals({ root, graph, findings, endpoints, datos: readJSON(path.join(lupaDir, 'datos.json')), aiFiles: tech?.ficherosIA || [] });
const r = writeArchWorksheet(root, s);
const rel = path.relative(root, archDir(root)).split(path.sep).join('/');
const S = s.seguridad, G = s.general;
console.log(`LUPA  arquitectura de ${graph.project?.name || path.basename(root)}${found ? '' : ' (sin pasada de Lupa: las pistas de seguridad salen casi vacías)'}`);
console.log(`  seguridad       ${S.repetidos.length} reglas repetidas en 3 sitios o más · ${S.endpoints.abiertosQueNoDeberian.length} endpoints abiertos que no deberían · ${S.endpoints.conIdentificadorYProblema.length} con id y problema · ${S.ia.ficheros.length} ficheros con IA · ${S.datosPersonales.sinCifrar.length} modelos delicados sin cifrar`);
console.log(`  mantenibilidad  ${G.calientes.length} ficheros calientes · ${G.enredos.length} pares de módulos enredados · ${G.pruebas.modulosSinPruebas.length} módulos sin pruebas · ${s.decididos.length} ADR`);
if (r.estado === 'al-dia') console.log(`✓ al día: las pistas no han cambiado y ${rel}/propuestas.json ya está hecho. No hay que rehacer nada.`);
else console.log(`➜ ${r.estado === 'cambiada' ? 'las pistas cambiaron desde la última vez: revisa las propuestas que hay' : 'pendiente'}: lee ${rel}/pistas.md y rellena ${rel}/propuestas.json (sección «Arquitectura» del SKILL). Después, merge.mjs.`);
