// Pruebas de servidores, red, vista desde internet y entrega del informe: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { serverFindings, loadServers } from '../skills/lupa/scripts/lib/servidores.mjs';
import { networkModel, exposure, networkFindings } from '../skills/lupa/scripts/lib/red.mjs';
import { externalFindings } from '../skills/lupa/scripts/lib/externo.mjs';
import { cleanRemote, deliveryInfo } from '../skills/lupa/scripts/lib/entrega.mjs';
import { toIssues, makeMapper } from '../skills/lupa/scripts/lib/issues.mjs';
import { buildReport } from '../skills/lupa/scripts/lib/report.mjs';
import { infraSection } from '../skills/lupa/scripts/lib/report-infra.mjs';

/** Una foto de servidor mínima y sana; cada prueba le cambia lo que necesita. */
const host = (over = {}) => ({
  lupa_servidor: 1, nombre: 'web-01', ipPrivada: '10.0.0.1', ipPublica: '',
  equipo: { nombre: 'web-01', so: 'Ubuntu 24.04 LTS', so_id: 'ubuntu', so_version: '24.04', ips: ['10.0.0.1'], arrancado_hace_dias: 3, root: true },
  parches: { gestor: 'apt', pendientes: 0, seguridad: 0, reinicio_pendiente: false, automaticas: true, listas_hace_dias: 0.5 },
  escucha: [], entradas: [], salidas: [], cortafuegos: {},
  ssh: { instalado: true, activo: true, config: { passwordauthentication: 'no', permitrootlogin: 'prohibit-password', x11forwarding: 'no' } },
  usuarios: { uid0: ['root'], sudo_sin_contrasena: [{ quien: 'ubuntu', fichero: '/etc/sudoers.d/90-cloud-init-users', todo: true }] },
  contenedores: [], servicios: { en_marcha: [], agentes: ['Wazuh', 'AWS SSM'] }, endurecimiento: { hora_sincronizada: true },
  ficheros: { lista: [], completo: true }, ...over,
});
const rules = (fs_) => Object.fromEntries(fs_.map((f) => [f.rule, f.severity]));

test('un servidor sano no da avisos, y el sudo sin contraseña de la cuenta de la nube no cuenta', () => {
  assert.deepEqual(serverFindings(host()), []);
});

test('servidor: parches, listas sin refrescar, SSH con contraseña, root extra y sin detección', () => {
  const r = rules(serverFindings(host({
    parches: { gestor: 'apt', pendientes: 40, seguridad: 12, reinicio_pendiente: true, automaticas: false, listas_hace_dias: 59 },
    ssh: { instalado: true, activo: true, config: { passwordauthentication: 'yes', permitrootlogin: 'yes', x11forwarding: 'yes' } },
    usuarios: { uid0: ['root', 'toor'], sudo_sin_contrasena: [{ quien: 'deploy', fichero: '/etc/sudoers.d/deploy', todo: true }] },
    servicios: { en_marcha: [], agentes: ['AWS SSM'] },
  })));
  assert.equal(r['parches-seguridad'], 'high');
  assert.equal(r['listas-viejas'], 'medium');
  assert.equal(r['sin-automaticas'], 'medium');
  assert.equal(r['reinicio-pendiente'], 'low');
  assert.equal(r['ssh-contrasena'], 'high');
  assert.equal(r['ssh-root'], 'high');
  assert.equal(r['uid0'], 'high');
  assert.equal(r['sudo-sin-contrasena'], 'medium');
  assert.equal(r['sin-deteccion'], 'medium');
});

test('servidor: contenedores peligrosos, base de datos publicada y secretos legibles por todos (las plantillas no cuentan)', () => {
  const fs_ = serverFindings(host({
    contenedores: [
      { nombre: 'db', imagen: 'postgres:16-alpine', privilegiado: false, usuario: 'root', puertos: [{ ip: '0.0.0.0', puerto: 5432 }], socket_docker: false, monta_raiz: false },
      { nombre: 'agente', imagen: 'repo/agente:latest', privilegiado: true, usuario: 'root', puertos: [], socket_docker: true, monta_raiz: true },
    ],
    escucha: [{ proto: 'tcp', ip: '0.0.0.0', puerto: 5432, proceso: 'docker-proxy' }, { proto: 'tcp', ip: '0.0.0.0', puerto: 6379, proceso: 'redis-server' }],
    ficheros: { completo: true, lista: [
      { ruta: '/opt/app/.env', modo: '0o644', legible_por_todos: true, clave_privada: false },
      { ruta: '/opt/app/.env.example', modo: '0o644', legible_por_todos: true, clave_privada: false },
    ] },
  }));
  const r = rules(fs_);
  assert.equal(r['contenedor-bd-abierta'], 'medium');
  assert.equal(r['contenedor-privilegiado'], 'high');
  assert.equal(r['contenedor-socket'], 'medium');
  assert.equal(r['contenedor-latest'], 'low');
  assert.equal(r['escucha-6379'], 'high', 'Redis fuera de Docker en todas las interfaces');
  assert.equal(r['escucha-5432'], undefined, 'el 5432 ya lo cuenta el contenedor: no se repite');
  const leak = fs_.find((f) => f.rule === 'ficheros-legibles');
  assert.equal(leak.severity, 'high');
  assert.ok(leak.title.includes('/opt/app/.env') && !leak.detail.includes('.example'));
});

test('loadServers solo lee fotos de Lupa y les pone el nombre de AWS', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-srv-'));
  fs.writeFileSync(path.join(d, 'a.json'), JSON.stringify({ ...host(), aws: { nombre: 'Web pública', ipPrivada: '10.0.0.9', ipPublica: '1.2.3.4' } }));
  fs.writeFileSync(path.join(d, 'basura.json'), '{"otra":"cosa"}');
  const s = loadServers(d);
  assert.equal(s.length, 1);
  assert.equal(s[0].nombre, 'Web pública');
  assert.equal(s[0].ipPublica, '1.2.3.4');
});

test('red: una conexión vista desde los dos extremos es una; los contenedores locales no son vecinos; el proxy no es tráfico en claro', () => {
  const a = host({ nombre: 'app', ipPrivada: '10.0.0.1', contenedores: [{ nombre: 'x', imagen: 'x:1', puertos: [] }],
    salidas: [{ ip: '10.0.0.2', puerto: 5432, proceso: 'node', publica: false }, { ip: '172.18.0.3', puerto: 9001, proceso: 'docker-proxy', publica: false },
      { ip: '10.0.0.3', puerto: 80, proceso: 'node', publica: false }, { ip: '10.0.0.2', puerto: 6379, proceso: 'node', publica: false }, { ip: '8.8.8.8', puerto: 443, proceso: 'node', publica: true }] });
  const b = host({ nombre: 'db', ipPrivada: '10.0.0.2', equipo: { ...host().equipo, ips: ['10.0.0.2'] },
    entradas: [{ puerto: 5432, proceso: 'postgres', pares_privados: ['10.0.0.1', '10.9.9.9'], privados_total: 2, publicos_total: 0 }, { puerto: 22, proceso: 'sshd', pares_privados: [], privados_total: 0, publicos_total: 7 }] });
  const proxy = host({ nombre: 'proxy', ipPrivada: '10.0.0.3', equipo: { ...host().equipo, ips: ['10.0.0.3'] }, entradas: [{ puerto: 80, proceso: 'squid', pares_privados: ['10.0.0.1'], privados_total: 1, publicos_total: 0 }] });
  const m = networkModel([a, b, proxy]);
  const e = (from, to, p) => m.edges.find((x) => x.from === from && x.to === to && x.puerto === p);
  const pg = e('h:app', 'h:db', 5432);
  assert.deepEqual(pg.vistoDesde.sort(), ['app', 'db']);
  assert.equal(m.edges.filter((x) => x.puerto === 5432 && x.from === 'h:app').length, 1);
  assert.ok(!m.nodes.some((n) => n.nombre === '172.18.0.3'), 'IP de un contenedor del propio servidor');
  assert.ok(m.nodes.some((n) => n.tipo === 'desconocido' && n.nombre === '10.9.9.9'));
  assert.equal(e('internet', 'h:db', 22).origenesInternet, 7);
  assert.equal(e('h:app', 'h:proxy', 80).claro, null, 'un proxy de salida lleva TLS dentro');
  assert.equal(e('h:app', 'h:db', 6379).claro, 'Redis');
  const f = rules(networkFindings([a, b, proxy], m, []));
  assert.equal(f['trafico-en-claro'], 'medium');
  assert.equal(f['ip-sin-identificar'], 'low');
});

test('exposición: IP pública con SSH abierto a 0.0.0.0/0 es grave; un balanceador manda cada puerto solo a su grupo de destino', () => {
  const web = host({ nombre: 'web', aws: { id: 'i-web' }, escucha: [{ proto: 'tcp', ip: '0.0.0.0', puerto: 22, proceso: 'sshd' }, { proto: 'tcp', ip: '0.0.0.0', puerto: 443, proceso: 'nginx' }] });
  const awsNet = {
    instancias: [{ id: 'i-web', nombre: 'web' }, { id: 'i-api', nombre: 'api' }],
    interfaces: [{ ip: '10.0.0.1', ips: ['10.0.0.1'], ipPublica: '1.2.3.4', instancia: 'i-web', grupos: ['sg-1'] }],
    gruposSeguridad: [{ id: 'sg-1', nombre: 'web-sg', entradas: [{ proto: 'tcp', desde: 22, hasta: 22, origenes: ['0.0.0.0/0'] }, { proto: 'tcp', desde: 443, hasta: 443, origenes: ['0.0.0.0/0'] }] },
      { id: 'sg-lb', nombre: 'lb', entradas: [{ proto: 'tcp', desde: 443, hasta: 443, origenes: ['0.0.0.0/0'] }] }],
    balanceadores: [{ nombre: 'alb', esquema: 'internet-facing', dns: 'alb.example', grupos: ['sg-lb'],
      escuchas: [{ puerto: 443, proto: 'HTTPS', grupos: ['tg-api'] }], destinos: [{ destino: 'i-api', puerto: 8000, grupo: 'tg-api' }, { destino: 'i-web', puerto: 80, grupo: 'tg-web' }] }],
  };
  const x = exposure([web], awsNet);
  const ssh = x.find((e) => e.via === 'IP pública' && e.rango === '22');
  assert.equal(ssh.puertos[0].escucha, 'sshd');
  const lb = x.find((e) => e.via === 'balanceador alb');
  assert.equal(lb.host, 'api', 'el 443 del balanceador va al grupo tg-api, no a web');
  const f = networkFindings([web], networkModel([web], awsNet), x);
  assert.ok(f.some((y) => y.rule === 'expuesto-admin' && y.severity === 'high' && /SSH/.test(y.title)));
  assert.ok(f.some((y) => y.rule === 'expuesto-web' && y.host === 'api'));
});

test('vista desde internet: base de datos abierta, certificado caducado, .git publicado y login sin cifrar', () => {
  const r = rules(externalFindings({ desde: '5.6.7.8', objetivos: [{ objetivo: 'app.example', ip: '1.2.3.4', puertos: [
    { puerto: 3306, servicio: 'MySQL', banner: '' },
    { puerto: 443, servicio: 'HTTPS', tls: { valido: false, autofirmado: false, dias: -3, caduca: '2026-10-26', protocolo: 'TLSv1.3' }, http: { estado: 200, titulo: 'App', cabeceras: {}, cookies: [{ nombre: 'sid', secure: false, httponly: true }], rutas: [{ ruta: '/.git/HEAD', que: 'el repo', sev: 'high' }] } },
    { puerto: 80, servicio: 'HTTP', http: { estado: 200, titulo: 'Admin login', cabeceras: { server: 'nginx/1.18.0' }, cookies: [], rutas: [] } },
  ] }, { objetivo: 'interno.example', privado: true, ips: ['10.0.0.5'] }] }));
  assert.equal(r['internet-3306'], 'high');
  assert.equal(r['tls-caducado'], 'high');
  assert.equal(r['ruta-/.git/HEAD'], 'high');
  assert.equal(r['http-en-claro'], 'medium');
  assert.equal(r['cabeceras'], 'low');
  assert.equal(r['cookies'], 'low');
  assert.equal(r['version-visible'], 'low');
});

test('los avisos de un servidor se agrupan en su tarjeta con el peor de titular, sin «línea 1»', () => {
  const fs_ = serverFindings(host({ parches: { gestor: 'apt', pendientes: 30, seguridad: 20, automaticas: true, listas_hace_dias: 1 }, ssh: { instalado: true, activo: true, config: { x11forwarding: 'yes' } } }));
  const [issue] = toIssues(fs_, makeMapper({ files: [], routes: [] }));
  assert.match(issue.title, /^20 parches de seguridad sin aplicar en web-01 \(y 1 aviso más\)$/);
  assert.ok(!/línea/.test(issue.detail));
});

test('entrega: la URL del remoto pierde las credenciales y la cobertura dice lo que falta', () => {
  assert.equal(cleanRemote('https://ghp_abc123@github.com/o/r.git'), 'https://github.com/o/r.git');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-ent-'));
  fs.mkdirSync(path.join(root, 'floorplan', 'lupa', 'revision'), { recursive: true });
  fs.writeFileSync(path.join(root, 'floorplan', 'lupa', 'revision', 'lote-01.json'), JSON.stringify({ hallazgos: [{ id: 'x', veredicto: '' }] }));
  const e = deliveryInfo({ root, graph: { project: { name: 'App' }, meta: { repos: [] } }, found: { herramientas: { trivy: '0.75.0' }, avisos: ['falta gitleaks: sin él no se mira esa parte'] },
    answers: { findings: new Map() }, endpoints: [{ revision: null }], discarded: [], infra: { servidores: [{}], sinAuditar: [{ nombre: 'bd' }], externo: null }, equipo: 'Visas' });
  assert.equal(e.completo, false);
  for (const h of ['sin gitleaks', '1 endpoints sin revisar', '1 avisos sin cribar', '1 servidores sin auditar por dentro', 'sin vista desde internet']) assert.ok(e.huecos.includes(h), h);
});

test('el informe lleva la infraestructura y sus datos en JSON con una huella que se puede comprobar', () => {
  const graph = { project: { name: 'App' }, nodes: [{ id: 'n', label: 'N', stats: { files: 1 } }], files: [], routes: [], meta: { repos: [] },
    health: { issues: [{ id: 'lupa:servidores|servidores/web-01', severity: 'high', title: 'Parches </script> sin aplicar', detail: 'd', items: [], locations: [{ file: 'servidores/web-01', line: 1 }], lupa: { cat: 'servidores', count: 1 } }] },
    lupa: { nombres: { servidores: 'Servidores por dentro' }, categorias: { servidores: { high: 1, medium: 0, low: 0 } } } };
  const infra = { servidores: [{ nombre: 'web-01', ip: '10.0.0.1', so: 'Ubuntu', soEstado: 'al-dia', parchesSeguridad: 12, agentes: [], graves: 1, aMirar: 0 }],
    red: { nodes: [{ id: 'internet', nombre: 'Internet', tipo: 'internet' }, { id: 'h:web-01', nombre: 'web-01', tipo: 'servidor', auditado: true }], edges: [{ from: 'internet', to: 'h:web-01', puerto: 22, servicio: 'SSH', procesos: ['sshd'], origenesInternet: 3 }] },
    expuesto: [], externo: null, sinAuditar: [] };
  const entrega = { lupa: '0.3.0', floorplan: '700645b', equipo: 'Visas', proyecto: 'App', quien: 'dev', email: '', generado: new Date().toISOString(), repos: [], herramientas: {}, faltan: [],
    revision: { endpoints: 0, endpointsTotal: 0, cribados: 0, pendientes: 0, descartados: 0 }, servidores: { revisados: 1, sinAuditar: [], externo: null }, huecos: ['sin vista desde internet'], completo: false };
  const html = buildReport({ graph, tech: null, datos: null, infra, entrega });
  assert.match(html, /<h2>Servidores y red<\/h2>/);
  assert.match(html, /<svg class="net"/);
  assert.match(html, /Pasada incompleta/);
  const raw = /<script type="application\/json" id="lupa-datos">([\s\S]*?)<\/script>/.exec(html)[1];
  const data = JSON.parse(raw);
  const { huella, ...rest } = data;
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(rest)).digest('hex'), huella);
  assert.equal(data.avisos[0].titulo, 'Parches </script> sin aplicar', 'el JSON sobrevive a un </script> dentro');
  assert.equal(infraSection(null), '');
});

test('el mapa del código viaja dentro del informe, comprimido, en su propia pestaña', async () => {
  const graph = { project: { name: 'App' }, nodes: [{ id: 'n', label: 'N', stats: { files: 1 } }], files: [], routes: [], meta: { repos: [] }, health: { issues: [] }, lupa: { nombres: {}, categorias: {} } };
  const map = '<!doctype html><html><body><div id="ask">pregunta</div>mapa de prueba</body></html>';
  const { gzipSync, gunzipSync } = await import('node:zlib');
  const html = buildReport({ graph, tech: null, datos: null, mapa: gzipSync(Buffer.from(map)).toString('base64') });
  assert.match(html, /role="tablist"/);
  assert.match(html, /data-tab="mapa"/);
  const b64 = /<script type="application\/octet-stream" id="lupa-mapa">([^<]+)<\/script>/.exec(html)[1];
  assert.equal(gunzipSync(Buffer.from(b64, 'base64')).toString('utf8'), map);
  const plain = buildReport({ graph, tech: null, datos: null });
  assert.ok(!/role="tablist"/.test(plain), 'sin mapa no hay pestañas');
});

// ---------------------------------------------------------------- arreglos de la revisión de código
import { sanitizeServer } from '../skills/lupa/scripts/lib/servidores.mjs';
import { inCidr } from '../skills/lupa/scripts/lib/red.mjs';

test('un servidor comprometido no cuela HTML en el informe a través de un «puerto»', () => {
  const evil = sanitizeServer(host({ salidas: [{ ip: '10.0.0.5', puerto: '<img src=x onerror=alert(1)>', proceso: '<b>x</b>', publica: false, veces: 'mucho' }] }));
  assert.equal(evil.salidas[0].puerto, 0);
  assert.equal(evil.salidas[0].veces, 0);
  const m = networkModel([{ ...evil, nombre: 'web-01', ipPrivada: '10.0.0.1' }]);
  const html = infraSection({ servidores: [], red: m, expuesto: [], externo: null, sinAuditar: [] });
  assert.ok(!html.includes('<img src=x'), 'el puerto llega como número');
  assert.ok(!html.includes('<b>x</b>'), 'el proceso llega escapado');
});

test('exposición: un rango amplio abierto a internet es grave aunque el servidor no esté auditado; también por IPv6', () => {
  const db = host({ nombre: 'db', aws: { id: 'i-db' }, escucha: [{ proto: 'tcp', ip: '0.0.0.0', puerto: 5432, proceso: 'postgres' }, { proto: 'tcp', ip: '0.0.0.0', puerto: 6379, proceso: 'redis-server' }] });
  const awsNet = {
    instancias: [{ id: 'i-db', nombre: 'db' }, { id: 'i-x', nombre: 'sin-auditar' }, { id: 'i-v6', nombre: 'v6' }],
    interfaces: [
      { ip: '10.0.0.1', ips: ['10.0.0.1'], ipPublica: '1.1.1.1', ipv6: [], instancia: 'i-db', grupos: ['sg-todo'] },
      { ip: '10.0.0.2', ips: ['10.0.0.2'], ipPublica: '2.2.2.2', ipv6: [], instancia: 'i-x', grupos: ['sg-altos'] },
      { ip: '10.0.0.3', ips: ['10.0.0.3'], ipPublica: '', ipv6: ['2a05::1'], instancia: 'i-v6', grupos: ['sg-v6'] },
    ],
    gruposSeguridad: [
      { id: 'sg-todo', nombre: 'todo', entradas: [{ proto: 'tcp', desde: 0, hasta: 65535, origenes: ['0.0.0.0/0'] }] },
      { id: 'sg-altos', nombre: 'altos', entradas: [{ proto: 'tcp', desde: 1024, hasta: 65535, origenes: ['0.0.0.0/0'] }] },
      { id: 'sg-v6', nombre: 'v6', entradas: [{ proto: 'tcp', desde: 22, hasta: 22, origenes: ['::/0'] }] },
    ],
    balanceadores: [],
  };
  const x = exposure([db], awsNet);
  const tcpAll = x.find((e) => e.host === 'db');
  assert.deepEqual(tcpAll.puertos.map((p) => p.puerto).sort(), [5432, 6379], 'lo que escucha dentro del rango');
  const f = networkFindings([db], networkModel([db], awsNet), x);
  assert.ok(f.some((y) => y.host === 'db' && y.severity === 'high'));
  assert.ok(f.some((y) => y.host === 'sin-auditar' && y.severity === 'high' && /1024-65535/.test(y.title)), 'rango amplio en un servidor sin auditar');
  assert.ok(x.some((e) => e.host === 'v6' && e.via === 'IPv6 pública'));
  assert.ok(f.some((y) => y.host === 'v6' && y.severity === 'high'));
});

test('Amazon Linux 2023 fijado en una versión vieja avisa aunque dnf diga «0 parches»; sin caché, «no se sabe»', () => {
  const al = (over) => host({ equipo: { ...host().equipo, so: 'Amazon Linux 2023.11.20250427', so_id: 'amzn', so_version: '2023' }, ...over });
  const r = rules(serverFindings(al({ parches: { gestor: 'dnf', pendientes: 0, seguridad: 0, automaticas: true, releasever: null } })));
  assert.equal(r['al2023-fijado'], 'high');
  assert.equal(rules(serverFindings(al({ parches: { gestor: 'dnf', pendientes: 0, seguridad: 0, automaticas: true, releasever: 'latest' } })))['al2023-fijado'], undefined);
  assert.equal(rules(serverFindings(al({ parches: { gestor: 'dnf', pendientes: null, seguridad: null, automaticas: true, releasever: 'latest' } })))['parches-desconocidos'], 'low');
});

test('sin la config de SSH leída no se inventan avisos de SSH', () => {
  const r = rules(serverFindings(host({ ssh: { instalado: true, activo: true, config_leida: false, config: {} } })));
  assert.equal(r['ssh-contrasena'], undefined);
});

test('las IP de las redes de Docker del servidor son sus contenedores; las demás 172.x son vecinos de verdad', () => {
  assert.ok(inCidr('172.18.0.3', '172.18.0.0/16'));
  assert.ok(!inCidr('172.31.5.9', '172.18.0.0/16'));
  const h = host({ nombre: 'app', redes_docker: ['172.18.0.0/16'], salidas: [{ ip: '172.18.0.3', puerto: 9001, proceso: 'docker-proxy', publica: false }, { ip: '172.31.5.9', puerto: 5432, proceso: 'node', publica: false }] });
  const m = networkModel([h]);
  assert.ok(!m.nodes.some((n) => n.nombre === '172.18.0.3'));
  assert.ok(m.nodes.some((n) => n.nombre === '172.31.5.9'), 'una IP de la VPC por defecto (172.31/16) no se descarta');
});
