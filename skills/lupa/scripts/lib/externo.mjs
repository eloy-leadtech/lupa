// La vista desde internet: lo que cualquiera ve de los servidores y dominios públicos del proyecto.
// Solo hace lo que haría un navegador o un cliente normal: abrir una conexión TCP a una lista corta de
// puertos, leer el saludo de los servicios que se presentan solos, pedir el certificado TLS, la portada
// y una docena de rutas delicadas conocidas. Sin ataques, sin fuerza bruta, sin cargas raras.
import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { portName } from './red.mjs';

export const PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 1514, 1515, 2375, 2376, 3000, 3306, 3333, 3389,
  5000, 5432, 5601, 5672, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9100, 9200, 9300, 11211, 15672, 27017, 55000];
const TLS_FIRST = new Set([443, 465, 993, 995, 1515, 5601, 8443, 9200, 55000]);
const HTTP_PLAIN = new Set([80, 3000, 3333, 5000, 8000, 8080, 8888, 9000, 9090, 15672]);
// abiertos a internet, estos son graves: acceso remoto de administración, bases de datos, APIs de control
export const DANGEROUS = { 23: 'Telnet', 445: 'SMB', 1433: 'SQL Server', 1515: 'alta de agentes de Wazuh', 2375: 'API de Docker', 2376: 'API de Docker', 3306: 'MySQL', 3389: 'escritorio remoto',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch/OpenSearch', 9300: 'Elasticsearch', 11211: 'Memcached', 15672: 'panel de RabbitMQ', 27017: 'MongoDB', 55000: 'API de Wazuh' };
const PATHS = [
  { p: '/.git/HEAD', ok: (b) => /^ref: refs\//.test(b), sev: 'high', que: 'el repositorio git del sitio (se puede descargar el código y su historial)' },
  { p: '/.env', ok: (b) => /^[A-Z_][A-Z0-9_]*=.+$/m.test(b) && !/<html/i.test(b), sev: 'high', que: 'el fichero .env con la configuración y sus secretos' },
  { p: '/actuator/env', ok: (b) => /"propertySources"|"activeProfiles"/.test(b), sev: 'high', que: 'el Actuator de Spring con las variables de entorno' },
  { p: '/server-status', ok: (b) => /Apache Server Status/i.test(b), sev: 'medium', que: 'el estado interno de Apache (clientes, URLs que se piden)' },
  { p: '/phpinfo.php', ok: (b) => /phpinfo\(\)|PHP Version/i.test(b), sev: 'medium', que: 'phpinfo() con la configuración de PHP y del servidor' },
  { p: '/.DS_Store', ok: (b) => b.startsWith('\0\0\0\x01Bud1'), sev: 'low', que: 'un .DS_Store que lista los ficheros de la carpeta' },
  { p: '/backup.zip', ok: (b, h) => /zip|octet-stream/.test(h['content-type'] || '') && b.startsWith('PK'), sev: 'high', que: 'una copia de seguridad descargable' },
  { p: '/swagger-ui.html', ok: (b) => /swagger-ui/i.test(b), sev: 'low', que: 'la documentación de la API (Swagger)' },
  { p: '/openapi.json', ok: (b) => /"openapi"\s*:|"swagger"\s*:/.test(b), sev: 'low', que: 'la especificación de la API (OpenAPI)' },
  { p: '/docs', ok: (b) => /swagger-ui|redoc/i.test(b), sev: 'low', que: 'la documentación interactiva de la API' },
];

function isPrivate(ip) {
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) || /^(::1|fe80:|f[cd])/i.test(ip);
}

/** ¿Acepta conexión el puerto? Si el servicio saluda solo (SSH, SMTP, FTP), se guarda el saludo. */
function connect(host, port, timeout = 2500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    let banner = '', open = false, done = false;
    const end = (r) => { if (done) return; done = true; s.destroy(); resolve(r); };
    s.setTimeout(timeout, () => end(open ? { abierto: true, banner } : { abierto: false }));
    s.on('connect', () => { open = true; s.setTimeout(1500); });
    s.on('data', (d) => { banner += d.toString('latin1'); if (banner.length > 160 || banner.includes('\n')) end({ abierto: true, banner }); });
    s.on('error', () => end({ abierto: open, banner }));
    s.on('close', () => end({ abierto: open, banner }));
  }).then((r) => ({ ...r, banner: (r.banner || '').replace(/[^\x20-\x7e]+/g, ' ').trim().slice(0, 120) }));
}

function tlsInfo(host, port, servername) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, servername: net.isIP(servername) ? undefined : servername, rejectUnauthorized: false, timeout: 4000 }, () => {
      const c = s.getPeerCertificate();
      const until = c?.valid_to ? Date.parse(c.valid_to) : null;
      resolve({ protocolo: s.getProtocol(), valido: s.authorized, error: s.authorizationError ? String(s.authorizationError) : '',
        sujeto: c?.subject?.CN || '', emisor: c?.issuer?.O || c?.issuer?.CN || '', autofirmado: !!c?.subject && JSON.stringify(c.subject) === JSON.stringify(c.issuer),
        nombres: String(c?.subjectaltname || '').replace(/DNS:/g, '').split(/,\s*/).filter(Boolean).slice(0, 10),
        caduca: c?.valid_to ? new Date(until).toISOString().slice(0, 10) : '', dias: until ? Math.floor((until - Date.now()) / 86400000) : null });
      s.end();
    });
    s.on('error', () => resolve(null));
    s.on('timeout', () => { s.destroy(); resolve(null); });
  });
}

function get(host, port, secure, path, servername) {
  return new Promise((resolve) => {
    const lib = secure ? https : http;
    const req = lib.request({ host, port, path, method: 'GET', timeout: 6000, rejectUnauthorized: false, servername: net.isIP(servername) ? undefined : servername,
      headers: { host: servername + ([80, 443].includes(port) ? '' : ':' + port), 'user-agent': 'Lupa (auditoria de seguridad)', accept: '*/*' } }, (res) => {
      let body = '';
      res.setEncoding('latin1');
      res.on('data', (d) => { if (body.length < 65536) body += d; });
      res.on('end', () => resolve({ estado: res.statusCode, cabeceras: res.headers, cuerpo: body }));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

const pickHeaders = (h) => Object.fromEntries(['server', 'x-powered-by', 'strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'location']
  .filter((k) => h?.[k]).map((k) => [k, String(h[k]).slice(0, 200)]));

async function probeHttp(ip, port, secure, name) {
  const home = await get(ip, port, secure, '/', name);
  if (!home) return null;
  const title = /<title[^>]*>([^<]{0,120})/i.exec(home.cuerpo)?.[1]?.trim() || '';
  const cookies = [].concat(home.cabeceras['set-cookie'] || []).map((c) => ({ nombre: c.split('=')[0], secure: /;\s*secure/i.test(c), httponly: /;\s*httponly/i.test(c) }));
  // si una ruta inventada da 200 con el mismo cuerpo, el sitio contesta a todo: no se cuentan las rutas
  const fake = await get(ip, port, secure, '/lupa-' + crypto.randomBytes(4).toString('hex'), name);
  const catchAll = fake?.estado === 200;
  const rutas = [];
  for (const x of PATHS) {
    const r = await get(ip, port, secure, x.p, name);
    if (r?.estado === 200 && x.ok(r.cuerpo, r.cabeceras) && !(catchAll && r.cuerpo === fake.cuerpo)) rutas.push({ ruta: x.p, que: x.que, sev: x.sev });
  }
  return { estado: home.estado, titulo: title, cabeceras: pickHeaders(home.cabeceras), cookies, rutas, contestaATodo: catchAll };
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

/** Mira un objetivo (dominio o IP) desde fuera. */
export async function probeTarget(target, { log = () => {} } = {}) {
  let ips = [];
  if (net.isIP(target)) ips = [target];
  else { try { ips = (await dns.lookup(target, { all: true })).map((a) => a.address); } catch (e) { return { objetivo: target, error: `no resuelve (${e.code || e.message})` }; } }
  const pub = ips.filter((ip) => !isPrivate(ip));
  if (!pub.length) return { objetivo: target, ips, privado: true };
  const ip = pub[0];
  log(`${target} (${ip}): ${PORTS.length} puertos…`);
  const scan = await pool(PORTS, 16, async (p) => ({ puerto: p, ...(await connect(ip, p)) }));
  const puertos = [];
  for (const s of scan.filter((x) => x.abierto)) {
    const e = { puerto: s.puerto, servicio: portName(s.puerto), banner: s.banner };
    const t = TLS_FIRST.has(s.puerto) || !HTTP_PLAIN.has(s.puerto) ? await tlsInfo(ip, s.puerto, target) : null;
    if (t) e.tls = t;
    if (t && [443, 8443, 5601, 9200, 55000].includes(s.puerto)) e.http = await probeHttp(ip, s.puerto, true, target);
    else if (!t && HTTP_PLAIN.has(s.puerto)) e.http = await probeHttp(ip, s.puerto, false, target);
    puertos.push(e);
  }
  return { objetivo: target, ips, ip, privado: false, puertos };
}

/** Desde qué IP pública se ha mirado: si está en una lista permitida, se ve más que el resto del mundo. */
export async function egressIp() {
  const r = await get('checkip.amazonaws.com', 443, true, '/', 'checkip.amazonaws.com');
  return r?.estado === 200 ? r.cuerpo.trim() : null;
}

/** Hallazgos de la vista desde internet. Cuelgan de «internet/<objetivo>». */
export function externalFindings(data) {
  const out = [];
  for (const t of data?.objetivos || []) {
    if (!t.puertos) continue;
    const file = `internet/${t.objetivo}`;
    const add = (rule, severity, title, detail, fix) => out.push({ tool: 'lupa-externo', cat: 'red', rule, severity, file, line: 1, host: t.objetivo, title, detail, fix: `Arreglo de exposición en ${t.objetivo} (${t.ip}): ${fix}` });
    for (const p of t.puertos) {
      if (DANGEROUS[p.puerto]) add(`internet-${p.puerto}`, 'high', `${DANGEROUS[p.puerto]} (${p.puerto}) se alcanza desde internet en ${t.objetivo}`, `Desde ${data.desde || 'fuera'} el puerto ${p.puerto} acepta conexiones${p.banner ? ` y se presenta como «${p.banner}»` : ''}. Es de lo primero que se ataca.`, `cierra el ${p.puerto} a internet (grupo de seguridad o cortafuegos) y deja entrar solo a las IP o la VPN que lo usan.`);
      else if (p.puerto === 22) add('internet-ssh', 'medium', `SSH (22) abierto a internet en ${t.objetivo}`, `Acepta conexiones desde ${data.desde || 'fuera'}${p.banner ? ` («${p.banner}»)` : ''}. Recibirá intentos de entrada continuos.`, 'restringe el 22 a la VPN o a IP concretas, o ciérralo y entra por SSM.');
      const c = p.tls;
      if (c) {
        if (c.dias != null && c.dias < 0) add('tls-caducado', 'high', `El certificado de ${t.objetivo}:${p.puerto} caducó el ${c.caduca}`, 'Los navegadores avisan y los clientes que lo aceptan igualmente pierden la protección contra suplantación.', 'renueva el certificado y automatiza la renovación (Let\'s Encrypt o ACM).');
        else if (c.dias != null && c.dias < 21) add('tls-caduca', 'medium', `El certificado de ${t.objetivo}:${p.puerto} caduca en ${c.dias} días`, `Caduca el ${c.caduca}.`, 'renuévalo ya y comprueba que la renovación automática funciona.');
        if (!c.valido && c.dias >= 0) add('tls-no-confiable', [443, 8443].includes(p.puerto) ? 'medium' : 'low', `El certificado de ${t.objetivo}:${p.puerto} no es de confianza${c.autofirmado ? ' (autofirmado)' : ''}`, `${c.error || 'No lo firma una autoridad reconocida o no es para este nombre'}. Sujeto «${c.sujeto}», emisor «${c.emisor}». Los clientes acaban aceptando cualquier certificado, y entonces cualquiera en medio puede suplantar al servidor.`, 'pon un certificado de una autoridad reconocida para el nombre con el que se llega al servicio.');
        if (/TLSv1(\.[01])?$/.test(c.protocolo || '')) add('tls-viejo', 'medium', `${t.objetivo}:${p.puerto} usa ${c.protocolo}`, 'TLS 1.0 y 1.1 están retirados por fallos conocidos.', 'deja solo TLS 1.2 y 1.3.');
      }
      const h = p.http;
      if (!h) continue;
      for (const r of h.rutas || []) add(`ruta-${r.ruta}`, r.sev, `${t.objetivo}:${p.puerto}${r.ruta} deja ver ${r.que}`, `Cualquiera puede pedir ${r.ruta} y el servidor lo devuelve.`, `bloquea ${r.ruta} en el servidor web (o quita el fichero de la carpeta pública).`);
      const hd = h.cabeceras || {};
      if (p.tls) {
        const missing = [!hd['strict-transport-security'] && 'HSTS', !hd['content-security-policy'] && 'CSP', !hd['x-frame-options'] && !/frame-ancestors/.test(hd['content-security-policy'] || '') && 'X-Frame-Options', !hd['x-content-type-options'] && 'X-Content-Type-Options'].filter(Boolean);
        if (missing.length >= 2 && h.estado < 500) add('cabeceras', 'low', `${t.objetivo}:${p.puerto} no manda cabeceras de seguridad (${missing.join(', ')})`, `La portada${h.titulo ? ` («${h.titulo}»)` : ''} no pide al navegador que use solo HTTPS ni limita desde dónde se carga o se enmarca.`, `añade ${missing.join(', ')} en el servidor web o el proxy.`);
        const weak = (h.cookies || []).filter((k) => !k.secure || !k.httponly);
        if (weak.length) add('cookies', 'low', `Cookies sin Secure o HttpOnly en ${t.objetivo}:${p.puerto}`, `${weak.map((k) => k.nombre).slice(0, 6).join(', ')}. Sin Secure pueden viajar en claro; sin HttpOnly, un fallo de XSS las roba.`, 'marca las cookies de sesión con Secure, HttpOnly y SameSite.');
      } else if (h.estado && !(h.estado >= 300 && h.estado < 400 && /^https:/i.test(hd.location || ''))) {
        add('http-en-claro', /login|sign in|iniciar|admin|panel/i.test(h.titulo) ? 'medium' : 'low', `${t.objetivo}:${p.puerto} sirve${h.titulo ? ` «${h.titulo}»` : ' contenido'} sin cifrar`, 'No redirige a HTTPS: lo que se envíe (contraseñas, cookies) viaja en claro.', `redirige el ${p.puerto} a HTTPS o ciérralo.`);
      }
      const leak = [hd.server, hd['x-powered-by']].filter((v) => v && /\d/.test(v));
      if (leak.length) add('version-visible', 'low', `${t.objetivo}:${p.puerto} dice qué versión usa (${leak.join(', ')})`, 'Con la versión exacta es más fácil buscar fallos conocidos.', 'oculta la versión (server_tokens off, expose_php = Off, quita X-Powered-By).');
    }
  }
  return out;
}
