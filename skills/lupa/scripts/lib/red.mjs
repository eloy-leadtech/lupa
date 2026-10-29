// Cómo se comunican los servidores del proyecto y qué queda expuesto a internet.
// - Lo que de verdad pasa: las conexiones que cada servidor tenía abiertas (servidor/lupa-servidor.py).
// - Lo que se permite: grupos de seguridad y balanceadores de AWS (servidores-ssm.mjs → red-aws.json).
// Juntas, las dos vistas dicen quién habla con quién, por qué puerto, y qué puede tocar cualquiera desde internet.
import { hostRef, RISKY_PORTS } from './servidores.mjs';

export const PORT_NAMES = {
  22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 1514: 'Wazuh (agentes)', 1515: 'Wazuh (alta de agentes)', 3000: 'web de aplicación',
  3128: 'proxy', 3306: 'MySQL', 3333: 'panel de administración', 3389: 'escritorio remoto', 5432: 'PostgreSQL', 5672: 'RabbitMQ', 6379: 'Redis',
  8000: 'API de aplicación', 8080: 'HTTP alternativo', 8443: 'HTTPS alternativo', 9000: 'aplicación', 9100: 'métricas (node_exporter)',
  9200: 'Elasticsearch/OpenSearch', 9256: 'métricas de procesos', 27017: 'MongoDB', 55000: 'API de Wazuh',
};
export const portName = (p) => PORT_NAMES[p] || `puerto ${p}`;
// lo que no debería poder tocar internet: acceso remoto, bases de datos, paneles y APIs de control
const ADMIN_PORTS = new Set([22, 23, 445, 1515, 2375, 2376, 3306, 3333, 3389, 5432, 5900, 6379, 9200, 9300, 11211, 15672, 27017, 55000]);
// protocolos que viajan en claro entre servidores (un proxy en el 80 lleva TLS dentro: no cuenta)
const CLEARTEXT = { 80: 'HTTP', 8080: 'HTTP', 6379: 'Redis', 9100: 'métricas', 9256: 'métricas', 21: 'FTP', 23: 'Telnet', 11211: 'Memcached' };
const PROXIES = /squid|tinyproxy|haproxy|envoy|privoxy/i;

function isPublic(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
  if (!m) return !!ip && !/^(::1|fe80:|fc|fd)/i.test(ip) && ip.includes(':');
  const [a, b] = [+m[1], +m[2]];
  return !(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0);
}

/** ¿Está la IPv4 dentro del CIDR? («172.18.0.3», «172.18.0.0/16») */
export function inCidr(ip, cidr) {
  const toInt = (s) => s.split('.').reduce((a, o) => (a << 8) + (+o & 255), 0) >>> 0;
  const [base, bits] = String(cidr).split('/');
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip || '') || !/^\d+\.\d+\.\d+\.\d+$/.test(base || '')) return false;
  const mask = +bits === 0 ? 0 : (~0 << (32 - +bits)) >>> 0;
  return (toInt(ip) & mask) === (toInt(base) & mask);
}

/** Un nombre legible para una interfaz de red de AWS que no es un servidor auditado. */
function ifaceLabel(n, instName, vpce) {
  if (n.instancia && instName.has(n.instancia)) return instName.get(n.instancia);
  const d = n.descripcion || '';
  let m = /^ELB (?:net|app|gwy)\/([^/]+)/.exec(d); if (m) return `Balanceador ${m[1]}`;
  m = /^VPC Endpoint Interface (vpce-\w+)/.exec(d); if (m) return vpce.has(m[1]) ? `AWS ${vpce.get(m[1])} (endpoint)` : `Endpoint de VPC ${m[1]}`;
  if (n.tipo === 'vpc_endpoint') return `Endpoint de VPC`;
  if (/^RDSNetworkInterface/.test(d)) return 'Base de datos RDS';
  if (/^EFS mount target/.test(d)) return 'Disco compartido EFS';
  if (/NAT Gateway/i.test(d) || n.tipo === 'nat_gateway') return 'NAT de salida';
  if (/^AWS Lambda/i.test(d) || n.tipo === 'lambda') return 'Funciones Lambda';
  return d ? d.slice(0, 40) : `Interfaz ${n.tipo || ''}`.trim();
}

/** El modelo de la red: nodos (servidores, piezas de AWS, internet) y las conexiones vistas entre ellos. */
export function networkModel(servers, awsNet = null) {
  const nodes = new Map(), byIp = new Map();
  const node = (id, n) => { if (!nodes.has(id)) nodes.set(id, { id, ...n }); return id; };
  node('internet', { nombre: 'Internet', tipo: 'internet' });
  for (const h of servers) {
    const id = node('h:' + h.nombre, { nombre: h.nombre, tipo: 'servidor', ip: h.ipPrivada, ipPublica: h.ipPublica, auditado: true });
    for (const ip of [h.ipPrivada, ...(h.equipo?.ips || [])]) if (ip) byIp.set(ip, id);
  }
  const instName = new Map([...(awsNet?.instancias || []), ...(awsNet?.instanciasExternas || [])].map((i) => [i.id, i.nombre]));
  const vpce = new Map((awsNet?.endpoints || []).map((e) => [e.id, e.servicio]));
  for (const i of awsNet?.instancias || []) if (i.ipPrivada && !byIp.has(i.ipPrivada)) byIp.set(i.ipPrivada, node('h:' + i.nombre, { nombre: i.nombre, tipo: 'servidor', ip: i.ipPrivada, ipPublica: i.ipPublica, auditado: false }));
  for (const n of awsNet?.interfaces || []) {
    const label = ifaceLabel(n, instName, vpce);
    for (const ip of n.ips?.length ? n.ips : [n.ip]) if (ip && !byIp.has(ip)) byIp.set(ip, node('a:' + label, { nombre: label, tipo: 'aws', ip }));
  }
  const nodeFor = (ip) => byIp.get(ip) || (isPublic(ip) ? 'internet' : node('u:' + ip, { nombre: ip, tipo: 'desconocido', ip }));

  const edges = new Map();
  const edge = (from, to, puerto, extra) => {
    if (from === to) return;
    const k = `${from}|${to}|${puerto}`;
    const e = edges.get(k) || { from, to, puerto, servicio: portName(puerto), procesos: new Set(), destinos: new Set(), origenesInternet: 0, vistoDesde: new Set() };
    if (extra.proceso) e.procesos.add(extra.proceso);
    if (extra.destino) e.destinos.add(extra.destino);
    if (extra.origenesInternet) e.origenesInternet = Math.max(e.origenesInternet, extra.origenesInternet);
    e.vistoDesde.add(extra.visto);
    edges.set(k, e);
  };
  // Las IP de las redes de Docker de un servidor son sus propios contenedores, no vecinos de red. Se usan las
  // subredes reales que dio el servidor; una foto vieja sin ellas cae en 172.16/12, solo si el servidor tiene Docker.
  const legacyDocker = (ip) => /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
  for (const h of servers) {
    const me = byIp.get(h.ipPrivada) || 'h:' + h.nombre;
    const nets = Array.isArray(h.redes_docker) ? h.redes_docker : null;
    const local = (ip) => !byIp.has(ip) && (nets ? nets.some((c) => inCidr(ip, c)) : legacyDocker(ip) && (h.contenedores?.length || (h.servicios?.en_marcha || []).includes('docker')));
    for (const s of h.salidas || []) if (!local(s.ip)) edge(me, s.publica ? 'internet' : nodeFor(s.ip), s.puerto, { proceso: s.proceso, destino: s.publica ? s.ip : '', visto: h.nombre });
    for (const e of h.entradas || []) {
      for (const p of e.pares_privados || []) if (!local(p)) edge(nodeFor(p), me, e.puerto, { proceso: e.proceso, visto: h.nombre });
      if (e.publicos_total) edge('internet', me, e.puerto, { proceso: e.proceso, origenesInternet: e.publicos_total, visto: h.nombre });
    }
  }
  const list = [...edges.values()].map((e) => {
    const procesos = [...e.procesos];
    const claro = CLEARTEXT[e.puerto] && !procesos.some((p) => PROXIES.test(p)) && e.from !== 'internet' && e.to !== 'internet' ? CLEARTEXT[e.puerto] : null;
    return { ...e, procesos, destinos: [...e.destinos].slice(0, 10), vistoDesde: [...e.vistoDesde], claro };
  });
  return { nodes: [...nodes.values()], edges: list.sort((a, b) => a.from.localeCompare(b.from) || a.puerto - b.puerto) };
}

const OPEN = new Set(['0.0.0.0/0', '::/0']);
const inRange = (r, port) => r.proto === '-1' || (r.desde != null && port >= r.desde && port <= r.hasta);
const rangeText = (r) => (r.proto === '-1' ? 'todos los puertos' : r.desde === r.hasta ? `${r.desde}` : `${r.desde}-${r.hasta}`);

/**
 * Lo que se puede alcanzar desde internet según AWS: instancias con IP pública y un grupo que deja
 * entrar 0.0.0.0/0, y balanceadores públicos con sus destinos. Cruzado con lo que escucha cada servidor.
 */
export function exposure(servers, awsNet) {
  if (!awsNet) return [];
  const sgs = new Map((awsNet.gruposSeguridad || []).map((g) => [g.id, g]));
  const byInstance = new Map([...(awsNet.instancias || []), ...(awsNet.instanciasExternas || [])].map((i) => [i.id, i]));
  const foto = new Map(servers.map((h) => [h.aws?.id || h.nombre, h]));
  const listening = (h, port) => (h?.escucha || []).find((e) => e.proto === 'tcp' && e.puerto === port && !/^(127\.|::1$)/.test(e.ip));
  const out = [];
  for (const n of awsNet.interfaces || []) {
    // pública por IPv4 (con 0.0.0.0/0) o por IPv6 (con ::/0)
    const v4 = !!n.ipPublica, v6 = !!n.ipv6?.length;
    if ((!v4 && !v6) || !n.instancia) continue;
    const inst = byInstance.get(n.instancia); const h = foto.get(n.instancia);
    const open = (r) => (v4 && r.origenes.includes('0.0.0.0/0')) || (v6 && r.origenes.includes('::/0'));
    for (const gid of n.grupos) for (const r of sgs.get(gid)?.entradas || []) {
      if (!open(r) || !['tcp', '-1'].includes(r.proto)) continue;
      // lo que escucha de verdad dentro del rango; un puerto suelto cuenta aunque no se sepa qué hay detrás
      const ports = (h?.escucha || []).filter((e) => e.proto === 'tcp' && !/^(127\.|::1$)/.test(e.ip) && inRange(r, e.puerto)).map((e) => e.puerto);
      if (r.proto !== '-1' && r.desde === r.hasta) ports.push(r.desde);
      const amplio = r.proto === '-1' || r.hasta - r.desde >= 100;
      out.push({ host: inst?.nombre || n.instancia, ip: n.ipPublica || n.ipv6[0], via: v4 ? 'IP pública' : 'IPv6 pública', grupo: `${gid} (${sgs.get(gid)?.nombre || ''})`, rango: rangeText(r), amplio,
        puertos: [...new Set(ports)].map((p) => ({ puerto: p, servicio: portName(p), escucha: listening(h, p)?.proceso || (h ? null : '¿?') })), auditado: !!h });
    }
  }
  for (const lb of awsNet.balanceadores || []) {
    if (lb.esquema !== 'internet-facing') continue;
    const open = !lb.grupos?.length || lb.grupos.some((g) => (sgs.get(g)?.entradas || []).some((r) => r.origenes.some((o) => OPEN.has(o))));
    for (const l of lb.escuchas) {
      // cada puerto del balanceador manda a sus grupos de destino; sin ese dato, a todos
      const targets = lb.destinos.filter((d) => !l.grupos?.length || l.grupos.includes(d.grupo));
      const hosts = [...new Set(targets.map((d) => { const i = byInstance.get(d.destino); return i ? `${i.nombre}${i.estado && i.estado !== 'running' ? ` (${i.estado === 'stopped' ? 'parada' : i.estado})` : ''}` : d.destino; }))];
      // qué proceso atiende de verdad ese puerto en el servidor de destino, si está auditado
      const t0 = targets[0]; const proc = t0 ? listening(foto.get(t0.destino), t0.puerto)?.proceso : null;
      out.push({ host: hosts.join(', ') || lb.nombre, ip: lb.dns, via: `balanceador ${lb.nombre}`, grupo: lb.grupos?.join(', ') || 'sin grupo', rango: String(l.puerto), abiertoATodos: open,
        puertos: [{ puerto: l.puerto, servicio: portName(l.puerto), escucha: proc || (foto.has(t0?.destino) ? null : '¿?') }], auditado: hosts.every((x) => servers.some((h) => h.nombre === x)) });
    }
  }
  return out;
}

/** Hallazgos de red: lo expuesto a internet, el tráfico sin cifrar entre servidores y las IP que nadie sabe qué son. */
export function networkFindings(servers, model, exposed) {
  const out = [];
  const hostFile = (name) => { const h = servers.find((x) => x.nombre === name); return h ? hostRef(h) : `red/${name}`; };
  for (const x of exposed) {
    const admin = x.puertos.filter((p) => ADMIN_PORTS.has(p.puerto) && p.escucha !== null);
    const web = x.puertos.filter((p) => !ADMIN_PORTS.has(p.puerto));
    // un rango amplio abierto a internet es grave aunque hoy no escuche nada (o no se haya auditado el servidor)
    const all = !!x.amplio;
    if (admin.length || all) out.push({
      tool: 'lupa-red', cat: 'red', rule: 'expuesto-admin', severity: 'high', file: hostFile(x.host.split(', ')[0]), line: 1, host: x.host,
      title: `${x.host}: ${all ? (x.rango === 'todos los puertos' ? 'todos los puertos abiertos' : `los puertos ${x.rango} abiertos`) : admin.map((p) => `${p.servicio} (${p.puerto})`).join(', ')} a cualquiera en internet`,
      detail: `El grupo ${x.grupo} deja entrar 0.0.0.0/0 a ${x.rango} por ${x.via} (${x.ip}).${admin.some((p) => p.escucha) ? ` En el servidor escucha${admin.filter((p) => p.escucha).length > 1 ? 'n' : ''}: ${admin.filter((p) => p.escucha).map((p) => `${p.puerto} → ${p.escucha}`).join(', ')}.` : ''} Acceso remoto, bases de datos y paneles de administración no deberían verse desde internet: son lo primero que se ataca.`,
      fix: `En ${x.grupo}, cambia el origen 0.0.0.0/0 del rango ${x.rango} por las IP o la VPN que de verdad lo usan (o quita la regla y entra por SSM). Si es Terraform, cámbialo allí para que no vuelva.`,
    });
    else if (web.length) out.push({
      tool: 'lupa-red', cat: 'red', rule: 'expuesto-web', severity: x.via.startsWith('balanceador') && x.abiertoATodos === false ? 'low' : 'medium', file: hostFile(x.host.split(', ')[0]), line: 1, host: x.host,
      title: `${x.host} se publica en internet: ${web.map((p) => `${p.servicio} (${p.puerto})`).join(', ')}`,
      detail: `Por ${x.via} (${x.ip}), grupo ${x.grupo}${x.abiertoATodos === false ? ', aunque el grupo del balanceador no deja entrar a cualquiera' : ', abierto a 0.0.0.0/0'}. Es la puerta de entrada del proyecto: tiene que tener login, TLS y límite de peticiones.`,
      fix: `confirma que ${x.host} tiene que estar en internet en ${web.map((p) => p.puerto).join(', ')}; si no, restringe el origen. Si sí, comprueba TLS, cabeceras de seguridad y que no se ve ningún panel sin login.`,
    });
  }
  const clear = model.edges.filter((e) => e.claro);
  const name = (id) => model.nodes.find((n) => n.id === id)?.nombre || id;
  if (clear.length) out.push({
    tool: 'lupa-red', cat: 'red', rule: 'trafico-en-claro', severity: clear.some((e) => !['métricas'].includes(e.claro)) ? 'medium' : 'low', file: 'red/comunicaciones', line: 1,
    title: `${clear.length} conexion${clear.length === 1 ? '' : 'es'} entre servidores van sin cifrar`,
    detail: clear.slice(0, 12).map((e) => `${name(e.from)} → ${name(e.to)}:${e.puerto} (${e.claro})`).join(' · ') + '. Quien esté en la misma red puede leer o cambiar ese tráfico.',
    fix: 'pon TLS en esos servicios (o un túnel), empezando por los que llevan credenciales o datos; las métricas pueden esperar.',
  });
  const unknown = model.nodes.filter((n) => n.tipo === 'desconocido');
  if (unknown.length) out.push({
    tool: 'lupa-red', cat: 'red', rule: 'ip-sin-identificar', severity: 'low', file: 'red/comunicaciones', line: 1,
    title: `${unknown.length} IP interna${unknown.length === 1 ? '' : 's'} habla${unknown.length === 1 ? '' : 'n'} con el proyecto y no se sabe qué ${unknown.length === 1 ? 'es' : 'son'}`,
    detail: unknown.slice(0, 15).map((n) => `${n.nombre} (${model.edges.filter((e) => e.from === n.id || e.to === n.id).map((e) => `${e.from === n.id ? '→ ' + name(e.to) : '← ' + name(e.from)}:${e.puerto}`).slice(0, 3).join(', ')})`).join(' · ') + '. Puede ser otra VPC, una VPN o algo que falta en el inventario.',
    fix: 'identifica esas IP; si son servidores del proyecto, añádelos al inventario y pásales lupa-servidor.py.',
  });
  return out;
}
