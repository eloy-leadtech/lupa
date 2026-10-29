// Los servidores por dentro: lee las fotos que deja servidor/lupa-servidor.py en floorplan/lupa/servidores/
// y las convierte en hallazgos (parches, SSH, contenedores, puertos abiertos, ficheros delicados, agentes…).
// Cada servidor es una «tarjeta» propia en el mapa: servidores/<nombre>.
import fs from 'node:fs';
import path from 'node:path';
import { readJSON } from './util.mjs';
import { eolStatus } from './intel.mjs';

export const hostRef = (h) => `servidores/${h.nombre}`;

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const nnum = (v) => (v == null ? null : num(v));
const str = (v) => (v == null ? '' : String(v)).slice(0, 400);
const arr = (v) => (Array.isArray(v) ? v : []);

/**
 * Una foto viene de un servidor que puede estar comprometido: lo que va a cálculos y al informe se fuerza
 * a su tipo (los puertos, números; los nombres, texto), para que un «puerto» con HTML no llegue al informe.
 */
export function sanitizeServer(j) {
  const ct = j.contenedores;
  return {
    ...j,
    escucha: arr(j.escucha).map((e) => ({ proto: str(e.proto), ip: str(e.ip), puerto: num(e.puerto), proceso: str(e.proceso) })),
    entradas: arr(j.entradas).map((e) => ({ puerto: num(e.puerto), proceso: str(e.proceso), pares_privados: arr(e.pares_privados).map(str), privados_total: num(e.privados_total), publicos_total: num(e.publicos_total) })),
    salidas: arr(j.salidas).map((s) => ({ ip: str(s.ip), puerto: num(s.puerto), proceso: str(s.proceso), publica: !!s.publica, veces: num(s.veces) })),
    contenedores: Array.isArray(ct) ? ct.map((c) => ({ ...c, nombre: str(c.nombre), imagen: str(c.imagen), usuario: str(c.usuario), red: str(c.red), capacidades: arr(c.capacidades).map(str),
      puertos: arr(c.puertos).map((q) => ({ contenedor: str(q.contenedor), ip: str(q.ip), puerto: num(q.puerto) })) })) : ct && typeof ct === 'object' ? { error: str(ct.error) } : null,
    parches: { ...(j.parches || {}), pendientes: nnum(j.parches?.pendientes), seguridad: nnum(j.parches?.seguridad), listas_hace_dias: nnum(j.parches?.listas_hace_dias),
      ejemplos_seguridad: arr(j.parches?.ejemplos_seguridad).map(str), releasever: j.parches?.releasever == null ? null : str(j.parches.releasever) },
    servicios: { en_marcha: arr(j.servicios?.en_marcha).map(str), agentes: arr(j.servicios?.agentes).map(str) },
    redes_docker: Array.isArray(j.redes_docker) ? j.redes_docker.map(str) : undefined,
    ficheros: { ...(j.ficheros || {}), lista: arr(j.ficheros?.lista).map((f) => ({ ...f, ruta: str(f.ruta), modo: str(f.modo), dueno: str(f.dueno) })) },
  };
}

/** Las fotos de los servidores, con un nombre corto y estable para cada uno. */
export function loadServers(dir) {
  let files = [];
  try { files = fs.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch {}
  return files.map((n) => readJSON(path.join(dir, n))).filter((j) => j?.lupa_servidor && j.equipo)
    .map((j) => ({ ...sanitizeServer(j), nombre: str(j.aws?.nombre || j.equipo.nombre), ipPrivada: str(j.aws?.ipPrivada || j.equipo.ips?.[0]), ipPublica: str(j.aws?.ipPublica) }))
    .sort((a, b) => a.nombre.localeCompare(b.nombre));
}

// puertos que no deberían escuchar en todas las interfaces: bases de datos, cachés, paneles y APIs de control
export const RISKY_PORTS = {
  2375: { que: 'la API de Docker sin TLS', sev: 'high' }, 2376: { que: 'la API de Docker', sev: 'medium' },
  3306: { que: 'MySQL', sev: 'medium' }, 5432: { que: 'PostgreSQL', sev: 'medium' }, 6379: { que: 'Redis', sev: 'high' },
  27017: { que: 'MongoDB', sev: 'high' }, 9200: { que: 'Elasticsearch/OpenSearch', sev: 'medium' }, 11211: { que: 'Memcached', sev: 'high' },
  3389: { que: 'el escritorio remoto (RDP/xrdp)', sev: 'medium' }, 5900: { que: 'VNC', sev: 'high' }, 15672: { que: 'el panel de RabbitMQ', sev: 'medium' },
  9090: { que: 'Prometheus', sev: 'low' }, 9093: { que: 'Alertmanager', sev: 'low' },
};
const DB_IMAGE = /(^|\/)(postgres|mysql|mariadb|mongo|redis|elasticsearch|opensearch|memcached|rabbitmq)(:|@|$)/i;
const ALL_IFACES = new Set(['0.0.0.0', '*', '::', '']);
const DETECTION = ['Wazuh', 'Wazuh (manager)', 'CrowdStrike', 'Microsoft Defender', 'osquery', 'Falco', 'CrowdSec'];
// las cuentas que crean las imágenes de nube con sudo sin contraseña: es lo normal, no un aviso
const CLOUD_USERS = new Set(['ubuntu', 'ec2-user', 'ssm-user', 'admin', 'debian', 'centos', 'rocky', 'azureuser', 'opc']);
const NOT_SECRET = /\.(example|sample|template|dist|tpl|default)$|(^|\/)go\.env$|(^|\/)(tests?|test_data|testdata|fixtures?)\//i;

/** Producto de endoflife.date para el sistema operativo de la foto. */
function osProduct(eq, eolData) {
  const name = { ubuntu: 'ubuntu', debian: 'debian', amzn: 'amazon-linux', rhel: 'rhel', rocky: 'rocky-linux', almalinux: 'almalinux', centos: 'centos', alpine: 'alpine-linux' }[eq.so_id];
  return name ? eolData?.byName?.get(name) || null : null;
}

/** Hallazgos de un servidor. Todos cuelgan de su tarjeta «servidores/<nombre>». */
export function serverFindings(h, { eolData = null } = {}) {
  const out = [];
  const file = hostRef(h);
  const add = (rule, severity, title, detail, fix) => out.push({ tool: 'lupa-servidor', cat: 'servidores', rule, severity, file, line: 1, host: h.nombre, title, detail, fix: `Arreglo en el servidor ${h.nombre} (${h.ipPrivada}): ${fix}` });
  const p = h.parches || {};

  // ---------------------------------------------------------------- sistema y parches
  const os = osProduct(h.equipo, eolData);
  const st = os ? eolStatus(os, h.equipo.so_version) : null;
  if (st?.estado === 'sin-soporte') add('so-sin-soporte', 'high', `${h.equipo.so} ya no recibe parches de seguridad (${h.nombre})`, `Su soporte acabó el ${st.finSoporte || '—'}. Cualquier fallo nuevo del sistema se queda sin arreglar.`, `actualiza el sistema operativo a una versión con soporte (${st.ultima || 'la última LTS'}), o migra el servicio a un servidor nuevo.`);
  else if (st?.estado === 'caduca-pronto') add('so-caduca', 'medium', `${h.equipo.so} se queda sin soporte el ${st.finSoporte} (${h.nombre})`, 'Quedan menos de seis meses de parches de seguridad.', 'planifica la actualización del sistema operativo antes de esa fecha.');
  if (p.seguridad > 0) {
    const sev = p.seguridad >= 10 ? 'high' : 'medium';
    add('parches-seguridad', sev, `${p.seguridad} parches de seguridad sin aplicar en ${h.nombre}`,
      `${p.pendientes ?? '?'} paquetes por actualizar, ${p.seguridad} de ellos de seguridad${p.ejemplos_seguridad?.length ? ` (${p.ejemplos_seguridad.slice(0, 6).join(', ')}…)` : ''}. ${p.automaticas ? '' : 'Las actualizaciones automáticas están apagadas. '}`.trim(),
      `aplica los parches de seguridad en una ventana planificada (${p.gestor === 'apt' ? 'sudo apt-get update && sudo apt-get upgrade' : 'sudo dnf upgrade --security'}), reinicia si lo pide y comprueba que el servicio vuelve.`);
  }
  if (p.gestor === 'apt' && p.listas_hace_dias > 7) add('listas-viejas', 'medium', `${h.nombre} lleva ${Math.round(p.listas_hace_dias)} días sin consultar las actualizaciones`,
    `Las listas de paquetes no se refrescan desde hace ${Math.round(p.listas_hace_dias)} días, así que las actualizaciones automáticas no ven los parches nuevos aunque estén encendidas, y el recuento de parches pendientes se queda corto. Suele ser un repositorio por http:// con el puerto 80 cerrado, o un proxy.`,
    'mira por qué falla «sudo apt-get update» (repositorios http:// con salida al 80 cerrada, proxy, DNS) y arréglalo para que las automáticas vuelvan a funcionar.');
  // Amazon Linux 2023 se queda en la versión con la que se instaló: los parches posteriores llegan como versión
  // nueva, así que dnf dice «0 pendientes» aunque la instancia lleve meses sin parchear
  const al = /2023\.\d+\.(\d{4})(\d{2})(\d{2})/.exec(h.equipo.so || '');
  if (h.equipo.so_id === 'amzn' && al && p.releasever !== 'latest') {
    const days = Math.floor((Date.now() - Date.UTC(+al[1], +al[2] - 1, +al[3])) / 86_400_000);
    if (days > 60) add('al2023-fijado', days > 120 ? 'high' : 'medium', `${h.nombre} sigue en Amazon Linux de hace ${days} días (${al[1]}-${al[2]}-${al[3]})`,
      `Amazon Linux 2023 deja el repositorio fijado en la versión con la que se instaló. Los parches de seguridad posteriores salen como versión nueva, así que dnf no los ve (por eso puede decir «0 pendientes») y las actualizaciones automáticas no los instalan.`,
      'mira qué hay con «sudo dnf check-release-update» y actualiza con «sudo dnf upgrade --releasever=latest» en una ventana; para que no vuelva a pasar, pon «latest» en /etc/dnf/vars/releasever o renueva la AMI con frecuencia.');
  }
  if (p.seguridad == null && p.gestor && p.gestor !== 'apt') add('parches-desconocidos', 'low', `No se pudo saber qué parches le faltan a ${h.nombre}`, 'dnf no tenía la caché de paquetes (nunca se refrescó o se limpió), así que el recuento de parches no es fiable.', 'ejecuta «sudo dnf makecache» y vuelve a pasar Lupa.');
  if (p.automaticas === false) add('sin-automaticas', p.seguridad > 0 ? 'medium' : 'low', `Las actualizaciones automáticas de seguridad están apagadas en ${h.nombre}`,
    'Los parches de seguridad solo entran cuando alguien se acuerda de aplicarlos.', p.gestor === 'apt' ? 'activa unattended-upgrades solo para el origen de seguridad (y fija los paquetes que no se deban tocar solos).' : 'activa dnf-automatic con upgrade_type = security.');
  if (p.reinicio_pendiente) add('reinicio-pendiente', 'low', `${h.nombre} tiene un reinicio pendiente (lleva ${Math.round(h.equipo.arrancado_hace_dias || 0)} días encendido)`,
    'Hay parches ya instalados (kernel o librerías) que no se usan hasta reiniciar.', 'programa un reinicio en una ventana de mantenimiento.');

  // ---------------------------------------------------------------- SSH y cuentas
  const ssh = h.ssh?.config || {};
  // sin la config leída no se sabe nada: mejor callar que dar un «acepta contraseñas» inventado
  if (h.ssh?.instalado && h.ssh?.activo !== false && h.ssh?.config_leida !== false) {
    if (ssh.passwordauthentication === 'yes') add('ssh-contrasena', 'high', `SSH acepta contraseñas en ${h.nombre}`, 'Cualquiera que llegue al puerto de SSH puede probar contraseñas a fuerza bruta.', 'pon PasswordAuthentication no y KbdInteractiveAuthentication no en /etc/ssh/sshd_config.d/, y entra solo con clave o con SSM.');
    if (ssh.permitrootlogin === 'yes') add('ssh-root', 'high', `SSH deja entrar como root con contraseña en ${h.nombre}`, 'root es el usuario que todo atacante prueba primero.', 'pon PermitRootLogin no.');
    if (ssh.permitemptypasswords === 'yes') add('ssh-vacia', 'high', `SSH acepta contraseñas vacías en ${h.nombre}`, 'Una cuenta sin contraseña es una puerta abierta.', 'pon PermitEmptyPasswords no.');
    if (ssh.x11forwarding === 'yes') add('ssh-x11', 'low', `SSH reenvía X11 en ${h.nombre}`, 'Un servidor no necesita ventanas gráficas, y el reenvío X11 amplía lo que un usuario remoto puede hacer.', 'pon X11Forwarding no.');
  }
  const extraRoot = (h.usuarios?.uid0 || []).filter((u) => u !== 'root');
  if (extraRoot.length) add('uid0', 'high', `${extraRoot.join(', ')} ${extraRoot.length === 1 ? 'tiene' : 'tienen'} los poderes de root en ${h.nombre}`, 'Una cuenta con UID 0 que no es root es una puerta trasera clásica.', `revisa de dónde sale ${extraRoot.join(', ')} y quítale el UID 0.`);
  const nopass = (h.usuarios?.sudo_sin_contrasena || []).filter((x) => x.todo && !CLOUD_USERS.has(x.quien.replace(/^%/, '')));
  if (nopass.length) add('sudo-sin-contrasena', 'medium', `${nopass.map((x) => x.quien).join(', ')} puede${nopass.length > 1 ? 'n' : ''} hacer de root sin contraseña en ${h.nombre}`, `Reglas NOPASSWD: ALL en ${[...new Set(nopass.map((x) => x.fichero))].join(', ')}.`, 'limita esas reglas a los comandos que de verdad hacen falta, o pide contraseña.');

  // ---------------------------------------------------------------- puertos y contenedores
  const docker = new Set((h.contenedores || []).flatMap((c) => (c.puertos || []).map((q) => q.puerto)));
  for (const e of h.escucha || []) {
    const r = RISKY_PORTS[e.puerto];
    if (!r || e.proto !== 'tcp' || !ALL_IFACES.has(e.ip) || docker.has(e.puerto)) continue;
    add(`escucha-${e.puerto}`, r.sev, `${r.que} escucha en todas las interfaces de ${h.nombre} (puerto ${e.puerto})`, `El proceso ${e.proceso || '?'} acepta conexiones de cualquier red que llegue al servidor; solo lo frena el cortafuegos de la nube.`, `haz que ${e.proceso || 'el servicio'} escuche solo en 127.0.0.1 o en la IP interna que lo necesita, y cierra el puerto ${e.puerto} en el grupo de seguridad salvo a quien lo use.`);
  }
  for (const c of h.contenedores || []) {
    const pub = (c.puertos || []).filter((q) => ALL_IFACES.has(q.ip));
    if (c.privilegiado) add('contenedor-privilegiado', 'high', `El contenedor ${c.nombre} corre en modo privilegiado en ${h.nombre}`, 'Un contenedor privilegiado tiene el servidor entero: quien lo comprometa es root del host.', `quita privileged: true a ${c.nombre} y da solo las capacidades que necesite.`);
    if (c.socket_docker) add('contenedor-socket', 'medium', `El contenedor ${c.nombre} tiene el socket de Docker de ${h.nombre}`, 'Con el socket de Docker se pueden lanzar contenedores privilegiados: quien controle ese contenedor controla el servidor. A veces es necesario (Cortex lanza así sus analizadores), pero entonces ese contenedor es tan sensible como el propio servidor.', `si ${c.nombre} no lo necesita, quita el montaje de /var/run/docker.sock; si lo necesita, ponlo detrás de un proxy del socket que solo permita las llamadas imprescindibles.`);
    if (c.monta_raiz) add('contenedor-monta-sistema', 'medium', `El contenedor ${c.nombre} monta carpetas del sistema de ${h.nombre}`, 'Montar /, /etc, /root, /proc o /sys deja leer o cambiar el servidor desde dentro del contenedor.', `monta solo la carpeta concreta que ${c.nombre} necesite, y en solo lectura.`);
    if (DB_IMAGE.test(c.imagen) && pub.length) add('contenedor-bd-abierta', 'medium', `La base de datos ${c.nombre} se publica en todas las interfaces de ${h.nombre} (${pub.map((q) => q.puerto).join(', ')})`, `Docker publica ${c.imagen.split('@')[0]} en 0.0.0.0, y además Docker se salta el cortafuegos del propio servidor. Solo la frena el grupo de seguridad.`, `en el docker-compose, publica ${c.nombre} en 127.0.0.1 («127.0.0.1:${pub[0].puerto}:${pub[0].puerto}») o no la publiques y usa la red interna de Docker.`);
    if (/:latest$|^[^:@]+$/.test(c.imagen.split('/').pop())) add('contenedor-latest', 'low', `El contenedor ${c.nombre} usa una imagen sin versión fija (${c.imagen.split('/').pop()}) en ${h.nombre}`, 'Con «latest» no se sabe qué versión corre ni se puede repetir el despliegue; una actualización rota o maliciosa entra sola.', `fija la imagen de ${c.nombre} a una versión o, mejor, a su digest sha256.`);
  }
  const rootCt = (h.contenedores || []).filter((c) => !c.privilegiado && ['root', '0', '0:0', ''].includes(String(c.usuario)));
  if (rootCt.length >= 2) add('contenedores-root', 'low', `${rootCt.length} contenedores corren como root en ${h.nombre}`, `${rootCt.map((c) => c.nombre).slice(0, 8).join(', ')}. Si alguien rompe la aplicación, ya es root dentro del contenedor y tiene más fácil saltar al servidor.`, 'añade un usuario sin privilegios (USER en el Dockerfile o user: en el compose) a los contenedores que no lo necesiten.');

  // ---------------------------------------------------------------- ficheros y vigilancia
  const leaks = (h.ficheros?.lista || []).filter((f) => f.legible_por_todos && !NOT_SECRET.test(f.ruta) && !/snakeoil/.test(f.ruta));
  if (leaks.length) add('ficheros-legibles', leaks.some((f) => f.clave_privada || /\.env$|\/\.env(\.|$)|credentials|\.pgpass|\.netrc|\.git-credentials|tfstate/.test(f.ruta)) ? 'high' : 'medium',
    `${leaks.length === 1 ? `${leaks[0].ruta} lo puede leer` : `${leaks.length} ficheros con secretos los puede leer`} cualquier usuario de ${h.nombre}`,
    `${leaks.slice(0, 6).map((f) => `${f.ruta} (${f.modo})`).join(', ')}${leaks.length > 6 ? ` y ${leaks.length - 6} más` : ''}. Cualquier cuenta o servicio del servidor, aunque no tenga nada que ver, puede leer esas credenciales.`,
    `quita el permiso de lectura a «otros» (chmod 600, o 640 con el grupo del servicio) a: ${leaks.slice(0, 10).map((f) => f.ruta).join(', ')}. Si alguno es una copia vieja (.bak), bórrala.`);
  const agentes = h.servicios?.agentes || [];
  if (!agentes.some((a) => DETECTION.includes(a))) add('sin-deteccion', 'medium', `${h.nombre} no tiene agente de detección`, `No corre Wazuh ni ningún EDR (${agentes.length ? `solo ${agentes.join(', ')}` : 'ningún agente'}). Si alguien entra, no salta ninguna alerta.`, 'instala y registra el agente de Wazuh (o el EDR de la empresa) y comprueba que aparece activo en la consola.');
  if (h.endurecimiento?.hora_sincronizada === false) add('hora', 'low', `La hora de ${h.nombre} no está sincronizada`, 'Con la hora mal, los logs no casan con los de otros sistemas y algunos certificados fallan.', 'activa chrony o systemd-timesyncd.');
  return out;
}

/** Una fila por servidor para la tabla del informe. */
export function serverSummary(h, findings, { eolData = null } = {}) {
  const mine = findings.filter((f) => f.host === h.nombre);
  const os = osProduct(h.equipo, eolData);
  return {
    nombre: h.nombre, ip: h.ipPrivada, ipPublica: h.ipPublica, so: h.equipo.so, soEstado: os ? eolStatus(os, h.equipo.so_version)?.estado || 'desconocido' : 'desconocido',
    parchesSeguridad: h.parches?.seguridad ?? null, parchesTotal: h.parches?.pendientes ?? null, listasViejas: h.parches?.gestor === 'apt' && h.parches?.listas_hace_dias > 7,
    automaticas: h.parches?.automaticas ?? null, reinicio: !!h.parches?.reinicio_pendiente, agentes: h.servicios?.agentes || [],
    contenedores: (h.contenedores || []).length, graves: mine.filter((f) => f.severity === 'high').length, aMirar: mine.filter((f) => f.severity === 'medium').length,
    root: h.equipo.root, generado: h.generado,
  };
}
