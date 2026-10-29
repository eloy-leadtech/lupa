#!/usr/bin/env node
// Lupa · recoger los servidores por SSM, para proyectos en AWS cuyos servidores tienen el agente de SSM.
// Manda servidor/lupa-servidor.py a cada uno, lo ejecuta como root y trae su foto a
// floorplan/lupa/servidores/<nombre>.json. Solo lee: trabaja en una carpeta propia de /run (solo root,
// distinta en cada pasada) que borra al acabar.
//
//   node servidores-ssm.mjs <raíz> --instancias i-aaa,i-bbb           [--region eu-west-1] [--perfil nombre]
//   node servidores-ssm.mjs <raíz> --vpc vpc-xxxx [--etiqueta Proyecto=Visas]   enseña la lista y no toca nada…
//   node servidores-ssm.mjs <raíz> --vpc vpc-xxxx --confirmar                   …hasta que se confirma
//   node servidores-ssm.mjs <raíz> --vpc vpc-xxxx --solo-red                    solo la red de AWS, sin entrar en los servidores
//
// Sin SSM, el mismo script va por ssh:  ssh servidor 'sudo python3 -I -' < lupa-servidor.py > servidor.json
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { run, writeJSON, tmpDir } from './lib/util.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const COLLECTOR = path.join(HERE, '..', 'servidor', 'lupa-servidor.py');
const argv = process.argv.slice(2);
const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const root = path.resolve(argv.find((a, i) => !a.startsWith('--') && !argv[i - 1]?.startsWith('--')) || '.');
const outDir = path.join(root, 'floorplan', 'lupa', 'servidores');
const SLICE = 20_000; // SSM corta la salida a 24.000 caracteres
// Una carpeta distinta en cada pasada y donde solo escribe root: con una ruta fija en /tmp, cualquier usuario
// del servidor podría crearla antes y colar código que root ejecutaría.
const WORK = `/run/lupa-srv-${crypto.randomBytes(8).toString('hex')}`;

function aws(args) {
  const extra = [...(opt('--region') ? ['--region', opt('--region')] : []), ...(opt('--perfil') ? ['--profile', opt('--perfil')] : [])];
  const r = run('aws', [...args, ...extra, '--output', 'json'], { timeout: 120_000 });
  if (r.status !== 0) throw new Error(`aws ${args.slice(0, 2).join(' ')}: ${(r.stderr || r.error?.message || '').trim().split('\n').pop()}`);
  return r.stdout.trim() ? JSON.parse(r.stdout) : {};
}

/** Las instancias a revisar, con un nombre único para cada una. Solo Linux y con el agente de SSM en línea. */
function instances() {
  const tag = opt('--etiqueta');
  const filters = opt('--vpc')
    ? ['--filters', `Name=vpc-id,Values=${opt('--vpc')}`, 'Name=instance-state-name,Values=running', ...(tag ? [`Name=tag:${tag.split('=')[0]},Values=${tag.split('=').slice(1).join('=')}`] : [])]
    : ['--instance-ids', ...(opt('--instancias') || '').split(',').filter(Boolean)];
  if (!opt('--vpc') && !opt('--instancias')) { console.error('Di qué servidores: --instancias i-aaa,i-bbb o --vpc vpc-xxxx'); process.exit(2); }
  const raw = aws(['ec2', 'describe-instances', ...filters]).Reservations.flatMap((r) => r.Instances);
  // en un grupo de autoescalado todas se llaman igual: se distinguen por el final de su id
  const nameOf = (i) => (i.Tags || []).find((t) => t.Key === 'Name')?.Value || i.InstanceId;
  const count = raw.reduce((m, i) => m.set(nameOf(i), (m.get(nameOf(i)) || 0) + 1), new Map());
  const list = raw.map((i) => ({
    id: i.InstanceId, nombre: count.get(nameOf(i)) > 1 ? `${nameOf(i)} (${i.InstanceId.slice(-6)})` : nameOf(i),
    ipPrivada: i.PrivateIpAddress || '', ipPublica: i.PublicIpAddress || '', vpc: i.VpcId, tipo: i.InstanceType,
    plataforma: i.PlatformDetails || '', gruposSeguridad: (i.SecurityGroups || []).map((g) => g.GroupId),
  }));
  const online = new Set(aws(['ssm', 'describe-instance-information', '--filters', 'Key=PingStatus,Values=Online']).InstanceInformationList
    .filter((x) => x.PlatformType === 'Linux').map((x) => x.InstanceId));
  for (const i of list) if (!online.has(i.id)) console.log(`  ✗ ${i.nombre} (${i.id}): sin SSM en línea o no es Linux; revísalo por ssh`);
  return { all: list, ok: list.filter((i) => online.has(i.id)) };
}

/** Balanceadores clásicos (ELB v1), con la misma forma que los de elbv2. */
function classicLbs(vpcs) {
  try {
    return aws(['elb', 'describe-load-balancers']).LoadBalancerDescriptions.filter((l) => vpcs.includes(l.VPCId)).map((l) => {
      const ls = (l.ListenerDescriptions || []).map((d) => d.Listener);
      return { nombre: l.LoadBalancerName, esquema: l.Scheme, tipo: 'classic', dns: l.DNSName, grupos: l.SecurityGroups || [],
        escuchas: ls.map((x) => ({ puerto: x.LoadBalancerPort, proto: x.Protocol, grupos: [`clasico-${x.InstancePort}`] })),
        destinos: (l.Instances || []).flatMap((i) => ls.map((x) => ({ destino: i.InstanceId, puerto: x.InstancePort, grupo: `clasico-${x.InstancePort}`, estado: '' }))) };
    });
  } catch (e) { console.log(`  · sin balanceadores clásicos (${e.message})`); return []; }
}

/**
 * La red vista desde AWS, solo lectura: qué es cada IP privada (instancias, endpoints, balanceadores…),
 * qué dejan entrar los grupos de seguridad y qué publican los balanceadores. Con esto el mapa de
 * comunicaciones pone nombre a cada IP y se sabe qué se ve desde internet.
 */
function awsNetwork(vpcs, running = []) {
  const f = ['--filters', `Name=vpc-id,Values=${vpcs.join(',')}`];
  const interfaces = aws(['ec2', 'describe-network-interfaces', ...f]).NetworkInterfaces.map((n) => ({
    ip: n.PrivateIpAddress, ips: (n.PrivateIpAddresses || []).map((p) => p.PrivateIpAddress), ipPublica: n.Association?.PublicIp || '',
    ipv6: (n.Ipv6Addresses || []).map((a) => a.Ipv6Address),
    tipo: n.InterfaceType, descripcion: n.Description || '', instancia: n.Attachment?.InstanceId || '', grupos: (n.Groups || []).map((g) => g.GroupId),
  }));
  const rule = (p) => ({ proto: p.IpProtocol, desde: p.FromPort ?? null, hasta: p.ToPort ?? null,
    origenes: [...(p.IpRanges || []).map((r) => r.CidrIp), ...(p.Ipv6Ranges || []).map((r) => r.CidrIpv6), ...(p.UserIdGroupPairs || []).map((g) => g.GroupId), ...(p.PrefixListIds || []).map((x) => x.PrefixListId)] });
  const gruposSeguridad = aws(['ec2', 'describe-security-groups', ...f]).SecurityGroups.map((g) => ({
    id: g.GroupId, nombre: g.GroupName, descripcion: g.Description || '', entradas: (g.IpPermissions || []).map(rule), salidas: (g.IpPermissionsEgress || []).map(rule),
  }));
  const balanceadores = [];
  for (const lb of aws(['elbv2', 'describe-load-balancers']).LoadBalancers.filter((l) => vpcs.includes(l.VpcId))) {
    const tgs = aws(['elbv2', 'describe-target-groups', '--load-balancer-arn', lb.LoadBalancerArn]).TargetGroups;
    const tgName = new Map(tgs.map((t) => [t.TargetGroupArn, t.TargetGroupName]));
    const escuchas = aws(['elbv2', 'describe-listeners', '--load-balancer-arn', lb.LoadBalancerArn]).Listeners.map((l) => ({
      puerto: l.Port, proto: l.Protocol,
      grupos: (l.DefaultActions || []).flatMap((a) => [a.TargetGroupArn, ...(a.ForwardConfig?.TargetGroups || []).map((t) => t.TargetGroupArn)]).filter(Boolean).map((a) => tgName.get(a) || a),
    }));
    const destinos = [];
    for (const tg of tgs) {
      for (const t of aws(['elbv2', 'describe-target-health', '--target-group-arn', tg.TargetGroupArn]).TargetHealthDescriptions) {
        destinos.push({ destino: t.Target.Id, puerto: t.Target.Port, grupo: tg.TargetGroupName, estado: t.TargetHealth?.State || '' });
      }
    }
    balanceadores.push({ nombre: lb.LoadBalancerName, esquema: lb.Scheme, tipo: lb.Type, dns: lb.DNSName, grupos: lb.SecurityGroups || [], escuchas, destinos });
  }
  balanceadores.push(...classicLbs(vpcs));
  // los endpoints de VPC, con el servicio que dan (ssm, guardduty, ecr…), para nombrar sus IP
  const endpoints = aws(['ec2', 'describe-vpc-endpoints', ...f]).VpcEndpoints.map((e) => ({ id: e.VpcEndpointId, servicio: e.ServiceName.split('.').slice(3).join('.') || e.ServiceName, tipo: e.VpcEndpointType }));
  // destinos de balanceadores que no están entre las instancias en marcha (paradas o de otra VPC): al menos su nombre y estado
  const known = new Set(running);
  const foreign = [...new Set(balanceadores.flatMap((b) => b.destinos.map((d) => d.destino)).filter((d) => /^i-/.test(d) && !known.has(d)))];
  const externas = foreign.length ? aws(['ec2', 'describe-instances', '--instance-ids', ...foreign]).Reservations.flatMap((r) => r.Instances)
    .map((i) => ({ id: i.InstanceId, nombre: (i.Tags || []).find((t) => t.Key === 'Name')?.Value || i.InstanceId, estado: i.State?.Name, vpc: i.VpcId })) : [];
  return { vpcs, interfaces, gruposSeguridad, balanceadores, endpoints, instanciasExternas: externas };
}

/** Manda un comando a varias instancias y espera. Devuelve { id: salida } de las que acabaron bien. */
function sendAndWait(ids, commands, comment) {
  const params = path.join(fs.mkdtempSync(path.join(tmpDir(), 'lupa-ssm-')), 'p.json');
  fs.writeFileSync(params, JSON.stringify({ commands, executionTimeout: ['900'] }));
  const out = {};
  for (let k = 0; k < ids.length; k += 50) {
    const batch = ids.slice(k, k + 50);
    const cmd = aws(['ssm', 'send-command', '--document-name', 'AWS-RunShellScript', '--comment', comment, '--instance-ids', ...batch, '--parameters', 'file://' + params, '--timeout-seconds', '600']).Command;
    const deadline = Date.now() + 15 * 60_000;
    const pending = new Set(batch);
    while (pending.size && Date.now() < deadline) {
      run(process.execPath, ['-e', 'setTimeout(()=>{},4000)']);
      for (const inv of aws(['ssm', 'list-command-invocations', '--command-id', cmd.CommandId]).CommandInvocations || []) {
        if (!pending.has(inv.InstanceId) || ['Pending', 'InProgress', 'Delayed'].includes(inv.Status)) continue;
        pending.delete(inv.InstanceId);
        const r = aws(['ssm', 'get-command-invocation', '--command-id', cmd.CommandId, '--instance-id', inv.InstanceId]);
        if (r.Status === 'Success') out[inv.InstanceId] = r.StandardOutputContent || '';
        else console.log(`  ✗ ${inv.InstanceId}: ${r.Status} ${(r.StandardErrorContent || r.StandardOutputContent || '').trim().slice(-300)}`);
      }
    }
    for (const id of pending) console.log(`  ✗ ${id}: no acabó a tiempo`);
  }
  fs.rmSync(path.dirname(params), { recursive: true, force: true });
  return out;
}

const code = Buffer.from(fs.readFileSync(COLLECTOR, 'latin1').replace(/\r\n/g, '\n'), 'latin1');
const sha = crypto.createHash('sha256').update(code).digest('hex');
const b64 = zlib.gzipSync(code, { level: 9 }).toString('base64');
// SSM lo ejecuta con sh (dash en Ubuntu): sin pipefail, así que el código de salida del auditor se guarda a mano
const setup = [
  'set -e', 'umask 077', `W=${WORK}`,
  // sin -p: si la carpeta ya existe, no es nuestra y se aborta
  'mkdir -m 700 "$W"',
  ...b64.match(/.{1,3000}/g).map((x) => `printf %s '${x}' >> "$W/s.b64"`),
  'base64 -d "$W/s.b64" | gunzip > "$W/lupa-servidor.py"',
  // si el script no llega idéntico, no se ejecuta
  `echo '${sha}  '"$W/lupa-servidor.py" | sha256sum -c --quiet`,
  // -I: Python no busca módulos junto al script ni en la carpeta actual; -B: no escribe .pyc
  'rc=0; timeout 600 python3 -I -B "$W/lupa-servidor.py" > "$W/out.json" 2> "$W/err" || rc=$?',
  'gzip -9 -c "$W/out.json" | base64 -w0 > "$W/out.b64"',
  'echo "LUPA_RC=$rc"', 'echo "LUPA_LEN=$(wc -c < "$W/out.b64")"',
  `echo "LUPA_ERR=$(tail -c 300 "$W/err" | tr '\\n' ' ' | tr -cd '\\40-\\176')"`,
];

const { all, ok } = instances();
console.log(`LUPA  servidores por SSM: ${ok.length} de ${all.length}`);
for (const i of all) console.log(`  · ${i.nombre} (${i.id}, ${i.ipPrivada}${i.ipPublica ? `, pública ${i.ipPublica}` : ''})`);
// una VPC puede ser compartida: antes de ejecutar nada como root en servidores, que alguien confirme la lista
if (opt('--vpc') && !argv.includes('--confirmar') && !argv.includes('--solo-red')) {
  console.log('\nNo he tocado nada. Si todos son del proyecto, repite con --confirmar (o filtra con --etiqueta Clave=Valor, o usa --instancias).');
  process.exit(0);
}
try {
  const red = awsNetwork([...new Set(all.map((i) => i.vpc).filter(Boolean))], all.map((i) => i.id));
  writeJSON(path.join(root, 'floorplan', 'lupa', 'red-aws.json'), { generadoEn: new Date().toISOString(), instancias: all, ...red });
  console.log(`  red de AWS: ${red.interfaces.length} interfaces · ${red.gruposSeguridad.length} grupos de seguridad · ${red.balanceadores.length} balanceadores`);
} catch (e) { console.log(`  ✗ no pude leer la red de AWS (${e.message}): el mapa de comunicaciones irá sin nombres de AWS`); }
if (argv.includes('--solo-red')) process.exit(0);

const first = sendAndWait(ok.map((i) => i.id), setup, 'Lupa: foto de solo lectura del servidor');
const field = (o, k) => (new RegExp(`${k}=(.*)`).exec(o) || [])[1]?.trim() || '';
const len = Object.fromEntries(Object.entries(first).map(([id, o]) => [id, +field(o, 'LUPA_LEN') || 0]));
const chunks = Object.fromEntries(Object.keys(len).map((id) => [id, []]));
for (let from = 1; Object.values(len).some((n) => n >= from); from += SLICE) {
  const ids = Object.keys(len).filter((id) => len[id] >= from);
  const cmd = [`cut -c ${from}-${from + SLICE - 1} ${WORK}/out.b64`];
  const got = sendAndWait(ids, cmd, 'Lupa: recoger la foto');
  // un trozo perdido estropea la foto entera: se pide otra vez antes de rendirse
  const missing = ids.filter((id) => !got[id]?.trim());
  if (missing.length) Object.assign(got, sendAndWait(missing, cmd, 'Lupa: recoger la foto (reintento)'));
  for (const id of ids) chunks[id].push((got[id] || '').trim());
}
sendAndWait(ok.map((i) => i.id), [`rm -rf ${WORK}`], 'Lupa: limpiar la carpeta de trabajo');

fs.mkdirSync(outDir, { recursive: true });
const used = new Set();
let saved = 0;
for (const i of ok) {
  const rc = field(first[i.id] || '', 'LUPA_RC'), err = field(first[i.id] || '', 'LUPA_ERR');
  if (!(i.id in first)) continue;
  if (rc && rc !== '0') console.log(`  ⚠ ${i.nombre}: el auditor acabó con código ${rc}${rc === '124' ? ' (se le acabó el tiempo)' : ''}${err ? `: ${err}` : ''}`);
  try {
    const foto = JSON.parse(zlib.gunzipSync(Buffer.from(chunks[i.id]?.join('') || '', 'base64')).toString('utf8'));
    // nombre de fichero seguro y único (dos «web» de un autoescalado, o «web 1» y «web-1»)
    let name = i.nombre.replace(/[^\w.-]+/g, '-').replace(/^[.-]+/, '') || i.id;
    if (used.has(name)) name = `${name}-${i.id}`;
    used.add(name);
    writeJSON(path.join(outDir, `${name}.json`), { aws: i, ...foto });
    saved++;
    console.log(`  ✓ ${i.nombre.padEnd(34)} ${foto.equipo?.so || ''} · ${foto.segundos} s`);
  } catch (e) { console.log(`  ✗ ${i.nombre}: no pude leer su foto (${len[i.id] || 0} caracteres)${err ? `. Error en el servidor: ${err}` : `: ${e.message}`}`); }
}
console.log(`✓ ${saved} servidor(es) en ${path.relative(root, outDir)}. Siguiente: scan.mjs y merge.mjs los meten en el informe.`);
