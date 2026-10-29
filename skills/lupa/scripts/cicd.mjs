#!/usr/bin/env node
// Lupa · el CI/CD por fuera del repo: la plataforma (GitHub o GitHub Enterprise, Bitbucket Cloud, Bitbucket Server),
// los logs de las últimas ejecuciones y, si se pide, los roles y usuarios de AWS que usa el CI. Todo en solo lectura
// y con la sesión del propio dev. Escribe floorplan/lupa/cicd.json; scan.mjs y merge.mjs lo meten en el informe.
//
//   node cicd.mjs <raíz> [--logs 15 | --sin-logs] [--aws [--region eu-west-1] [--perfil nombre]]
//
// Credenciales (variables de entorno; nunca se guardan ni se muestran):
//   GitHub             la sesión de «gh auth login», o GH_TOKEN / GITHUB_TOKEN
//   GitHub Enterprise  GH_HOST=<host> y la sesión de gh para ese host, o GH_ENTERPRISE_TOKEN
//   Bitbucket Cloud    BITBUCKET_EMAIL + BITBUCKET_API_TOKEN (token de API de Atlassian), o BITBUCKET_ACCESS_TOKEN
//   Bitbucket Server   BITBUCKET_SERVER_URL (p. ej. https://bitbucket.empresa.com) + BITBUCKET_SERVER_TOKEN
import fs from 'node:fs';
import path from 'node:path';
import { run, readJSON, writeJSON } from './lib/util.mjs';
import { findTool } from './lib/tools.mjs';
import { parseRemote } from './lib/cicd.mjs';
import { credentials, collectGitHub, collectBitbucketCloud, collectBitbucketServer, githubLogs, bitbucketLogs, scanLog, newWorkDir } from './lib/plataforma.mjs';

const argv = process.argv.slice(2);
const WITH_VALUE = new Set(['--logs', '--region', '--perfil']);
const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
// la raíz es el primer argumento que no es una opción ni el valor de una opción
const root = path.resolve(argv.find((a, i) => !a.startsWith('--') && !WITH_VALUE.has(argv[i - 1])) || '.');
const nLogs = argv.includes('--sin-logs') ? 0 : opt('--logs') != null ? Math.max(0, Math.min(50, Number(opt('--logs')) || 0)) : 15;
const out = path.join(root, 'floorplan', 'lupa', 'cicd.json');

const scan = readJSON(path.join(root, 'floorplan', '.cache', 'scan.json'), { repos: [] });
const repos = (scan.repos || []).length ? scan.repos.map((r) => r.path) : ['.'];
const COLLECT = { github: collectGitHub, 'bitbucket-cloud': collectBitbucketCloud, 'bitbucket-server': collectBitbucketServer };
const LOGS = { github: githubLogs, 'bitbucket-cloud': bitbucketLogs };
const HOW = {
  github: 'inicia sesión con «gh auth login» (o define GH_TOKEN; en GitHub Enterprise, GH_HOST y su sesión, o GH_ENTERPRISE_TOKEN)',
  'bitbucket-cloud': 'define BITBUCKET_EMAIL y BITBUCKET_API_TOKEN (un token de API de Atlassian con permisos de lectura de repositorio, pull requests, pipelines y webhooks)',
  'bitbucket-server': 'define BITBUCKET_SERVER_URL y BITBUCKET_SERVER_TOKEN (token de acceso personal con lectura del repositorio)',
};

// los logs pueden llevar secretos: van a una carpeta solo del usuario y se borran pase lo que pase
let work = null;
const cleanup = () => { if (work) { fs.rmSync(work, { recursive: true, force: true }); work = null; } };
process.on('exit', cleanup);
for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(s, () => { cleanup(); process.exit(130); });

const plataformas = [];
let awsData = null;
// se escribe a medida que termina cada repositorio: si el proceso se corta, lo hecho no se pierde
const save = () => writeJSON(out, { generadoEn: new Date().toISOString(), logsPedidos: nLogs, plataformas, aws: awsData });
const gitleaks = nLogs ? findTool('gitleaks') : null;

for (const rp of repos) {
  const dir = path.join(root, rp);
  const remote = run('git', ['-C', dir, 'remote', 'get-url', 'origin'], { timeout: 20_000 }).stdout.trim();
  const where = parseRemote(remote);
  const repoName = where.owner ? `${where.owner}/${where.repo}` : rp;
  const label = `${rp === '.' ? path.basename(root) : rp} (${where.plataforma}${where.owner ? `: ${repoName}` : ''})`;
  const entry = (extra) => ({ plataforma: where.plataforma, repo: repoName, ruta: rp, huecos: [], ...extra });
  if (!COLLECT[where.plataforma]) {
    plataformas.push(entry({ soloFicheros: true, huecos: [`la plataforma (${where.plataforma}${where.host ? `, ${where.host}` : ''}) no se revisa por API: solo sus ficheros de pipeline`] }));
    console.log(`  · ${label}: solo ficheros (la plataforma no se revisa por API)`);
    save(); continue;
  }
  // Bitbucket Server: el token solo viaja al host configurado en BITBUCKET_SERVER_URL, nunca al que diga un remoto
  if (where.plataforma === 'bitbucket-server') {
    let cfg = null; try { cfg = new URL(process.env.BITBUCKET_SERVER_URL || ''); } catch {}
    if (!cfg) { plataformas.push(entry({ error: 'sin BITBUCKET_SERVER_URL', huecos: [`toda la plataforma: ${HOW['bitbucket-server']}`] })); console.log(`  ✗ ${label}: falta BITBUCKET_SERVER_URL`); save(); continue; }
    if (cfg.hostname.toLowerCase() !== where.host) { plataformas.push(entry({ error: `el remoto es de ${where.host}, no de ${cfg.hostname}`, huecos: [`toda la plataforma: el remoto apunta a ${where.host}, que no es BITBUCKET_SERVER_URL; no se manda el token`] })); console.log(`  ✗ ${label}: el remoto no es del Bitbucket Server configurado; no se manda el token`); save(); continue; }
    where.base = cfg.origin + cfg.pathname.replace(/\/+$/, '');
  }
  const h = credentials(where.plataforma, { host: where.host });
  if (!h) {
    plataformas.push(entry({ error: 'sin credenciales', huecos: [`toda la plataforma: ${HOW[where.plataforma]}`] }));
    console.log(`  ✗ ${label}: sin credenciales; ${HOW[where.plataforma]}`);
    save(); continue;
  }
  const m = { ...(await COLLECT[where.plataforma](where, h)), ruta: rp };
  if (m.error) { console.log(`  ✗ ${label}: ${m.error}`); plataformas.push(m); save(); continue; }
  // logs de las últimas ejecuciones: una a una se bajan, se pasa gitleaks y se borran; con un plazo total
  if (nLogs && LOGS[where.plataforma]) {
    if (!gitleaks) m.huecos.push('los logs de las ejecuciones (falta gitleaks)');
    else {
      work = newWorkDir();
      const hallazgos = [];
      const res = await LOGS[where.plataforma](where, h, nLogs, work, (r1) => { const f = scanLog(gitleaks, r1); if (f) hallazgos.push(...f); return !!f; }, { signal: AbortSignal.timeout(8 * 60_000) });
      cleanup();
      m.logs = { revisadas: res.revisadas, hallazgos };
      m.huecos.push(...res.huecos);
    }
  }
  plataformas.push(m);
  save();
  const p = m.proteccion || {};
  console.log(`  ✓ ${label}: rama ${m.ramaPrincipal || '?'} ${p.conocida ? (p.existe ? 'protegida' : 'SIN proteger') : '(protección no visible)'} · ${m.revisionReal ? `${m.revisionReal.aprobados}/${m.revisionReal.cambios} cambios revisados` : 'revisión no visible'} · ${m.secretos.length} secretos · ${m.entornos.length} entornos · logs: ${m.logs ? `${m.logs.revisadas} ejecuciones, ${m.logs.hallazgos.length} secretos` : 'sin revisar'}${m.huecos.length ? ` · sin ver: ${m.huecos.length}` : ''}`);
}

// ---------------------------------------------------------------- AWS: los roles y usuarios que usa el CI
function aws(args) {
  const extra = [...(opt('--region') ? ['--region', opt('--region')] : []), ...(opt('--perfil') ? ['--profile', opt('--perfil')] : [])];
  const r = run('aws', [...args, ...extra, '--output', 'json'], { timeout: 120_000 });
  if (r.status !== 0) throw new Error(`aws ${args.slice(0, 2).join(' ')}: ${(r.stderr || '').trim().split('\n').pop()}`);
  return r.stdout.trim() ? JSON.parse(r.stdout) : {};
}
const PROVIDERS = [['GitHub', /token\.actions\.githubusercontent\.com|\.ghe\.com\/_services\/token|\/_services\/token/], ['Bitbucket', /api\.bitbucket\.org\/2\.0\/workspaces\/[^/]+\/pipelines-config\/identity\/oidc/], ['GitLab', /gitlab\.com|gitlab\./]];

/** Roles con confianza OIDC en una plataforma de CI que afectan a estos repos (los nombran o llevan comodines). */
function awsCi() {
  const names = plataformas.filter((p) => p.repo).map((p) => p.repo.toLowerCase());
  const uuids = plataformas.map((p) => p.uuid).filter(Boolean).map((u) => u.replace(/[{}]/g, '').toLowerCase());
  // la CLI de aws pagina sola
  const roles = aws(['iam', 'list-roles']).Roles || [];
  const found = [];
  for (const r of roles) {
    const doc = typeof r.AssumeRolePolicyDocument === 'string' ? JSON.parse(decodeURIComponent(r.AssumeRolePolicyDocument)) : r.AssumeRolePolicyDocument;
    for (const st of [].concat(doc?.Statement || [])) {
      const fed = [].concat(st.Principal?.Federated || []).join(' ');
      const prov = PROVIDERS.find(([, re]) => re.test(fed));
      if (!prov || st.Effect !== 'Allow') continue;
      const sub = Object.values(st.Condition || {}).flatMap((c) => Object.entries(c).filter(([k]) => /:sub$/.test(k)).flatMap(([, v]) => [].concat(v)));
      const mine = !sub.length || sub.some((s) => /^\*$|^repo:\*|^repo:[^/]+\/\*/.test(s) || names.some((n) => s.toLowerCase().includes(`repo:${n}`)) || uuids.some((u) => s.toLowerCase().includes(u)));
      if (!mine) continue;
      const pol = aws(['iam', 'list-attached-role-policies', '--role-name', r.RoleName]).AttachedPolicies || [];
      const inline = aws(['iam', 'list-role-policies', '--role-name', r.RoleName]).PolicyNames || [];
      let star = false;
      for (const n of inline) {
        const d = aws(['iam', 'get-role-policy', '--role-name', r.RoleName, '--policy-name', n]).PolicyDocument;
        star ||= [].concat(d?.Statement || []).some((s) => s.Effect === 'Allow' && [].concat(s.Action || []).includes('*') && [].concat(s.Resource || []).includes('*'));
      }
      found.push({ nombre: r.RoleName, proveedor: prov[0], sub, politicas: [...pol.map((p) => p.PolicyName), ...(star ? ['AdministratorAccess'] : [])] });
      break;
    }
  }
  const users = (aws(['iam', 'list-users']).Users || []).filter((u) => /(^|[-_.])(ci|cd|deploy|deployer|github|bitbucket|gitlab|jenkins|pipeline|bamboo|actions)([-_.]|$)/i.test(u.UserName));
  const usuarios = users.map((u) => ({ nombre: u.UserName, claves: (aws(['iam', 'list-access-keys', '--user-name', u.UserName]).AccessKeyMetadata || [])
    .map((k) => ({ estado: k.Status, dias: Math.floor((Date.now() - Date.parse(k.CreateDate)) / 86_400_000) })) }));
  return { cuenta: aws(['sts', 'get-caller-identity']).Account, roles: found, usuarios };
}

if (argv.includes('--aws')) {
  try { awsData = awsCi(); console.log(`  ✓ AWS ${awsData.cuenta}: ${awsData.roles.length} roles con confianza en el CI · ${awsData.usuarios.length} usuarios de CI`); }
  catch (e) { awsData = { error: e.message }; console.log(`  ✗ AWS: ${e.message}`); }
}
save();
console.log('✓ floorplan/lupa/cicd.json. Siguiente: scan.mjs (con --solo propios basta) y merge.mjs lo meten en el informe.');
