// La plataforma donde vive el código (GitHub o GitHub Enterprise, Bitbucket Cloud, Bitbucket Server/Data Center),
// en solo lectura y con la sesión del propio dev. Todas devuelven el mismo modelo, para que las reglas de cicd.mjs
// las midan igual. Lo que no se puede leer (falta de permiso, API que no existe, tiempo) queda en «huecos» con su
// código HTTP: no se da por bueno.
//
// Nunca se guarda el valor de un secreto ni de una variable, ni la URL entera de un webhook (puede llevar un token).
// El token solo viaja al host de su plataforma: las páginas siguientes de una lista se piden solo si son del mismo origen.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run, posix, readJSON } from './util.mjs';
import { runTool } from './tools.mjs';

const UA = { 'user-agent': 'lupa-security-audit' };
const origin = (u) => { try { return new URL(u).origin; } catch { return null; } };

/** GET a una API. Devuelve { ok, status, data } y nunca lanza: un 403/404 es un dato, no un error. */
async function get(url, headers, { raw = false, max = 0, signal = null } = {}) {
  try {
    const sig = signal ? AbortSignal.any([signal, AbortSignal.timeout(60_000)]) : AbortSignal.timeout(60_000);
    const r = await fetch(url, { headers: { ...UA, ...headers }, redirect: 'follow', signal: sig });
    if (!r.ok) return { ok: false, status: r.status, data: null };
    if (raw) {
      // lo que pase del tope no se lee entero en memoria
      if (max && +(r.headers.get('content-length') || 0) > max) { await r.body?.cancel?.(); return { ok: false, status: 413, data: null }; }
      const buf = Buffer.from(await r.arrayBuffer());
      return max && buf.length > max ? { ok: false, status: 413, data: null } : { ok: true, status: r.status, data: buf };
    }
    return { ok: true, status: r.status, data: r.status === 204 ? null : await r.json().catch(() => null), link: r.headers.get('link') || '' };
  } catch (e) { return { ok: false, status: 0, data: null, error: e.name === 'TimeoutError' || e.name === 'AbortError' ? 'tiempo agotado' : e.message }; }
}

/**
 * Una lista paginada (GitHub: cabecera Link; Bitbucket Cloud: «next»; Bitbucket Server: isLastPage/nextPageStart),
 * con tope de páginas. Las páginas de otro origen no se piden: el token no sale de su plataforma.
 */
export async function list(url, h, kind, { key = null, maxPages = 10 } = {}) {
  const values = []; let next = url, pages = 0;
  while (next && pages < maxPages) {
    const r = await get(next, h); pages++;
    if (!r.ok) return { ok: false, status: r.status, values };
    if (kind === 'github') { values.push(...((key ? r.data?.[key] : r.data) || [])); next = /<([^>]+)>;\s*rel="next"/.exec(r.link)?.[1] || null; }
    else if (kind === 'cloud') { values.push(...(r.data?.values || [])); next = r.data?.next || null; }
    else { values.push(...(r.data?.values || [])); next = r.data?.isLastPage === false && r.data?.nextPageStart != null ? `${url}${url.includes('?') ? '&' : '?'}start=${r.data.nextPageStart}` : null; }
    if (next && origin(next) !== origin(url)) next = null;
  }
  return { ok: true, status: 200, values, truncado: !!next };
}

/** Credenciales de cada plataforma, de las variables de entorno o de la sesión de gh. Nunca se guardan ni se muestran. */
export function credentials(plataforma, { host = 'github.com' } = {}) {
  const env = process.env;
  if (plataforma === 'github') {
    const enterprise = host !== 'github.com';
    const t = (enterprise ? env.GH_ENTERPRISE_TOKEN : env.GH_TOKEN || env.GITHUB_TOKEN) || run('gh', ['auth', 'token', ...(enterprise ? ['--hostname', host] : [])], { timeout: 20_000 }).stdout.trim();
    return t ? { authorization: `Bearer ${t}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' } : null;
  }
  if (plataforma === 'bitbucket-cloud') {
    if (env.BITBUCKET_ACCESS_TOKEN) return { authorization: `Bearer ${env.BITBUCKET_ACCESS_TOKEN}` };
    // los tokens de API de Atlassian van con el email de la cuenta (las contraseñas de aplicación ya no funcionan)
    return env.BITBUCKET_EMAIL && env.BITBUCKET_API_TOKEN ? { authorization: `Basic ${Buffer.from(`${env.BITBUCKET_EMAIL}:${env.BITBUCKET_API_TOKEN}`).toString('base64')}` } : null;
  }
  if (plataforma === 'bitbucket-server') return env.BITBUCKET_SERVER_TOKEN ? { authorization: `Bearer ${env.BITBUCKET_SERVER_TOKEN}` } : null;
  return null;
}

/** ¿Cumple el nombre de rama un patrón glob de las plataformas («release/*», «**»)? */
export function branchMatches(pattern, branch) {
  const re = '^' + String(pattern).split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
  return new RegExp(re).test(branch);
}

// nombres de secreto: por palabras (no «KEY» dentro de «KEYCLOAK_URL») y sin lo que es público por diseño
const NOT_SECRET = /PUBLIC|PUBLISHABLE|_(ID|URL|URI|NAME|HOST|PORT|EXPIRY|EXPIRES|TTL|SECONDS|PATH|FILE|ARN|REGION)$/i;
const SECRET_WORDS = /(^|_)(PASS(WORD)?|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)(_|$)/i;
export const secretName = (n) => /(^|_)(DATABASE_URL|DSN|CONNECTION_STRING)$/i.test(n) || (SECRET_WORDS.test(n) && !NOT_SECRET.test(n));
/** ¿Tiene el valor pinta de secreto? Se mira y se descarta: nunca se guarda. */
const valueLooksSecret = (v) => typeof v === 'string' && (/:\/\/[^\s:/@]+:[^\s@]+@/.test(v) || (v.length >= 16 && /[A-Za-z]/.test(v) && /\d/.test(v) && !/\s/.test(v)));
const isProd = (n) => /(^|[-_ ])(prod|production|producci[oó]n|live|prd)([-_ ]|$)/i.test(n) && !/(pre|non|no)[-_ ]?prod/i.test(n);

const hostOnly = (u) => { try { const x = new URL(u); return { url: `${x.protocol}//${x.host}`, host: x.host }; } catch { return { url: '', host: '?' }; } };
const empty = (plataforma, repo) => ({ plataforma, repo, privado: null, ramaPrincipal: null, proteccion: { conocida: false }, revisionReal: null, ci: {}, secretos: [], entornos: [], entornosLeidos: false,
  clavesDespliegue: [], webhooks: [], colaboradoresExternos: [], alertas: {}, seguridad: {}, logs: null, huecos: [] });
const why = (r) => (r.status ? `HTTP ${r.status}` : r.error || 'sin respuesta');

// ---------------------------------------------------------------- GitHub (y GitHub Enterprise)
export async function collectGitHub({ owner, repo, api: apiBase = 'https://api.github.com' }, h) {
  const base = `${apiBase}/repos/${owner}/${repo}`;
  const api = (p) => get(base + p, h);
  const lst = (p, key) => list(base + p, h, 'github', { key });
  const m = empty('github', `${owner}/${repo}`);
  const gap = (que, r) => m.huecos.push(r ? `${que} (${why(r)})` : que);
  const info = await api('');
  if (!info.ok) return { ...m, error: `GitHub respondió ${why(info)} al leer el repositorio` };
  const admin = !!info.data.permissions?.admin;
  // en una cuenta personal gratuita, GitHub no deja proteger ramas ni pedir aprobación en entornos de repos privados
  Object.assign(m, { privado: info.data.private, ramaPrincipal: info.data.default_branch, admin, cuentaPersonal: info.data.owner?.type === 'User' });
  const b = m.ramaPrincipal;
  // la rama: lo básico lo ve cualquiera; el detalle de la protección clásica solo un administrador; las reglas (rulesets) todos
  const branch = await api(`/branches/${encodeURIComponent(b)}`);
  const rules = await api(`/rules/branches/${encodeURIComponent(b)}`);
  if (!branch.ok) gap('la rama principal', branch);
  const rl = Array.isArray(rules.data) ? rules.data : [];
  const prRule = rl.find((r) => r.type === 'pull_request');
  const p = { conocida: branch.ok, existe: !!branch.data?.protected || rl.length > 0, exigePR: prRule ? true : null, aprobaciones: prRule ? prRule.parameters?.required_approving_review_count ?? 0 : null,
    forcePush: rl.some((r) => r.type === 'non_fast_forward') ? false : null, borrar: rl.some((r) => r.type === 'deletion') ? false : null, aplicada: true, adminsExentos: null };
  if (branch.data?.protected) {
    const prot = await api(`/branches/${encodeURIComponent(b)}/protection`);
    if (prot.ok) {
      const rv = prot.data.required_pull_request_reviews;
      p.exigePR = p.exigePR || !!rv;
      p.aprobaciones = Math.max(p.aprobaciones ?? 0, rv?.required_approving_review_count ?? 0);
      p.forcePush = p.forcePush === false ? false : !!prot.data.allow_force_pushes?.enabled;
      p.borrar = p.borrar === false ? false : !!prot.data.allow_deletions?.enabled;
      p.adminsExentos = !prot.data.enforce_admins?.enabled;
    } else gap('el detalle de la protección de la rama (hace falta ser administrador del repo)', prot);
  }
  if (p.existe && p.exigePR === null && !branch.data?.protected) p.exigePR = false;
  m.proteccion = p;
  // la revisión de verdad: cada cambio de la rama principal, ¿llegó por un PR aprobado por otra persona?
  // Un commit sin PR (también un merge hecho en local y subido) es un cambio directo.
  const commits = await api(`/commits?sha=${encodeURIComponent(b)}&per_page=30`);
  if (commits.ok) {
    const prs = new Map(); let directos = 0, desconocidos = 0;
    for (const c of commits.data || []) {
      const assoc = await api(`/commits/${c.sha}/pulls`);
      if (!assoc.ok) { desconocidos++; continue; }
      const pr = (assoc.data || []).find((x) => x.merged_at);
      if (!pr) { directos++; continue; }
      if (prs.has(pr.number)) continue;
      const rev = await lst(`/pulls/${pr.number}/reviews?per_page=100`);
      prs.set(pr.number, rev.values.some((r) => r.state === 'APPROVED' && r.user?.login !== pr.user?.login));
    }
    if (desconocidos * 3 > (commits.data || []).length) gap(`la revisión de los últimos cambios (${desconocidos} commits sin respuesta de la API)`);
    else m.revisionReal = { cambios: prs.size + directos, aprobados: [...prs.values()].filter(Boolean).length, directos };
  } else gap('los últimos cambios de la rama principal', commits);
  // el CI y lo que solo ve un administrador
  if (admin) {
    const perm = await api('/actions/permissions'), wf = await api('/actions/permissions/workflow');
    m.ci = { sistema: 'github-actions', accionesPermitidas: perm.data?.allowed_actions || null, permisosPorDefecto: wf.data?.default_workflow_permissions || null, puedeAprobarPRs: !!wf.data?.can_approve_pull_request_reviews };
    const runners = await api('/actions/runners?per_page=1');
    m.ci.runnersPropios = runners.ok ? (runners.data?.total_count || 0) > 0 : null;
    const keys = await lst('/keys?per_page=100');
    if (keys.ok) m.clavesDespliegue = keys.values.map((k) => ({ titulo: k.title, escritura: !k.read_only, creada: k.created_at })); else gap('las claves de despliegue', keys);
    const hooks = await lst('/hooks?per_page=100');
    if (hooks.ok) m.webhooks = hooks.values.map((w) => ({ ...hostOnly(w.config?.url), verificaTls: String(w.config?.insecure_ssl) !== '1' })); else gap('los webhooks', hooks);
    const sa = info.data.security_and_analysis || {};
    m.seguridad = { escaneoSecretos: sa.secret_scanning ? sa.secret_scanning.status === 'enabled' : null, proteccionPush: sa.secret_scanning_push_protection ? sa.secret_scanning_push_protection.status === 'enabled' : null };
  } else gap('permisos del CI, runners, claves de despliegue, webhooks y ajustes de seguridad (hace falta ser administrador del repo)');
  const sec = await lst('/actions/secrets?per_page=100', 'secrets');
  if (sec.ok) m.secretos.push(...sec.values.map((s) => ({ nombre: s.name, ambito: 'repo', protegido: true }))); else gap('los nombres de los secretos del repositorio', sec);
  const org = await lst('/actions/organization-secrets?per_page=100', 'secrets');
  if (org.ok) m.secretos.push(...org.values.map((s) => ({ nombre: s.name, ambito: 'organización', protegido: true })));
  const envs = await lst('/environments?per_page=100', 'environments');
  if (envs.ok) {
    m.entornosLeidos = true;
    for (const e of envs.values) {
      m.entornos.push({ nombre: e.name, produccion: isProd(e.name), aprobacion: (e.protection_rules || []).some((r) => r.type === 'required_reviewers') });
      const es = await lst(`/environments/${encodeURIComponent(e.name)}/secrets?per_page=100`, 'secrets');
      if (es.ok) m.secretos.push(...es.values.map((s) => ({ nombre: s.name, ambito: `entorno ${e.name}`, protegido: true }))); else gap(`los secretos del entorno ${e.name}`, es);
    }
  } else gap('los entornos de despliegue', envs);
  // «externo» solo tiene sentido en una organización: en una cuenta personal todo el que no es el dueño lo es
  if (!m.cuentaPersonal) {
    const outside = await lst('/collaborators?affiliation=outside&per_page=100');
    if (outside.ok) m.colaboradoresExternos = outside.values.map((c) => ({ usuario: c.login, permiso: c.role_name || (c.permissions?.admin ? 'admin' : c.permissions?.push ? 'write' : 'read') }));
  }
  const ss = await lst('/secret-scanning/alerts?state=open&per_page=100');
  if (ss.ok) { m.alertas.secretos = ss.values.length; m.alertas.tiposSecretos = [...new Set(ss.values.map((a) => a.secret_type_display_name || a.secret_type))]; }
  else gap('las alertas de secretos de GitHub', ss);
  const dep = await lst('/dependabot/alerts?state=open&severity=critical,high&per_page=100');
  if (dep.ok) m.alertas.dependenciasGraves = dep.values.length;
  return m;
}

/**
 * Las últimas ejecuciones de GitHub Actions, una a una: se baja el zip de sus logs, se pasa por scan(fichero) y se
 * borra antes de pedir la siguiente. Devuelve cuántas se revisaron y los huecos.
 */
export async function githubLogs({ owner, repo, api: apiBase = 'https://api.github.com' }, h, n, dir, scan, { signal } = {}) {
  const base = `${apiBase}/repos/${owner}/${repo}`;
  const runs = await get(`${base}/actions/runs?per_page=${n}&status=completed`, h, { signal });
  if (!runs.ok) return { revisadas: 0, huecos: [`los logs de las ejecuciones (${why(runs)})`] };
  let revisadas = 0; const huecos = [];
  for (const r of runs.data?.workflow_runs || []) {
    if (signal?.aborted) { huecos.push('no dio tiempo a revisar todos los logs'); break; }
    const z = await get(`${base}/actions/runs/${r.id}/logs`, h, { raw: true, max: 100 * 1024 * 1024, signal });
    if (!z.ok) { huecos.push(`los logs de la ejecución ${r.id} (${why(z)})`); continue; }
    const file = path.join(dir, `${String(r.id).replace(/\D/g, '')}.zip`);
    fs.writeFileSync(file, z.data);
    try { if (scan({ id: String(r.id), pipeline: r.name || r.path || 'workflow', path: file })) revisadas++; else huecos.push(`gitleaks falló con los logs de la ejecución ${r.id}`); }
    finally { fs.rmSync(file, { force: true }); }
  }
  return { revisadas, huecos };
}

// ---------------------------------------------------------------- Bitbucket Cloud
export async function collectBitbucketCloud({ owner, repo }, h) {
  const base = `https://api.bitbucket.org/2.0/repositories/${owner}/${repo}`;
  const api = (p) => get(base + p, h);
  const lst = (p) => list(base + p, h, 'cloud');
  const m = empty('bitbucket-cloud', `${owner}/${repo}`);
  const gap = (que, r) => m.huecos.push(r ? `${que} (${why(r)})` : que);
  const info = await api('');
  if (!info.ok) return { ...m, error: `Bitbucket respondió ${why(info)} al leer el repositorio` };
  Object.assign(m, { privado: info.data.is_private, ramaPrincipal: info.data.mainbranch?.name || null, uuid: info.data.uuid });
  const b = m.ramaPrincipal;
  // el modelo de ramas dice qué rama es «development» y cuál «production»: una restricción por modelo solo cuenta si es la principal
  const bm = await api('/branching-model');
  const modelBranch = (t) => { const x = bm.data?.[t]; return !x ? null : x.use_mainbranch ? b : x.branch?.name || x.name || null; };
  const br = b ? await lst('/branch-restrictions?pagelen=100') : { ok: false, status: 0 };
  if (br.ok) {
    const mine = br.values.filter((r) => (r.branch_match_kind === 'glob' && branchMatches(r.pattern, b)) || (r.branch_match_kind === 'branching_model' && modelBranch(r.branch_type) === b));
    const kinds = new Set(mine.map((r) => r.kind));
    const push = mine.find((r) => r.kind === 'push');
    const approvals = Math.max(0, ...mine.filter((r) => /require_.*approvals_to_merge/.test(r.kind)).map((r) => r.value || 0));
    m.proteccion = { conocida: true, existe: mine.length > 0, exigePR: !!push && !(push.users || []).length && !(push.groups || []).length, aprobaciones: approvals,
      forcePush: !kinds.has('force'), borrar: !kinds.has('delete'), aplicada: approvals > 0 ? kinds.has('enforce_merge_checks') : null, adminsExentos: null };
  } else gap('las restricciones de la rama principal (hace falta permiso de administrador del repo)', br);
  // la revisión de verdad: PR mergeados a la rama principal y aprobados por otra persona, más los commits directos
  // de la cadena del primer padre (los commits de una rama de PR traída con un merge no son «directos»)
  const q = encodeURIComponent(`destination.branch.name="${b}"`);
  const prs = await get(`${base}/pullrequests?state=MERGED&q=${q}&sort=-updated_on&pagelen=30&fields=%2Bvalues.participants`, h);
  const commits = await api(`/commits/${encodeURIComponent(b)}?pagelen=50`);
  const list0 = prs.data?.values || [];
  if (prs.ok && commits.ok && (!list0.length || list0.some((p) => Array.isArray(p.participants)))) {
    const byHash = new Map((commits.data?.values || []).map((c) => [c.hash, c]));
    let c = (commits.data?.values || [])[0], directos = 0, steps = 0;
    while (c && steps++ < 30) {
      if ((c.parents || []).length < 2 && !/pull request #\d+/i.test(c.message || '')) directos++;
      c = byHash.get(c.parents?.[0]?.hash);
    }
    m.revisionReal = { cambios: list0.length + directos, aprobados: list0.filter((p) => (p.participants || []).some((x) => x.approved && x.user?.uuid !== p.author?.uuid)).length, directos };
  } else gap('la revisión de los últimos cambios', prs.ok ? commits : prs);
  const pc = await api('/pipelines_config');
  m.ci = { sistema: 'bitbucket-pipelines', activo: pc.ok ? !!pc.data?.enabled : null };
  // variables: solo el nombre, si están protegidas y si el valor tiene pinta de secreto; el valor se descarta aquí
  const vars = await lst('/pipelines_config/variables?pagelen=100');
  if (vars.ok) m.secretos.push(...vars.values.map((v) => ({ nombre: v.key, ambito: 'repo', protegido: !!v.secured, valorPareceSecreto: v.secured ? null : valueLooksSecret(v.value) })));
  else gap('las variables de Pipelines del repositorio', vars);
  const wvars = await list(`https://api.bitbucket.org/2.0/workspaces/${owner}/pipelines-config/variables?pagelen=100`, h, 'cloud');
  if (wvars.ok) m.secretos.push(...wvars.values.map((v) => ({ nombre: v.key, ambito: 'workspace', protegido: !!v.secured, valorPareceSecreto: v.secured ? null : valueLooksSecret(v.value) })));
  const envs = await lst('/environments?pagelen=100');
  if (envs.ok) {
    m.entornosLeidos = true;
    for (const e of envs.values) {
      m.entornos.push({ nombre: e.name, produccion: /production/i.test(e.environment_type?.name || '') || isProd(e.name), aprobacion: e.restrictions?.admin_only === true });
      const ev = await lst(`/deployments_config/environments/${encodeURIComponent(e.uuid)}/variables?pagelen=100`);
      if (ev.ok) m.secretos.push(...ev.values.map((v) => ({ nombre: v.key, ambito: `entorno ${e.name}`, protegido: !!v.secured, valorPareceSecreto: v.secured ? null : valueLooksSecret(v.value) })));
      else gap(`las variables del entorno ${e.name}`, ev);
    }
  } else gap('los entornos de despliegue', envs);
  const keys = await lst('/deploy-keys?pagelen=100');
  if (keys.ok) m.clavesDespliegue = keys.values.map((k) => ({ titulo: k.label, escritura: false, creada: k.created_on })); else gap('las claves de despliegue', keys);
  const hooks = await lst('/hooks?pagelen=100');
  if (hooks.ok) m.webhooks = hooks.values.map((w) => ({ ...hostOnly(w.url), verificaTls: !w.skip_cert_verification })); else gap('los webhooks (hace falta permiso de administrador del repo)', hooks);
  gap('alertas de secretos y de dependencias (Bitbucket Cloud no las ofrece por API)');
  return m;
}

/** Las últimas ejecuciones de Bitbucket Pipelines, una a una: los logs de sus pasos a una carpeta, scan(carpeta) y se borra. */
export async function bitbucketLogs({ owner, repo }, h, n, dir, scan, { signal } = {}) {
  const base = `https://api.bitbucket.org/2.0/repositories/${owner}/${repo}/pipelines`;
  const runs = await get(`${base}/?sort=-created_on&pagelen=${n}`, h, { signal });
  if (!runs.ok) return { revisadas: 0, huecos: [`los logs de las ejecuciones (${why(runs)})`] };
  let revisadas = 0; const huecos = [];
  for (const r of runs.data?.values || []) {
    if (signal?.aborted) { huecos.push('no dio tiempo a revisar todos los logs'); break; }
    const steps = await list(`${base}/${encodeURIComponent(r.uuid)}/steps/?pagelen=100`, h, 'cloud');
    const d = path.join(dir, String(r.build_number || '').replace(/\D/g, '') || 'x');
    fs.mkdirSync(d, { recursive: true });
    try {
      // un número delante de cada paso: dos pasos con el mismo nombre (o sin nombre) no se pisan
      let i = 0;
      for (const s of steps.values) {
        const log = await get(`${base}/${encodeURIComponent(r.uuid)}/steps/${encodeURIComponent(s.uuid)}/log`, h, { raw: true, max: 50 * 1024 * 1024, signal });
        if (log.ok) fs.writeFileSync(path.join(d, `${String(++i).padStart(2, '0')}_${(s.name || 'paso').replace(/[^\w .-]/g, '_').slice(0, 80)}.txt`), log.data);
      }
      if (scan({ id: `#${r.build_number}`, pipeline: r.target?.ref_name ? `pipeline de ${r.target.ref_name}` : 'pipeline', path: d })) revisadas++;
      else huecos.push(`gitleaks falló con los logs de la ejecución #${r.build_number}`);
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  }
  return { revisadas, huecos };
}

// ---------------------------------------------------------------- Bitbucket Server / Data Center
export async function collectBitbucketServer({ base, owner, repo }, h) {
  const rbase = `${base}/rest/api/1.0/projects/${owner}/repos/${repo}`;
  const api = (p) => get(rbase + p, h);
  const lst = (u) => list(u, h, 'server');
  const m = empty('bitbucket-server', `${owner}/${repo}`);
  const gap = (que, r) => m.huecos.push(r ? `${que} (${why(r)})` : que);
  const info = await api('');
  if (!info.ok) return { ...m, error: `Bitbucket Server respondió ${why(info)} al leer el repositorio` };
  m.privado = !(info.data.public || info.data.project?.public);
  const def = await api('/default-branch');
  const def2 = def.ok ? def : await api('/branches/default');
  const b = m.ramaPrincipal = def2.data?.displayId || null;
  if (!b) gap('la rama principal', def2);
  // el modelo de ramas: «production»/«development» y los prefijos de las categorías
  const bm = await get(`${base}/rest/branch-utils/1.0/projects/${owner}/repos/${repo}/branchmodel`, h);
  const applies = (r) => {
    const t = r.matcher?.type?.id, id = r.matcher?.id;
    if (t === 'BRANCH') return r.matcher?.displayId === b || id === `refs/heads/${b}`;
    if (t === 'PATTERN') return branchMatches(id, b) || branchMatches(id, `refs/heads/${b}`);
    if (t === 'MODEL_BRANCH') return bm.data?.[String(id).toLowerCase()]?.displayId === b;
    if (t === 'MODEL_CATEGORY') { const pre = (bm.data?.types || []).find((x) => x.id === id)?.prefix; return !!pre && b.startsWith(pre); }
    return false;
  };
  if (b) {
    // las restricciones del repo y las heredadas del proyecto
    const rs = await lst(`${base}/rest/branch-permissions/2.0/projects/${owner}/repos/${repo}/restrictions?limit=100`);
    const ps = await lst(`${base}/rest/branch-permissions/2.0/projects/${owner}/restrictions?limit=100`);
    if (rs.ok) {
      const mine = [...rs.values, ...(ps.ok ? ps.values : [])].filter(applies);
      const types = new Set(mine.map((r) => r.type));
      const ro = mine.find((r) => r.type === 'read-only');
      // el mínimo de aprobaciones es un merge check (heredable del proyecto); si no se ve, queda en «no se sabe»
      const hookKey = 'com.atlassian.bitbucket.server.bitbucket-bundled-hooks:requiredApproversMergeHook';
      const hook = await api(`/settings/hooks/${encodeURIComponent(hookKey)}`);
      const hookCfg = hook.ok && hook.data?.enabled ? await api(`/settings/hooks/${encodeURIComponent(hookKey)}/settings`) : null;
      const set = hookCfg?.ok ? null : await api('/settings/pull-requests');
      const aprobaciones = hookCfg?.ok ? +(hookCfg.data?.requiredCount ?? 0) : hook.ok && !hook.data?.enabled ? 0 : set?.ok && set.data?.requiredApprovers != null ? set.data.requiredApprovers : null;
      if (aprobaciones == null) gap('las aprobaciones obligatorias de los pull requests');
      m.proteccion = { conocida: true, existe: mine.length > 0, exigePR: types.has('pull-request-only') || (!!ro && !(ro.users || []).length && !(ro.groups || []).length),
        aprobaciones, forcePush: !types.has('fast-forward-only'), borrar: !types.has('no-deletes'), aplicada: true, adminsExentos: null };
      if (!ps.ok) gap('las restricciones heredadas del proyecto', ps);
    } else gap('los permisos de la rama principal (hace falta permiso de administrador del repo)', rs);
    const prs = await lst(`${rbase}/pull-requests?state=MERGED&at=${encodeURIComponent(`refs/heads/${b}`)}&limit=30`);
    if (prs.ok) m.revisionReal = { cambios: prs.values.length, aprobados: prs.values.filter((p) => (p.reviewers || []).some((r) => r.approved || r.status === 'APPROVED')).length, directos: null };
    else gap('los pull requests mergeados', prs);
  }
  const hooks = await lst(`${rbase}/webhooks?limit=100`);
  if (hooks.ok) m.webhooks = hooks.values.map((w) => ({ ...hostOnly(w.url), verificaTls: w.sslVerificationRequired !== false })); else gap('los webhooks (hace falta permiso de administrador del repo)', hooks);
  const keys = await lst(`${base}/rest/keys/1.0/projects/${owner}/repos/${repo}/ssh?limit=100`);
  if (keys.ok) m.clavesDespliegue = keys.values.map((k) => ({ titulo: k.key?.label || 'clave', escritura: k.permission === 'REPO_WRITE', creada: k.key?.createdDate ? new Date(k.key.createdDate).toISOString() : null }));
  else gap('las claves de acceso', keys);
  m.ci = { sistema: 'externo' };
  gap('el CI de Bitbucket Server es externo (Jenkins, Bamboo…): sus logs y sus secretos no se revisan desde aquí');
  return m;
}

// ---------------------------------------------------------------- secretos en los logs
/** Una carpeta para los logs, solo del usuario (la temporal del sistema, no la pública), y limpieza de las viejas. */
export function newWorkDir() {
  for (const n of fs.readdirSync(os.tmpdir()).filter((x) => x.startsWith('lupa-logs-'))) {
    const p = path.join(os.tmpdir(), n);
    try { if (Date.now() - fs.statSync(p).mtimeMs > 3600_000) fs.rmSync(p, { recursive: true, force: true }); } catch {}
  }
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-logs-'));
}

/**
 * Pasa gitleaks por los logs de una ejecución (un zip, que lee por dentro sin descomprimir, o una carpeta).
 * De cada secreto solo queda la regla, la ejecución, el paso y el contexto con el valor tapado. Devuelve null si
 * gitleaks falla: entonces no se puede decir que no haya nada.
 */
export function scanLog(gitleaks, run1) {
  const report = `${run1.path}.gitleaks.json`;
  const r = runTool(gitleaks, ['dir', run1.path, '--max-archive-depth', '1', '--report-format', 'json', '--report-path', report, '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'error']);
  const data = readJSON(report, null);
  fs.rmSync(report, { force: true });
  if (r.status !== 0 || !Array.isArray(data)) return null;
  const seen = new Set(), out = [];
  for (const f of data) {
    // «run.zip!job/3_Deploy.txt» o «carpeta/02_Deploy.txt» → «Deploy»
    const inner = posix(String(f.File || '')).split('!').pop();
    const paso = path.posix.basename(inner).replace(/\.txt$/, '').replace(/^\d+_/, '');
    const contexto = String(f.Match || '').includes('REDACTED') ? String(f.Match).replace(/\s+/g, ' ').slice(0, 120) : '';
    const k = `${f.RuleID}|${paso}`;
    if (seen.has(k)) continue; // el mismo secreto repetido en un paso cuenta una vez
    seen.add(k);
    out.push({ regla: f.RuleID, pipeline: run1.pipeline, ejecucion: run1.id, paso, contexto });
  }
  return out;
}
