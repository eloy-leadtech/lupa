// Pruebas de CI/CD: detección de plataforma, reglas de pipelines, OIDC, plataforma (GitHub y Bitbucket) y logs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseRemote, detectCi, ciLineFindings, deployModel, oidcTerraformFindings, oidcSubValues, oidcScope, platformFindings, awsCiFindings, stageSummary } from '../skills/lupa/scripts/lib/cicd.mjs';
import { collectBitbucketCloud, collectBitbucketServer, collectGitHub, scanLog, branchMatches, secretName, list } from '../skills/lupa/scripts/lib/plataforma.mjs';
import { cicdSection } from '../skills/lupa/scripts/lib/report-cicd.mjs';
import { findTool } from '../skills/lupa/scripts/lib/tools.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lupa-ci-'));
const write = (root, files) => { for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(root, f)), { recursive: true }); fs.writeFileSync(path.join(root, f), t); } };
const rules = (fs_) => [...new Set(fs_.map((f) => f.rule))].sort();

test('la plataforma se reconoce por el remoto, también con las formas raras de las URL reales', () => {
  const p = (u, env = {}) => parseRemote(u, env);
  assert.deepEqual(p('https://github.com/acme/web.git'), { plataforma: 'github', host: 'github.com', owner: 'acme', repo: 'web', api: 'https://api.github.com' });
  for (const u of ['git@github.com:acme/web.git', 'https://github.com/acme/web/', 'ssh://git@github.com:22/acme/web.git', 'org-123@github.com:acme/web.git', 'https://token@github.com/acme/web']) {
    const r = p(u); assert.equal(`${r.plataforma} ${r.owner}/${r.repo}`, 'github acme/web', u);
  }
  assert.equal(p('https://acme.ghe.com/team/web.git').api, 'https://api.acme.ghe.com');
  assert.equal(p('https://git.empresa.com/team/web.git', { GH_HOST: 'git.empresa.com' }).api, 'https://git.empresa.com/api/v3');
  assert.deepEqual(p('https://juan@bitbucket.org/visas/portal.git'), { plataforma: 'bitbucket-cloud', host: 'bitbucket.org', owner: 'visas', repo: 'portal' });
  assert.equal(p('git@bitbucket.org:visas/portal.git').plataforma, 'bitbucket-cloud');
  const srv = p('http://bb.empresa.com:7990/bitbucket/scm/VIS/portal.git');
  assert.equal(srv.plataforma, 'bitbucket-server'); assert.equal(srv.owner, 'VIS'); assert.equal(srv.base, undefined, 'la dirección de Server no sale del remoto');
  assert.equal(p('ssh://git@bitbucket.empresa.com:7999/vis/portal.git').plataforma, 'bitbucket-server');
  assert.equal(p('https://gitlab.com/grupo/sub/app.git').plataforma, 'gitlab');
  assert.equal(p('https://git.otra.com/org/app.git').plataforma, 'otra');
});

test('se detectan los pipelines de cada sistema, también dentro de una carpeta con varios repos', () => {
  const ci = detectCi(['.github/workflows/ci.yml', 'api/bitbucket-pipelines.yml', 'web/Jenkinsfile', '.gitlab-ci.yml', 'src/app.js']);
  assert.deepEqual(ci.sistemas.map((s) => s.ci).sort(), ['bitbucket-pipelines', 'github-actions', 'gitlab-ci', 'jenkins']);
});

const BITBUCKET_PIPELINE = `image: node
pipelines:
  pull-requests:
    '**':
      - step:
          name: Build
          deployment: staging
          script:
            - npm ci
  branches:
    main:
      - step:
          name: Deploy
          image:
            name: atlassian/default-image:latest
          script:
            - curl -sL https://get.example.com/install.sh | bash
            - ssh -o StrictHostKeyChecking=no deploy@10.0.0.5 'sudo systemctl restart app'
            - echo $DEPLOY_TOKEN
            - pipe: atlassian/aws-s3-deploy:1.1.0
              variables:
                AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
`;

test('Bitbucket Pipelines: las reglas comunes (script de internet, SSH sin huella, claves fijas, echo de secretos, imágenes, PR que despliega)', () => {
  const root = tmp();
  write(root, { 'bitbucket-pipelines.yml': BITBUCKET_PIPELINE });
  const f = ciLineFindings(root, [{ fichero: 'bitbucket-pipelines.yml', ci: 'bitbucket-pipelines' }]);
  assert.deepEqual(rules(f), ['ci.claves-fijas-nube', 'ci.curl-a-shell', 'ci.echo-secreto', 'ci.imagen-sin-version', 'ci.pr-despliega', 'ci.ssh-sin-host-key']);
  assert.equal(f.filter((x) => x.rule === 'ci.imagen-sin-version').length, 2, '«node» sin etiqueta y la de «latest»');
  const d = deployModel(root, [{ fichero: 'bitbucket-pipelines.yml', ci: 'bitbucket-pipelines' }]);
  assert.equal(d.credenciales, 'claves-fijas');
  assert.ok(d.destinos.includes('AWS S3') && d.destinos.includes('Servidores por SSH'));
});

test('OIDC en Terraform: el orden de la condición da igual; comodines, organización (también interpolada) y cualquier rama', () => {
  const root = tmp();
  const trust = (cond) => `data "aws_iam_policy_document" "t" {\n statement {\n actions = ["sts:AssumeRoleWithWebIdentity"]\n principals { identifiers = ["arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"] }\n${cond}\n }\n}\nresource "aws_iam_policy" "p" { policy = jsonencode({ Statement = [{ Action = "s3:*", Resource = "*" }] }) }\n`;
  write(root, {
    'sin.tf': trust(''),
    'orden.tf': trust(' condition {\n values = ["repo:*"]\n variable = "token.actions.githubusercontent.com:sub"\n test = "StringLike"\n }'),
    'org.tf': trust(' condition {\n variable = "token.actions.githubusercontent.com:sub"\n values = ["repo:${var.org}/*"]\n }'),
    'rama.tf': trust(' condition {\n variable = "token.actions.githubusercontent.com:sub"\n values = ["repo:acme/web:*"]\n }'),
    'bien.tf': trust(' condition {\n variable = "${replace(local.github_oidc_provider_url, "https://", "")}:sub"\n values = ["repo:${local.repo}:ref:refs/heads/main"]\n }'),
    'testdata/x.tf': trust(''),
  });
  const f = oidcTerraformFindings(root, ['sin.tf', 'orden.tf', 'org.tf', 'rama.tf', 'bien.tf', 'testdata/x.tf']);
  assert.deepEqual(f.map((x) => `${x.file}:${x.rule}:${x.severity}`).sort(), ['orden.tf:ci.oidc-comodin:high', 'org.tf:ci.oidc-org:medium', 'rama.tf:ci.oidc-cualquier-rama:medium', 'sin.tf:ci.oidc-sin-sub:high']);
  assert.deepEqual(oidcSubValues('{ "token.actions.githubusercontent.com:sub" = ["repo:a/b:ref:refs/heads/main"] }'), ['repo:a/b:ref:refs/heads/main']);
  assert.equal(oidcScope(['repo:a/b:environment:production']), 'concreto');
});

test('nombres de variable: secretos por palabras, no por trozos; lo público por diseño no cuenta', () => {
  for (const n of ['DB_PASSWORD', 'API_TOKEN', 'STRIPE_SECRET_KEY', 'DATABASE_URL', 'SENTRY_DSN', 'GITHUB_API_KEY']) assert.ok(secretName(n), n);
  for (const n of ['STRIPE_PUBLISHABLE_KEY', 'SSH_PUBLIC_KEY', 'KEYCLOAK_URL', 'PASSPORT_API_URL', 'BYPASS_CACHE', 'TOKEN_EXPIRY_SECONDS', 'AWS_SECRET_NAME']) assert.ok(!secretName(n), n);
});

/** El mismo estado en dos plataformas: las reglas tienen que dar lo mismo. */
const MODEL = (plataforma, repo = 'acme/web') => ({
  plataforma, repo, privado: true, ramaPrincipal: 'main', entornosLeidos: true,
  proteccion: { conocida: true, existe: true, exigePR: true, aprobaciones: 0, forcePush: true, borrar: false, aplicada: false },
  revisionReal: { cambios: 10, aprobados: 2 }, ci: {}, entornos: [{ nombre: 'production', produccion: true, aprobacion: false }, { nombre: 'preprod', produccion: false, aprobacion: false }],
  secretos: [{ nombre: 'AWS_ACCESS_KEY_ID', ambito: 'repo', protegido: true }, { nombre: 'DB_PASSWORD', ambito: 'repo', protegido: false }],
  clavesDespliegue: [], webhooks: [{ url: 'http://hooks.example.com', host: 'hooks.example.com', verificaTls: false }], colaboradoresExternos: [],
  alertas: {}, seguridad: {}, logs: { revisadas: 3, hallazgos: [{ regla: 'aws-access-token', pipeline: 'deploy', ejecucion: '7', paso: 'build' }, { regla: 'generic-api-key', pipeline: 'deploy', ejecucion: '7', paso: 'tf', contexto: 'id = REDACTED' }, { regla: 'generic-api-key', pipeline: 'deploy', ejecucion: '8', paso: 'tf' }] }, huecos: [],
});

test('GitHub y Bitbucket se miden con los mismos parámetros; cada repo y cada log, su tarjeta', () => {
  const gh = platformFindings(MODEL('github')), bb = platformFindings(MODEL('bitbucket-cloud'));
  assert.deepEqual(rules(gh), rules(bb));
  assert.deepEqual(rules(gh), ['plataforma.checks-no-obligatorios', 'plataforma.clave-nube', 'plataforma.force-push', 'plataforma.poca-revision', 'plataforma.posible-secreto-en-log',
    'plataforma.prod-sin-aprobacion', 'plataforma.secreto-en-log', 'plataforma.sin-aprobacion', 'plataforma.variable-sin-proteger', 'plataforma.webhook-http', 'plataforma.webhook-sin-tls']);
  assert.equal(gh.filter((x) => x.rule === 'plataforma.prod-sin-aprobacion').length, 1, '«preprod» no es producción');
  const logs = gh.filter((x) => /secreto-en-log/.test(x.rule));
  assert.equal(new Set(logs.map((x) => x.file)).size, 3, 'cada secreto de log en su tarjeta: la criba de uno no se lleva a los otros');
  assert.ok(gh.every((x) => x.file.startsWith('cicd/acme/web/') && x.title.includes('acme/web')));
  const two = [...platformFindings(MODEL('github', 'acme/a')), ...platformFindings(MODEL('github', 'acme/b'))];
  assert.equal(two.filter((x) => x.rule === 'plataforma.force-push').length, 2, 'dos repos, dos avisos: no se funden');
  const open = platformFindings({ ...MODEL('github'), proteccion: { conocida: true, existe: false }, cuentaPersonal: true });
  assert.match(open.find((x) => x.rule === 'plataforma.rama-sin-proteger').detail, /cuenta personal/);
});

test('sin falsos graves: runners solo con repo público sabido; «sin entornos» solo si se leyeron; lo que no tiene API, nada', () => {
  assert.ok(!rules(platformFindings({ plataforma: 'gitlab', repo: 'x', soloFicheros: true }, { runnersPropios: true, destinos: ['AWS S3'] })).length);
  assert.ok(!rules(platformFindings({ ...MODEL('github'), privado: null }, { runnersPropios: true })).includes('plataforma.runners-publico'));
  assert.ok(rules(platformFindings({ ...MODEL('github'), privado: false }, { runnersPropios: true })).includes('plataforma.runners-publico'));
  assert.ok(!rules(platformFindings({ ...MODEL('github'), entornos: [], entornosLeidos: false }, { destinos: ['AWS S3'] })).includes('plataforma.sin-entornos'));
  assert.ok(!rules(platformFindings({ ...MODEL('bitbucket-server'), entornos: [], entornosLeidos: true }, { destinos: ['AWS S3'] })).includes('plataforma.sin-entornos'));
  assert.ok(rules(platformFindings({ ...MODEL('github'), entornos: [], entornosLeidos: true }, { destinos: ['AWS S3'] })).includes('plataforma.sin-entornos'));
  const looks = platformFindings({ ...MODEL('bitbucket-cloud'), secretos: [{ nombre: 'DB_PASSWORD', ambito: 'repo', protegido: false, valorPareceSecreto: false }] });
  assert.equal(looks.find((x) => x.rule === 'plataforma.variable-sin-proteger').severity, 'medium', 'si el valor no tiene pinta de secreto, a mirar');
});

/** Un fetch de mentira: «=url» es la URL exacta; el resto, la ruta más específica que encaje. Apunta a qué se llama. */
function fakeFetch(routes) {
  const calls = [];
  const f = async (url) => {
    calls.push(String(url));
    const hit = Object.entries(routes).filter(([k]) => (k.startsWith('=') ? String(url) === k.slice(1) : String(url).includes(k))).sort((a, b) => b[0].length - a[0].length)[0];
    const headers = { get: () => null };
    if (!hit) return { ok: false, status: 404, headers, json: async () => null };
    return { ok: true, status: 200, headers, json: async () => hit[1], arrayBuffer: async () => Buffer.from(JSON.stringify(hit[1])) };
  };
  f.calls = calls;
  return f;
}
const withFetch = async (routes, fn) => { const real = globalThis.fetch; globalThis.fetch = fakeFetch(routes); try { return await fn(globalThis.fetch); } finally { globalThis.fetch = real; } };

test('Bitbucket Cloud: restricciones (también por modelo de ramas), revisión de verdad, variables sin su valor y webhooks sin su URL', () => withFetch({
  '/branching-model': { development: { use_mainbranch: true }, production: { branch: { name: 'production' } } },
  '/branch-restrictions': { values: [
    { kind: 'push', branch_match_kind: 'glob', pattern: 'main', users: [], groups: [] },
    { kind: 'require_approvals_to_merge', branch_match_kind: 'branching_model', branch_type: 'development', value: 2 },
    { kind: 'force', branch_match_kind: 'branching_model', branch_type: 'production' },
    { kind: 'delete', branch_match_kind: 'glob', pattern: 'release/*' },
  ] },
  '/pullrequests?state=MERGED': { values: [
    { id: 1, author: { uuid: 'a' }, participants: [{ approved: true, user: { uuid: 'b' } }] },
    { id: 2, author: { uuid: 'a' }, participants: [{ approved: true, user: { uuid: 'a' } }] },
  ] },
  '/commits/main': { values: [
    { hash: 'm', parents: [{ hash: 'x' }, { hash: 'f1' }], message: 'Merged in f (pull request #1)' },
    { hash: 'f1', parents: [{ hash: 'x' }], message: 'commit de la rama del PR' },
    { hash: 'x', parents: [{ hash: 'r' }], message: 'arreglo rápido' },
  ] },
  '/pipelines_config/variables': { values: [{ key: 'DB_PASSWORD', secured: false, value: 'supersecreta12345' }, { key: 'API_TOKEN', secured: true }] },
  '/pipelines-config/variables': { values: [] },
  '/pipelines_config': { enabled: true },
  '/environments': { values: [{ uuid: '{e1}', name: 'Production', environment_type: { name: 'Production' }, restrictions: { admin_only: false } }] },
  '/deployments_config/environments/': { values: [{ key: 'AWS_SECRET_ACCESS_KEY', secured: true }] },
  '/deploy-keys': { values: [{ label: 'servidor', created_on: '2020-01-01T00:00:00Z' }] },
  '/hooks': { values: [{ url: 'https://hooks.slack.com/services/T000/B000/xxxxSECRETOxxxx', skip_cert_verification: true }] },
  '=https://api.bitbucket.org/2.0/repositories/visas/portal': { is_private: true, mainbranch: { name: 'main' }, uuid: '{repo-uuid}' },
}, async (f) => {
  const m = await collectBitbucketCloud({ owner: 'visas', repo: 'portal' }, { authorization: 'Basic x' });
  assert.deepEqual({ ...m.proteccion }, { conocida: true, existe: true, exigePR: true, aprobaciones: 2, forcePush: true, borrar: true, aplicada: false, adminsExentos: null },
    'la de «production» no es la principal; la de «development» sí (usa la principal)');
  assert.deepEqual(m.revisionReal, { cambios: 3, aprobados: 1, directos: 1 }, 'los commits de la rama del PR no cuentan como directos');
  const json = JSON.stringify(m);
  assert.ok(!json.includes('supersecreta12345'), 'el valor de una variable no protegida no se guarda');
  assert.ok(!json.includes('SECRETO') && m.webhooks[0].url === 'https://hooks.slack.com', 'de un webhook solo queda el host');
  assert.ok(m.secretos.some((s) => s.nombre === 'AWS_SECRET_ACCESS_KEY' && s.ambito === 'entorno Production'));
  assert.ok(f.calls.every((u) => u.startsWith('https://api.bitbucket.org/')), 'solo se habla con la API de Bitbucket');
  assert.ok(f.calls.some((u) => /q=destination\.branch\.name%3D%22main%22/.test(u)), 'solo los PR a la rama principal');
  const r = rules(platformFindings(m));
  for (const x of ['plataforma.variable-sin-proteger', 'plataforma.clave-nube', 'plataforma.prod-sin-aprobacion', 'plataforma.webhook-sin-tls', 'plataforma.clave-vieja', 'plataforma.checks-no-obligatorios', 'plataforma.force-push']) assert.ok(r.includes(x), x);
}));

test('Bitbucket Server: permisos por rama y por modelo, aprobaciones del merge check; el CI externo queda como hueco', () => withFetch({
  '/branchmodel': { development: { displayId: 'develop' }, production: { displayId: 'master' } },
  '/repos/portal/restrictions': { values: [{ type: 'pull-request-only', matcher: { id: 'production', type: { id: 'MODEL_BRANCH' } } }, { type: 'fast-forward-only', matcher: { id: '*', type: { id: 'PATTERN' } } }] },
  '/projects/VIS/restrictions': { values: [{ type: 'no-deletes', matcher: { id: 'refs/heads/master', displayId: 'master', type: { id: 'BRANCH' } } }] },
  'requiredApproversMergeHook/settings': { requiredCount: 2 },
  'requiredApproversMergeHook': { enabled: true },
  '/pull-requests?state=MERGED': { values: [{ reviewers: [{ approved: true }] }, { reviewers: [] }] },
  '/default-branch': { displayId: 'master' },
  '/webhooks': { values: [{ url: 'http://jenkins.empresa.com/bitbucket-hook/?token=abc', sslVerificationRequired: true }] },
  '/ssh': { values: [{ key: { label: 'jenkins' }, permission: 'REPO_WRITE' }] },
  '=https://bb.empresa.com/rest/api/1.0/projects/VIS/repos/portal': { public: false, project: { public: false } },
}, async (f) => {
  const m = await collectBitbucketServer({ base: 'https://bb.empresa.com', owner: 'VIS', repo: 'portal' }, { authorization: 'Bearer x' });
  assert.equal(m.ramaPrincipal, 'master');
  assert.deepEqual([m.proteccion.existe, m.proteccion.exigePR, m.proteccion.forcePush, m.proteccion.borrar, m.proteccion.aprobaciones], [true, true, false, false, 2]);
  assert.equal(m.revisionReal.aprobados, 1);
  assert.ok(f.calls.some((u) => /at=refs%2Fheads%2Fmaster/.test(u)), 'solo los PR a la rama principal');
  assert.ok(!JSON.stringify(m).includes('token=abc'));
  assert.ok(m.huecos.some((h) => /CI de Bitbucket Server es externo/.test(h)));
  assert.ok(rules(platformFindings(m)).includes('plataforma.clave-escritura'));
}));

test('Bitbucket Server sin rama por defecto: no se inventa «master» ni «sin proteger»', () => withFetch({
  '=https://bb.empresa.com/rest/api/1.0/projects/VIS/repos/portal': { public: false },
}, async () => {
  const m = await collectBitbucketServer({ base: 'https://bb.empresa.com', owner: 'VIS', repo: 'portal' }, { authorization: 'Bearer x' });
  assert.equal(m.ramaPrincipal, null);
  assert.ok(!rules(platformFindings(m)).includes('plataforma.rama-sin-proteger'));
}));

test('GitHub: rama sin proteger y revisión de verdad; un commit sin respuesta de la API no cuenta como directo', () => withFetch({
  '/branches/main': { protected: false },
  '/rules/branches/main': [],
  '/commits?sha=main': [{ sha: 'c1', parents: [{}] }, { sha: 'c2', parents: [{}] }, { sha: 'c3', parents: [{}, {}] }, { sha: 'c4', parents: [{}] }],
  '/commits/c1/pulls': [{ number: 5, merged_at: 'x', user: { login: 'ana' } }],
  '/commits/c2/pulls': [{ number: 5, merged_at: 'x', user: { login: 'ana' } }],
  '/commits/c3/pulls': [],
  '/pulls/5/reviews': [{ state: 'APPROVED', user: { login: 'ana' } }],
  '=https://api.github.com/repos/acme/web': { private: true, default_branch: 'main', permissions: { admin: false }, owner: { type: 'User' } },
}, async () => {
  const m = await collectGitHub({ owner: 'acme', repo: 'web' }, { authorization: 'Bearer x' });
  assert.equal(m.proteccion.existe, false);
  assert.deepEqual(m.revisionReal, { cambios: 2, aprobados: 0, directos: 1 }, 'un PR autoaprobado, un merge local sin PR (directo) y uno sin respuesta (no cuenta)');
  assert.ok(m.huecos.length > 0, 'sin ser administrador hay cosas que no se ven');
  assert.equal(m.cuentaPersonal, true);
}));

test('paginación: se siguen las páginas del mismo origen y nunca las de otro host', async () => {
  const pages = { 'https://api.bitbucket.org/2.0/x': { values: [1], next: 'https://api.bitbucket.org/2.0/x?page=2' }, 'https://api.bitbucket.org/2.0/x?page=2': { values: [2], next: 'https://malo.example/robar' } };
  const real = globalThis.fetch; const calls = [];
  globalThis.fetch = async (u) => { calls.push(u); const d = pages[u]; return d ? { ok: true, status: 200, headers: { get: () => null }, json: async () => d } : { ok: false, status: 404, headers: { get: () => null } }; };
  try {
    const r = await list('https://api.bitbucket.org/2.0/x', {}, 'cloud');
    assert.deepEqual(r.values, [1, 2]);
    assert.ok(!calls.some((u) => u.includes('malo.example')));
  } finally { globalThis.fetch = real; }
});

test('AWS: un rol de CI sin «sub» o con AdministratorAccess es grave; en Bitbucket el alcance es el workspace', () => {
  const f = awsCiFindings({ roles: [{ nombre: 'ci', proveedor: 'GitHub', sub: [], politicas: ['AdministratorAccess'] }, { nombre: 'bb', proveedor: 'Bitbucket', sub: [], politicas: [] },
    { nombre: 'rama', proveedor: 'GitHub', sub: ['repo:acme/web:*'], politicas: [] }, { nombre: 'ok', proveedor: 'GitHub', sub: ['repo:acme/web:ref:refs/heads/main'], politicas: ['deploy'] }],
  usuarios: [{ nombre: 'deployer', claves: [{ estado: 'Active', dias: 400 }] }] });
  assert.deepEqual(rules(f), ['aws.ci-admin', 'aws.clave-vieja', 'aws.oidc-cualquier-rama', 'aws.oidc-sin-sub']);
  assert.equal(f.find((x) => x.title.includes('rol bb')).severity, 'medium');
});

test('logs: gitleaks lee el zip de logs por dentro sin descomprimir y no guarda el valor', { skip: !findTool('gitleaks') && 'gitleaks no está instalado' }, () => {
  const d = tmp(), job = path.join(d, 'in', 'job');
  const key = 'AKIA' + 'QYLPMN5HHHFPZAM2'; // formato de clave de AWS, de ejemplo
  write(job, { '3_Deploy.txt': `2026-10-29 aws configure set aws_access_key_id ${key}\n` });
  const zip = path.join(d, '7.zip');
  const tar = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'zip';
  spawnSync(tar, process.platform === 'win32' ? ['-a', '-cf', zip, 'job'] : ['-qr', zip, 'job'], { cwd: path.join(d, 'in') });
  const h = scanLog(findTool('gitleaks'), { id: '7', pipeline: 'deploy', path: zip });
  assert.equal(h.length, 1);
  assert.equal(h[0].paso, 'Deploy');
  assert.ok(!JSON.stringify(h).includes(key));
});
test('el camino a producción del informe: cinco etapas, escapadas, con lo grave primero', () => {
  const etapas = stageSummary([
    { cat: 'cicd', etapa: 'codigo', severity: 'medium', title: 'poca revisión' },
    { cat: 'cicd', etapa: 'codigo', severity: 'high', title: '<b>rama</b> sin proteger' },
    { cat: 'codigo', severity: 'high', title: 'no es de CI' },
  ]);
  assert.equal(etapas.codigo.titulos[0].titulo, '<b>rama</b> sin proteger');
  const html = cicdSection({ sistemas: [{ ci: 'bitbucket-pipelines', nombre: 'Bitbucket Pipelines' }], ficheros: 1, despliegue: { destinos: ['AWS S3'], credenciales: 'claves-fijas' }, etapas, revisadoPorFuera: false, plataformas: [] });
  assert.equal((html.match(/class="cc-box"/g) || []).length, 5);
  assert.ok(!html.includes('<b>rama</b>'));
  assert.match(html, /no se ha revisado/);
  assert.ok(branchMatches('release/*', 'release/1.2') && !branchMatches('release/*', 'main'));
});
