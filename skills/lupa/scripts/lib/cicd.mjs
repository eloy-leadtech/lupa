// CI/CD y despliegue: cómo llega el código a producción y por dónde se puede colar alguien en ese camino.
// Aquí va lo que se ve en los ficheros del repo (pipelines de cualquier plataforma, zizmor para GitHub
// Actions, el Terraform del CI) y las reglas que convierten lo que trae la plataforma (plataforma.mjs) en
// hallazgos. Las reglas no saben de qué plataforma viene cada dato: GitHub y Bitbucket se miden igual.
import fs from 'node:fs';
import path from 'node:path';
import { run, readJSON, relTo, posix } from './util.mjs';
import { runTool } from './tools.mjs';
import { secretName } from './plataforma.mjs';

// ---------------------------------------------------------------- qué CI y qué plataforma
export const CI_FILES = [
  { re: /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/, ci: 'github-actions', nombre: 'GitHub Actions' },
  { re: /(^|\/)bitbucket-pipelines\.ya?ml$/, ci: 'bitbucket-pipelines', nombre: 'Bitbucket Pipelines' },
  { re: /(^|\/)\.gitlab-ci\.ya?ml$/, ci: 'gitlab-ci', nombre: 'GitLab CI' },
  { re: /(^|\/)Jenkinsfile[^/]*$/, ci: 'jenkins', nombre: 'Jenkins' },
  { re: /(^|\/)azure-pipelines\.ya?ml$/, ci: 'azure-pipelines', nombre: 'Azure Pipelines' },
  { re: /(^|\/)\.circleci\/config\.ya?ml$/, ci: 'circleci', nombre: 'CircleCI' },
  { re: /(^|\/)bamboo-specs\/.+\.(ya?ml|java)$/, ci: 'bamboo', nombre: 'Bamboo' },
  { re: /(^|\/)\.drone\.ya?ml$/, ci: 'drone', nombre: 'Drone' },
];

/** Los ficheros de pipeline del proyecto y los sistemas de CI que usan. */
export function detectCi(files) {
  const ficheros = [];
  for (const f of files) { const hit = CI_FILES.find((c) => c.re.test(f)); if (hit) ficheros.push({ fichero: f, ci: hit.ci }); }
  const sistemas = [...new Set(ficheros.map((f) => f.ci))].map((ci) => ({ ci, nombre: CI_FILES.find((c) => c.ci === ci).nombre }));
  return { ficheros, sistemas };
}

/**
 * De qué plataforma es un remoto de git: GitHub, Bitbucket Cloud, Bitbucket Server/Data Center, GitLab u otra.
 * Bitbucket Server se reconoce por /scm/ (https) o por el puerto 7999 (ssh) en un host propio.
 */
export function parseRemote(url, env = process.env) {
  let s = String(url || '').trim();
  // la forma corta de ssh («usuario@host:ruta») como URL, para leerlas todas igual
  if (!/^[a-z][\w+.-]*:\/\//i.test(s) && /^[^@/\s]+@[^:/\s]+:/.test(s)) s = 'ssh://' + s.replace(/:(?!\d+\/)/, '/');
  let u; try { u = new URL(s); } catch { return { plataforma: 'desconocida' }; }
  const host = u.hostname.toLowerCase();
  const parts = decodeURIComponent(u.pathname).replace(/\.git\/?$/, '').replace(/\/+$/, '').split('/').filter(Boolean);
  if (parts.length < 2) return { plataforma: 'desconocida', host };
  const repo = parts.at(-1), owner = parts.slice(0, -1).join('/');
  const ghe = env.GH_HOST || env.GITHUB_ENTERPRISE_HOST;
  if (host === 'github.com') return { plataforma: 'github', host, owner, repo, api: 'https://api.github.com' };
  if (/\.ghe\.com$/.test(host)) return { plataforma: 'github', host, owner, repo, api: `https://api.${host}` };
  if (ghe && host === ghe.toLowerCase()) return { plataforma: 'github', host, owner, repo, api: `https://${host}/api/v3` };
  if (host === 'bitbucket.org') return { plataforma: 'bitbucket-cloud', host, owner, repo };
  if (host === 'gitlab.com') return { plataforma: 'gitlab', host, owner, repo };
  // Bitbucket Server: /scm/<proyecto>/<repo> por https, o el puerto 7999 por ssh. Su dirección web (y a dónde se
  // manda el token) sale de BITBUCKET_SERVER_URL, nunca del remoto.
  const scm = parts.indexOf('scm');
  if (scm >= 0 && parts.length - scm === 3) return { plataforma: 'bitbucket-server', host, owner: parts[scm + 1], repo };
  if (u.protocol === 'ssh:' && u.port === '7999') return { plataforma: 'bitbucket-server', host, owner: parts.at(-2), repo };
  return { plataforma: 'otra', host, owner, repo };
}

// ---------------------------------------------------------------- zizmor (GitHub Actions)
// lo que dice cada auditoría de zizmor, en castellano llano; lo que no esté aquí sale con su texto en inglés
const ZIZMOR = {
  'template-injection': ['Un valor que controla quien abre el PR o la issue se pega dentro de un script del pipeline', 'Con un título de PR o una rama con nombre preparado, se ejecutan órdenes en el CI, con sus secretos y sus permisos.', 'pasa el valor por una variable de entorno (env:) y úsalo como "$VAR" en el script, nunca con ${{ }} dentro de run:.'],
  'excessive-permissions': ['El workflow tiene más permisos de los que necesita', 'Si cualquier paso se ve comprometido, el token del CI puede escribir en el repo, en paquetes o en releases.', 'declara permissions: {} arriba y da a cada job solo lo que use (contents: read, id-token: write…).'],
  'unpinned-uses': ['Usa acciones de terceros sin fijar a un commit', 'Quien controle esa acción (o su etiqueta) puede cambiar lo que se ejecuta en vuestro CI sin que nadie lo note.', 'fija cada uses: al SHA completo del commit (y deja la versión en un comentario).'],
  'dangerous-triggers': ['El workflow se dispara con pull_request_target o workflow_run', 'Corre con los secretos y permisos del repo aunque el cambio venga de un fork: si además ejecuta su código, cualquiera puede robarlos.', 'usa pull_request; si hace falta pull_request_target, no hagas checkout ni ejecutes el código del PR.'],
  'artipacked': ['El checkout deja las credenciales de git guardadas en el workspace', 'Si el workspace se sube como artefacto o lo lee otro paso, el token queda expuesto.', 'añade persist-credentials: false al actions/checkout.'],
  'cache-poisoning': ['La caché del workflow se puede envenenar', 'Un PR puede dejar en la caché algo que luego usa un build de publicación.', 'no uses caché en los workflows que publican o despliegan.'],
  'known-vulnerable-actions': ['Usa una acción con una vulnerabilidad conocida', 'Hay un aviso de seguridad publicado para esa versión.', 'súbela a la versión arreglada y fíjala por SHA.'],
  'impostor-commit': ['Una acción apunta a un commit que no es del repositorio oficial', 'Es una técnica para colar código ajeno haciéndolo pasar por una acción conocida.', 'apunta a un SHA que esté en el repositorio oficial de la acción.'],
  'ref-confusion': ['Una acción se fija con una referencia ambigua (rama y etiqueta con el mismo nombre)', 'Se puede cambiar qué código se ejecuta creando una rama con ese nombre.', 'fija la acción por SHA.'],
  'self-hosted-runner': ['El workflow usa runners propios', 'En un repo público, cualquiera con un PR puede ejecutar código en esas máquinas.', 'usa runners de GitHub para lo que venga de PRs, o aísla los propios (efímeros, sin acceso a la red interna).'],
  'secrets-inherit': ['Se pasan todos los secretos a otro workflow (secrets: inherit)', 'El workflow llamado recibe secretos que no necesita.', 'pasa solo los secretos concretos que use.'],
  'hardcoded-container-credentials': ['Hay credenciales de un registro de contenedores escritas en el workflow', 'Cualquiera con acceso al repo las tiene.', 'muévelas a secretos y rótalas.'],
  'insecure-commands': ['El workflow permite comandos obsoletos e inseguros (ACTIONS_ALLOW_UNSECURE_COMMANDS)', 'Deja que la salida de cualquier paso cambie variables y rutas del job.', 'quita ACTIONS_ALLOW_UNSECURE_COMMANDS.'],
  'github-env': ['Se escribe en GITHUB_ENV o GITHUB_PATH con datos que controla un tercero', 'Permite inyectar variables o binarios en los pasos siguientes.', 'no escribas en GITHUB_ENV valores que vengan del PR o de la issue.'],
  'overprovisioned-secrets': ['Se carga el objeto entero de secretos (toJSON(secrets))', 'Todos los secretos del repo acaban en el entorno del paso.', 'usa solo los secretos concretos que hagan falta.'],
  'unredacted-secrets': ['Un secreto se transforma de forma que GitHub no lo tapa en los logs', 'Si sale en el log, queda a la vista de quien vea la ejecución.', 'no derives valores de secretos (fromJSON, substrings) en el workflow.'],
  'bot-conditions': ['Una condición confía en que el autor sea un bot', 'Es fácil de falsificar: el nombre del actor no prueba quién hizo el cambio.', 'comprueba el evento y el autor de forma robusta (github.event.pull_request.user.login no basta).'],
  'unpinned-images': ['Usa imágenes de contenedor sin fijar', 'Quien controle la etiqueta controla lo que corre en el CI.', 'fija la imagen por su digest sha256.'],
  'dependabot-cooldown': ['Dependabot propone actualizaciones el mismo día que salen', 'Una versión maliciosa recién publicada puede entrar antes de que nadie la detecte.', 'añade un cooldown de al menos 7 días en dependabot.yml.'],
  'dependabot-execution': ['Dependabot puede ejecutar código externo al actualizar', 'Algunos ecosistemas ejecutan scripts al resolver dependencias.', 'pon insecure-external-code-execution: deny.'],
  'obfuscation': ['El workflow usa expresiones ofuscadas', 'Dificulta ver qué se ejecuta de verdad.', 'escríbelo de forma directa.'],
  'archived-uses': ['Usa una acción de un repositorio archivado', 'Ya no recibe arreglos de seguridad.', 'cámbiala por una mantenida.'],
  'use-trusted-publishing': ['Publica paquetes con un token en vez de con publicación de confianza (OIDC)', 'Ese token vive en los secretos y se puede filtrar.', 'usa trusted publishing del registro (PyPI, npm…).'],
  'unsound-condition': ['Una condición if: siempre se cumple por cómo está escrita', 'El paso protegido se ejecuta aunque no debería.', 'revisa la expresión (cuidado con ${{ }} dentro de if: con texto alrededor).'],
};
const ZZ_SEV = { High: 'high', Medium: 'medium', Low: 'low' };
const lower = (s) => (s === 'high' ? 'medium' : 'low');

/**
 * zizmor sobre los workflows de cada repo. Con un token de GitHub hace también las comprobaciones en línea; si así
 * falla (token caducado, sin red), repite sin ellas. Devuelve los hallazgos, los repos que de verdad se miraron y
 * cuántos avisos tenía ignorados el propio equipo (# zizmor: ignore o zizmor.yml), que se cuentan en el informe.
 */
export function runZizmor(tool, root, repos, { token = '', log = () => {} } = {}) {
  const out = [], ok = new Set();
  let ignorados = 0;
  for (const repo of repos.length ? repos : [{ path: '.' }]) {
    const dir = path.join(root, repo.path);
    if (!fs.existsSync(path.join(dir, '.github'))) continue;
    const once = (online) => {
      const r = runTool(tool, ['--format', 'json', '--no-exit-codes', ...(online ? [] : ['--offline']), dir], { cwd: dir, env: online ? { GH_TOKEN: token } : {}, timeout: 10 * 60_000 });
      try { return r.status === 0 ? JSON.parse(r.stdout || 'null') : null; } catch { return null; }
    };
    let data = token ? once(true) : null;
    if (!Array.isArray(data)) data = once(false);
    if (!Array.isArray(data)) { log(`zizmor falló en ${repo.path}: sus workflows de GitHub Actions se quedan sin su revisión`); continue; }
    ok.add(repo.path);
    for (const f of data) {
      const sev0 = ZZ_SEV[f.determinations?.severity];
      if (f.ignored) { ignorados++; continue; }
      if (!sev0) continue; // «Informational» no es un aviso
      const sev = f.determinations?.confidence === 'Low' ? lower(sev0) : sev0;
      const loc = (f.locations || []).find((l) => l.symbolic?.kind === 'Primary') || f.locations?.[0];
      const p = loc?.symbolic?.key?.Local?.verbatim_path || loc?.symbolic?.key?.Local?.given_path || '';
      const file = relTo(root, path.resolve(dir, posix(p)));
      const line = (loc?.concrete?.location?.start_point?.row ?? 0) + 1;
      const [t, why, fix] = ZIZMOR[f.ident] || [f.desc, '', 'sigue la recomendación de la auditoría de zizmor.'];
      out.push({
        tool: 'zizmor', cat: 'cicd', etapa: 'ci', rule: `zizmor.${f.ident}`, severity: sev, file, line,
        title: `${t} (${path.posix.basename(file)})`,
        detail: `${why}${loc?.symbolic?.annotation ? ` Aquí: ${loc.symbolic.annotation}.` : ''} Más: ${f.url || 'https://docs.zizmor.sh'}`.trim(),
        fix: `Arreglo de CI en ${file}:${line} (zizmor: ${f.ident}): ${fix}`,
      });
    }
  }
  if (ignorados) log(`zizmor: ${ignorados} aviso(s) marcados como ignorados por el propio equipo (# zizmor: ignore o zizmor.yml); no salen en el informe`);
  return { findings: out, ok, ignorados };
}

// ---------------------------------------------------------------- reglas comunes a cualquier pipeline
// Las mismas para GitHub Actions, Bitbucket Pipelines, GitLab, Jenkins, Azure o CircleCI.
const LINE_RULES = [
  { id: 'curl-a-shell', re: /\b(curl|wget)\b[^\n|#]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, sev: 'medium', etapa: 'ci',
    t: 'El pipeline descarga un script de internet y lo ejecuta sin comprobarlo', d: 'Si esa web o su dominio cambian de manos, el CI ejecuta lo que ellos quieran, con sus secretos.', f: 'descarga el script, comprueba su SHA-256 y solo entonces ejecútalo; mejor aún, usa un paquete o una imagen fijados.' },
  { id: 'ssh-sin-host-key', re: /StrictHostKeyChecking\s*=?\s*no|UserKnownHostsFile\s*=?\s*\/dev\/null/i, sev: 'medium', etapa: 'destino',
    t: 'El despliegue por SSH no comprueba la identidad del servidor', d: 'Quien se ponga en medio puede hacerse pasar por el servidor y recibir el código, o la clave de despliegue.', f: 'guarda la huella del servidor (ssh-keyscan una vez, en un secreto o en known_hosts del repo) y quita StrictHostKeyChecking=no.' },
  { id: 'tls-desactivado', re: /\bcurl\b[^\n]*\s(-k|--insecure)\b|--no-check-certificate|sslVerify\s*=?\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|GIT_SSL_NO_VERIFY/i, sev: 'medium', etapa: 'ci',
    t: 'El pipeline desactiva la comprobación de certificados', d: 'Lo que descarga o envía puede interceptarse y cambiarse por el camino.', f: 'quita la opción que desactiva TLS y, si es una CA propia, añádela a la confianza del runner.' },
  { id: 'claves-fijas-nube', re: /aws-access-key-id\s*:|\bAWS_ACCESS_KEY_ID\b\s*[:=]\s*['"]?\$|credentials_json\s*:|AZURE_CREDENTIALS|\bcreds\s*:\s*\$\{\{\s*secrets\./i, sev: 'medium', etapa: 'credenciales',
    t: 'El CI entra en la nube con claves fijas', d: 'Esas claves viven en los secretos del CI y no caducan: si se filtran (un log, un fork, una acción comprometida), sirven hasta que alguien las revoque.', f: 'usa OIDC (role-to-assume en GitHub, oidc: true en Bitbucket) con un rol limitado a este repo y rama, y borra las claves fijas.' },
  { id: 'docker-login-password', re: /docker\s+login\b[^\n]*\s(-p|--password)\s/i, sev: 'low', etapa: 'credenciales',
    t: 'La contraseña del registro va en la línea de órdenes', d: 'Queda en el historial y, con la depuración activa, en el log.', f: 'usa docker login --password-stdin.' },
  { id: 'set-x', re: /^\s*-?\s*(set\s+-[a-wyz]*x|bash\s+-x\b)/m, sev: 'low', etapa: 'ci',
    t: 'El pipeline imprime cada orden con sus variables (set -x)', d: 'Los secretos que no estén enmascarados acaban en el log.', f: 'quita set -x de los pasos que manejan secretos.' },
  { id: 'echo-secreto', re: /\becho\b[^\n]*\$\{?\{?\s*(secrets\.)?[A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\b/i, sev: 'medium', etapa: 'credenciales',
    t: 'El pipeline imprime un secreto en el log', d: 'Aunque la plataforma tape los secretos registrados, cualquier transformación (base64, otro nombre) se escapa.', f: 'no hagas echo de secretos; si hay que pasarlos a un fichero, usa printf %s "$VAR" > fichero sin mostrarlo.' },
];
// imágenes del CI sin versión fija (Bitbucket, GitLab, CircleCI, Azure)
const IMAGE = /^\s*(?:-\s*)?(?:image|name)\s*:\s*['"]?([a-z0-9][\w.\/-]*)(?::([\w.-]+))?['"]?\s*$/i;

/** Las reglas comunes sobre cada fichero de pipeline. */
export function ciLineFindings(root, ciFiles) {
  const out = [];
  for (const { fichero, ci } of ciFiles) {
    let text = ''; try { text = fs.readFileSync(path.join(root, fichero), 'utf8'); } catch { continue; }
    const lines = text.split(/\r?\n/);
    lines.forEach((l, i) => {
      if (/^\s*#/.test(l)) return;
      for (const r of LINE_RULES) {
        // en GitHub Actions las claves fijas y los echo ya los cubren zizmor y Semgrep con más contexto
        if (ci === 'github-actions' && ['echo-secreto'].includes(r.id)) continue;
        if (r.re.test(l)) out.push({ tool: 'lupa-ci', cat: 'cicd', etapa: r.etapa, rule: `ci.${r.id}`, severity: r.sev, file: fichero, line: i + 1, title: `${r.t} (${path.posix.basename(fichero)})`, detail: r.d, fix: `Arreglo de CI en ${fichero}:${i + 1}: ${r.f}` });
      }
      // «image: x» o, en la forma larga de Bitbucket/GitLab, el «name:» que va justo debajo de «image:»
      const prev = lines.slice(0, i).reverse().find((x) => x.trim()) || '';
      const isImage = /^\s*(?:-\s*)?image\s*:/i.test(l) || (/^\s*name\s*:/i.test(l) && /^\s*image\s*:\s*$/i.test(prev));
      const m = isImage && ci !== 'github-actions' && ci !== 'jenkins' ? IMAGE.exec(l) : null;
      if (m && !/@sha256:/.test(l) && (!m[2] || m[2] === 'latest')) out.push({ tool: 'lupa-ci', cat: 'cicd', etapa: 'artefactos', rule: 'ci.imagen-sin-version', severity: 'low', file: fichero, line: i + 1,
        title: `El pipeline usa la imagen ${m[1]} sin versión fija (${path.posix.basename(fichero)})`, detail: 'Con «latest» o sin etiqueta, una imagen nueva (rota o maliciosa) entra sola en el CI.', fix: `Arreglo de CI en ${fichero}:${i + 1}: fija la imagen a una versión, o mejor a su digest sha256.` });
    });
    // Bitbucket: un pull request que despliega corre con las variables del repo
    if (ci === 'bitbucket-pipelines') {
      const pr = section(lines, 'pull-requests');
      if (pr && /\bdeployment\s*:|\b(deploy|kubectl|helm|terraform\s+apply|aws\s+(s3|ecs|lambda))\b/i.test(pr.text)) out.push({ tool: 'lupa-ci', cat: 'cicd', etapa: 'destino', rule: 'ci.pr-despliega', severity: 'medium', file: fichero, line: pr.line,
        title: 'Los pipelines de pull request despliegan', detail: 'Un cambio que aún no ha revisado nadie llega a un entorno con las variables y permisos del repo.', fix: `Arreglo de CI en ${fichero}:${pr.line}: deja en pull-requests solo pruebas y build; despliega desde branches: tras el merge.` });
    }
  }
  return out;
}

/** El bloque de una clave de pipelines: (sus líneas hasta la siguiente clave del mismo nivel). */
function section(lines, key) {
  const i = lines.findIndex((l) => new RegExp(`^(\\s+)${key}\\s*:`).test(l));
  if (i < 0) return null;
  const ind = /^(\s*)/.exec(lines[i])[1].length;
  let j = i + 1;
  while (j < lines.length && (!lines[j].trim() || /^(\s*)/.exec(lines[j])[1].length > ind)) j++;
  return { line: i + 1, text: lines.slice(i, j).join('\n') };
}

// ---------------------------------------------------------------- a dónde despliega y con qué credenciales
const DESTINOS = [
  ['AWS ECR', /amazon-ecr-login|\.dkr\.ecr\.|aws ecr get-login|aws-ecr-push-image/i], ['GitHub Container Registry', /ghcr\.io/i],
  ['Docker Hub', /docker\.io\/|registry-1\.docker|docker\/login-action(?![\s\S]{0,200}registry:)/i], ['AWS S3', /aws s3 (sync|cp)|aws-s3-deploy/i],
  ['AWS ECS', /ecs update-service|amazon-ecs-deploy|aws-ecs-deploy|ecs-deploy-task-definition/i], ['AWS Lambda', /lambda update-function|aws-lambda-deploy|serverless deploy|sam deploy/i],
  ['Kubernetes', /\bkubectl\b|\bhelm (upgrade|install)\b/i], ['Servidores por SSH', /\bscp\b|\brsync\b|appleboy\/ssh-action|atlassian\/ssh-run|sftp-deploy|\bssh\b[^\n]*\s[\w.-]+@[\w.-]+/i],
  ['Terraform', /terraform (apply|-chdir=\S+ apply)/i], ['AWS SSM', /ssm send-command/i], ['CloudFormation', /cloudformation deploy|aws-cloudformation/i],
  ['Google Cloud', /gcloud (run|app|functions) deploy|google-github-actions\/deploy/i], ['Azure', /azure\/webapps-deploy|az webapp|az functionapp/i],
  ['Vercel / Netlify / Heroku / Fly', /vercel|netlify deploy|heroku|flyctl deploy/i],
];

/** Qué se ve del despliegue en los pipelines: destinos, cómo entra en la nube, si firma lo que publica. */
export function deployModel(root, ciFiles) {
  const text = ciFiles.map(({ fichero }) => { try { return fs.readFileSync(path.join(root, fichero), 'utf8'); } catch { return ''; } }).join('\n');
  const oidc = /role-to-assume|id-token:\s*write|\boidc:\s*true\b|workload_identity_provider|azure\/login[\s\S]{0,300}client-id/i.test(text);
  const fijas = /aws-access-key-id\s*:|\bAWS_ACCESS_KEY_ID\b\s*[:=]\s*['"]?\$|credentials_json\s*:|AZURE_CREDENTIALS/i.test(text);
  return {
    destinos: DESTINOS.filter(([, re]) => re.test(text)).map(([n]) => n),
    credenciales: oidc && fijas ? 'mixto' : oidc ? 'oidc' : fijas ? 'claves-fijas' : 'no-se-ve',
    publicaImagenes: /docker push|build-push-action|buildx[^\n]*--push|kaniko|aws-ecr-push-image/i.test(text),
    firma: /cosign|sigstore|attest-build-provenance|notation sign/i.test(text),
    sbom: /\bsyft\b|sbom-action|cyclonedx|--format\s+spdx/i.test(text),
    runnersPropios: /runs-on:\s*\[?\s*['"]?self-hosted|runs-on:\s*\n\s*-\s*['"]?self\.hosted|\bself\.hosted\b/i.test(text),
  };
}

// ---------------------------------------------------------------- confianza OIDC en el Terraform del CI
const OIDC_MARK = /token\.actions\.githubusercontent\.com|github_oidc|pipelines-config\/identity\/oidc|gitlab\.com|oidc-provider\//i;

/** Roles que confían en el CI (OIDC) sin decir qué repo o rama puede usarlos, o con comodines. */
export function oidcTerraformFindings(root, files) {
  const out = [];
  // los datos de prueba (políticas de ejemplo en testdata/) no son la configuración real
  for (const f of files.filter((x) => /\.tf$/.test(x) && !/(^|\/)(tests?|testdata|fixtures?|__tests__|examples?)\//i.test(x))) {
    let text = ''; try { text = fs.readFileSync(path.join(root, f), 'utf8'); } catch { continue; }
    if (!/AssumeRoleWithWebIdentity/.test(text) || !OIDC_MARK.test(text)) continue;
    const line = text.slice(0, text.search(/AssumeRoleWithWebIdentity/)).split('\n').length;
    const add = (rule, sev, t, d) => out.push({ tool: 'lupa-ci', cat: 'cicd', etapa: 'credenciales', rule, severity: sev, file: f, line, title: `${t} (${path.posix.basename(f)})`, detail: d,
      fix: `Arreglo en ${f}:${line}: añade a la confianza una condición sobre «:sub» que nombre el repositorio y la rama o entorno concretos (repo:<org>/<repo>:ref:refs/heads/main, o :environment:production), y otra sobre «:aud».` });
    // solo cuentan los valores de la condición sobre «:sub» (un «Resource = "*"» de otra política no dice nada de la confianza)
    const subs = oidcSubValues(text);
    // el proveedor de Bitbucket es de un workspace: sin «sub» entra cualquier repo de ese workspace, no de todo Bitbucket
    const bitbucket = /pipelines-config\/identity\/oidc/.test(text) && !/token\.actions\.githubusercontent/.test(text);
    if (!subs) add('ci.oidc-sin-sub', bitbucket ? 'medium' : 'high', 'Un rol de la nube confía en el CI sin decir qué repositorio puede usarlo', bitbucket ? 'Sin condición sobre «sub», cualquier repositorio del workspace de Bitbucket puede pedir credenciales de ese rol.' : 'Sin condición sobre «sub», cualquier repositorio de la plataforma (de cualquier organización, en GitHub) puede pedir credenciales de ese rol.');
    else {
      const k = oidcScope(subs);
      if (k === 'cualquiera') add('ci.oidc-comodin', 'high', 'Un rol de la nube confía en cualquier repositorio del CI', `La condición sobre «sub» (${subs.slice(0, 3).join(', ')}) deja pasar a cualquier repositorio.`);
      else if (k === 'organizacion') add('ci.oidc-org', 'medium', 'Un rol de la nube confía en todos los repositorios de la organización', `Condición: ${subs.slice(0, 3).join(', ')}. Cualquier repo de la organización (también uno nuevo o de prueba) puede asumir ese rol.`);
      else if (k === 'cualquier-rama') add('ci.oidc-cualquier-rama', 'medium', 'Un rol de la nube confía en cualquier rama del repositorio', `Condición: ${subs.slice(0, 3).join(', ')}. Una rama de pruebas o el pipeline de un pull request puede pedir las mismas credenciales que producción.`);
    }
  }
  return out;
}

/**
 * Los valores de las condiciones sobre «…:sub» de un fichero de Terraform, en las dos formas habituales:
 * bloques condition { variable = "…:sub"  values = [ … ] } (en cualquier orden) y mapas jsonencode/JSON
 * «"…:sub" = "…"» o «: [ … ]». null si no hay ninguna condición sobre «sub».
 */
export function oidcSubValues(text) {
  const vals = [];
  let found = false;
  for (const body of hclBlocks(text, 'condition')) {
    // por línea: la variable suele ir interpolada con comillas dentro («${replace(local.url, "https://", "")}:sub»)
    if (!/variable\s*=[^\n]*:sub"/.test(body)) continue;
    found = true;
    const v = /values\s*=\s*\[([^\]]*)\]/.exec(body);
    if (v) vals.push(...[...v[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]));
  }
  for (const m of text.matchAll(/"[^"\n]*:sub"\s*[:=]\s*(\[[^\]]*\]|"[^"]*")/g)) {
    found = true;
    vals.push(...[...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]));
  }
  return found ? vals : null;
}

/** El cuerpo de cada bloque «nombre { … }» de HCL, contando llaves (un «${local.repo}» dentro no lo corta). */
function hclBlocks(text, name) {
  const out = [];
  for (const m of text.matchAll(new RegExp(`\\b${name}\\s*\\{`, 'g'))) {
    let depth = 0, i = m.index + m[0].length - 1;
    for (let j = i; j < text.length; j++) {
      if (text[j] === '{') depth++;
      else if (text[j] === '}' && --depth === 0) { out.push(text.slice(i + 1, j)); break; }
    }
  }
  return out;
}

/** A quién deja pasar una lista de valores de «sub»: a cualquiera, a la organización, a cualquier rama, o a lo concreto. */
export function oidcScope(subs) {
  if (subs.some((s) => s === '*' || /^repo:\*/.test(s))) return 'cualquiera';
  // «repo:acme/*» o «repo:${var.org}/*»: cualquier repo de la organización
  if (subs.some((s) => /^repo:[^:]*\/\*(:|$)/.test(s))) return 'organizacion';
  if (subs.some((s) => /^repo:[^:]+\/[^:]+:\*$/.test(s))) return 'cualquier-rama';
  return 'concreto';
}

/** Cómo está cada etapa del camino a producción (para el diagrama del informe), con lo que queda tras la criba. */
export function stageSummary(findings) {
  const etapas = {};
  // lo grave primero, y de ahí los cuatro primeros de cada etapa
  const cicd = findings.filter((x) => x.cat === 'cicd').sort((a, b) => (a.severity === 'high' ? 0 : 1) - (b.severity === 'high' ? 0 : 1));
  for (const f of cicd) {
    const e = etapas[f.etapa || 'ci'] ||= { high: 0, medium: 0, low: 0, titulos: [] };
    e[f.severity]++;
    if (f.severity !== 'low' && e.titulos.length < 4 && !e.titulos.some((x) => x.titulo === f.title)) e.titulos.push({ titulo: f.title, gravedad: f.severity });
  }
  return etapas;
}

// ---------------------------------------------------------------- lo que trae la plataforma → hallazgos
const CLOUD_KEY = /^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET|GCP_SA_KEY|GOOGLE_CREDENTIALS|GCLOUD_SERVICE_KEY|[A-Z_]*SERVICE_ACCOUNT_KEY)$/i;
const isProdEnv = (e) => e.produccion || (/(^|[-_ ])(prod|production|producci[oó]n|live|prd)([-_ ]|$)/i.test(e.nombre) && !/(pre|non|no)[-_ ]?prod/i.test(e.nombre));
// solo estas plataformas tienen entornos de despliegue que se puedan leer por API
const HAS_ENVS = new Set(['github', 'bitbucket-cloud']);

/**
 * Las reglas sobre la plataforma, iguales para GitHub y Bitbucket: rama principal, revisión de verdad,
 * permisos del CI, secretos, entornos de producción, runners, claves de despliegue, webhooks, alertas y logs.
 * Cada repositorio es su propia tarjeta (cicd/<repo>/plataforma) y cada log, la suya: nada se pisa entre repos.
 */
export function platformFindings(p, model = {}) {
  if (!p || p.error || p.soloFicheros) return [];
  const out = [];
  const name = { github: 'GitHub', 'bitbucket-cloud': 'Bitbucket', 'bitbucket-server': 'Bitbucket Server' }[p.plataforma] || p.plataforma;
  const card = `cicd/${p.repo}/plataforma`;
  const add = (etapa, rule, severity, title, detail, fix, file = card, clave = '') => out.push({ tool: 'lupa-plataforma', cat: 'cicd', etapa, rule: `plataforma.${rule}`, severity, file, line: 1,
    title: `${title} (${p.repo})`, detail, fix: `Arreglo en ${name} (${p.repo}): ${fix}`, clave: `${p.repo}|${rule}|${clave || title}` });
  const b = p.ramaPrincipal || 'main', pr = p.proteccion || {};
  // en una cuenta personal gratuita, GitHub no permite proteger ramas ni pedir aprobación en entornos de repos privados
  const plan = p.plataforma === 'github' && p.cuentaPersonal && p.privado ? ' El repositorio es privado y está en una cuenta personal: ahí GitHub no permite proteger ramas ni exigir aprobación en los entornos; hace falta moverlo a una organización con plan Team o superior.' : '';
  if (pr.conocida && !pr.existe) add('codigo', 'rama-sin-proteger', 'high', `La rama principal (${b}) no está protegida`, `Cualquiera con permiso de escritura puede subir directamente a la rama que se despliega, sin revisión y sin dejar rastro en un pull request.${plan}`, `protege ${b}: cambios solo por pull request, con al menos una aprobación, y sin push --force ni borrado.`);
  if (pr.existe && pr.exigePR === false) add('codigo', 'sin-pr', 'medium', `Se puede subir a ${b} sin pull request`, 'La protección existe, pero deja empujar cambios directos que nadie revisa.', `exige pull request para ${b} (también para los administradores).`);
  if (pr.existe && pr.exigePR && pr.aprobaciones === 0) add('codigo', 'sin-aprobacion', 'medium', 'Los pull requests se mergean sin que nadie los apruebe', 'El autor puede mergear su propio cambio a producción sin una segunda mirada.', 'exige al menos una aprobación que no sea del autor.');
  if (pr.existe && pr.forcePush === true) add('codigo', 'force-push', 'medium', `Se puede reescribir el historial de ${b} (push --force)`, 'Permite borrar cambios ya revisados o colar otros sin rastro.', `prohíbe push --force en ${b}.`);
  if (pr.existe && pr.borrar === true) add('codigo', 'borrar-rama', 'low', `Se puede borrar la rama ${b}`, 'Un error o un abuso se lleva por delante la rama principal.', `prohíbe borrar ${b}.`);
  if (pr.existe && pr.aplicada === false) add('codigo', 'checks-no-obligatorios', 'low', 'Las aprobaciones son una recomendación, no una obligación', `${name} avisa si faltan aprobaciones, pero deja mergear igualmente.`, 'activa la obligación de las comprobaciones de merge (en Bitbucket Cloud, «Enforce merge checks», del plan Premium).');
  if (pr.existe && pr.adminsExentos === true) add('codigo', 'admins-exentos', 'low', 'Los administradores se saltan la protección de la rama', 'Una cuenta de administrador comprometida sube a producción sin revisión.', 'aplica la protección también a los administradores.');
  const rv = p.revisionReal;
  if (rv && rv.cambios >= 5 && rv.aprobados / rv.cambios < 0.5) add('codigo', 'poca-revision', 'medium', `Solo ${rv.aprobados} de los ${rv.cambios} últimos cambios en ${b} pasaron por una revisión aprobada`, 'En la práctica, casi todo llega a producción sin que nadie más lo mire.', 'exige aprobación antes de mergear y revisa por qué se está saltando.');
  if (p.ci?.permisosPorDefecto === 'write') add('ci', 'token-escritura', 'medium', 'El token del CI tiene permiso de escritura por defecto', 'Cualquier workflow, también uno nuevo o de un PR, puede escribir en el repositorio y en sus paquetes.', 'pon los permisos por defecto en solo lectura (Settings → Actions → Workflow permissions) y da escritura solo a los jobs que la necesiten.');
  if (p.ci?.puedeAprobarPRs) add('ci', 'ci-aprueba', 'medium', 'El CI puede crear y aprobar pull requests', 'Un workflow comprometido puede aprobar su propio cambio y saltarse la revisión.', 'desactiva «Allow GitHub Actions to create and approve pull requests».');
  if (p.ci?.accionesPermitidas === 'all') add('ci', 'acciones-cualquiera', 'low', 'El CI puede usar cualquier acción de terceros', 'No hay lista de acciones aprobadas: cualquiera que añada un workflow decide qué código externo se ejecuta.', 'limita las acciones a las de GitHub, las verificadas y una lista vuestra.');
  for (const s of (p.secretos || []).filter((x) => CLOUD_KEY.test(x.nombre))) add('credenciales', 'clave-nube', 'medium', `El CI guarda claves fijas de la nube (${s.nombre}${s.ambito !== 'repo' ? `, ${s.ambito}` : ''})`, 'No caducan: si se filtran, sirven hasta que alguien las revoque.', 'cambia a OIDC con un rol limitado a este repo y rama, y borra esa variable.', card, `${s.nombre}|${s.ambito}`);
  // una variable sin proteger con nombre de secreto: grave si su valor también lo parece; si no, a mirar
  for (const s of (p.secretos || []).filter((x) => x.protegido === false && secretName(x.nombre))) {
    const likely = s.valorPareceSecreto !== false;
    add('credenciales', 'variable-sin-proteger', likely ? 'high' : 'medium', `La variable ${s.nombre} parece un secreto y no está protegida`, `Su valor se ve en la configuración del repositorio y puede salir tal cual en los logs.${likely ? '' : ' Por su forma podría no serlo: confírmalo.'}`, `márcala como secured${likely ? ' y rótala, porque ya ha estado a la vista' : ' si es un secreto'}.`, card, `${s.nombre}|${s.ambito}`);
  }
  for (const e of (p.entornos || []).filter(isProdEnv).filter((x) => x.aprobacion === false)) add('destino', 'prod-sin-aprobacion', 'medium', `Desplegar a «${e.nombre}» no pide aprobación de nadie`, `Cualquier cambio que llegue a la rama, o cualquier ejecución manual, despliega a producción sin un segundo par de ojos.${plan}`, `añade revisores obligatorios (o solo administradores) al entorno ${e.nombre}.`, card, e.nombre);
  if (HAS_ENVS.has(p.plataforma) && p.entornosLeidos && !(p.entornos || []).length && model.destinos?.length) add('destino', 'sin-entornos', 'low', 'Los despliegues no usan entornos de la plataforma', 'Sin entornos no se puede exigir aprobación para producción ni separar sus secretos.', 'crea un entorno de producción con aprobación obligatoria y mueve allí sus secretos.');
  if (p.privado === false && (p.ci?.runnersPropios || model.runnersPropios)) add('ci', 'runners-publico', 'high', 'Repositorio público con runners propios', 'Cualquiera puede abrir un pull request y ejecutar código en vuestras máquinas de CI, que suelen tener acceso a la red interna.', 'usa runners de la plataforma para lo que venga de PRs, o aísla los propios.');
  for (const k of (p.clavesDespliegue || []).filter((x) => x.escritura)) add('credenciales', 'clave-escritura', 'medium', `La clave de despliegue «${k.titulo}» puede escribir en el repositorio`, 'Quien tenga esa clave (un servidor, un script) puede subir código.', 'déjala en solo lectura si no necesita escribir.', card, k.titulo);
  for (const k of (p.clavesDespliegue || []).filter((x) => x.creada && Date.now() - Date.parse(x.creada) > 365 * 86_400_000)) add('credenciales', 'clave-vieja', 'low', `La clave de despliegue «${k.titulo}» tiene más de un año`, 'Las claves viejas suelen estar copiadas en sitios de los que nadie se acuerda.', 'rótala y borra la vieja.', card, k.titulo);
  for (const w of p.webhooks || []) {
    if (/^http:\/\//i.test(w.url)) add('ci', 'webhook-http', 'medium', `Un webhook manda los eventos sin cifrar (${w.host})`, 'El contenido de los eventos (y su firma) viaja en claro.', 'cambia la URL a https.', card, w.host);
    if (w.verificaTls === false) add('ci', 'webhook-sin-tls', 'medium', `Un webhook no comprueba el certificado del destino (${w.host})`, 'Quien se ponga en medio recibe los eventos del repositorio.', 'activa la comprobación SSL del webhook.', card, w.host);
  }
  for (const c of (p.colaboradoresExternos || []).filter((x) => /admin|write|maintain|push/i.test(x.permiso))) add('codigo', 'externo-escritura', 'medium', `Un colaborador externo (${c.usuario}) tiene permiso de ${c.permiso}`, 'Alguien de fuera de la organización puede cambiar el código.', 'revisa si sigue haciendo falta y bájale el permiso.', card, c.usuario);
  if (p.alertas?.secretos > 0) add('credenciales', 'alertas-secretos', 'high', `${p.alertas.secretos} secreto(s) detectado(s) por ${name} siguen sin cerrar`, `La propia plataforma los encontró en el código o en el historial (${(p.alertas.tiposSecretos || []).slice(0, 4).join(', ')}).`, 'rótalos y cierra las alertas.');
  if (p.alertas?.dependenciasGraves > 0) add('artefactos', 'alertas-dependencias', 'medium', `${p.alertas.dependenciasGraves} alerta(s) graves de dependencias abiertas en ${name}`, 'Librerías con vulnerabilidades críticas o altas que nadie ha actualizado.', 'atiende las alertas de Dependabot (o equivalente).');
  if (p.seguridad?.escaneoSecretos === false) add('credenciales', 'sin-escaneo-secretos', 'low', 'El escaneo de secretos de la plataforma está apagado', 'Un secreto subido por error no avisa a nadie.', 'activa secret scanning y la protección al hacer push.');
  // cada secreto de un log es su propia tarjeta: la criba de uno (un id de Terraform) no se lleva por delante a
  // otro (un token real). La regla genérica de gitleaks salta con ids y hashes: es «posible», y la criba la IA.
  const slug = (s) => String(s).replace(/[^\w.-]+/g, '-').slice(0, 60);
  for (const l of p.logs?.hallazgos || []) {
    const generic = /^generic-/.test(l.regla);
    add('credenciales', generic ? 'posible-secreto-en-log' : 'secreto-en-log', generic ? 'medium' : 'high', `${generic ? 'Posible secreto' : `Un secreto (${l.regla})`} en el log de «${l.pipeline}»`,
      `Ejecución ${l.ejecucion}${l.paso ? `, paso «${l.paso}»` : ''}${l.contexto ? `. Contexto, con el valor tapado: «${l.contexto}»` : ''}. Quien pueda ver las ejecuciones puede copiarlo; la plataforma no lo tapó porque no estaba registrado como secreto.${generic ? ' Es la regla genérica de gitleaks: confirma que no es un id o un hash antes de rotar nada.' : ''}`,
      'confirma qué es; si es un secreto, rótalo, cambia el pipeline para que no lo imprima y borra los logs de esas ejecuciones.',
      `cicd/${p.repo}/logs/${slug(l.ejecucion)}/${slug(l.paso || 'paso')}`, `${l.regla}|${l.ejecucion}|${l.paso}`);
  }
  return out;
}

/** Roles y usuarios de AWS que usa el CI: confianza OIDC demasiado abierta, permisos de más, claves viejas. */
export function awsCiFindings(aws) {
  const out = [];
  if (!aws || aws.error) return out;
  const add = (rule, severity, title, detail, fix, clave) => out.push({ tool: 'lupa-aws', cat: 'cicd', etapa: 'destino', rule: `aws.${rule}`, severity, file: 'cicd/aws', line: 1, title, detail, fix: `Arreglo en AWS: ${fix}`, clave: `${rule}|${clave}` });
  for (const r of aws.roles || []) {
    // el proveedor OIDC de Bitbucket es de un workspace: sin «sub» entra su workspace, no todo Bitbucket
    const bb = r.proveedor === 'Bitbucket';
    const scope = r.sub.length ? oidcScope(r.sub) : null;
    if (!r.sub.length) add('oidc-sin-sub', bb ? 'medium' : 'high', `El rol ${r.nombre} confía en el CI (${r.proveedor}) sin limitar el repositorio`, bb ? 'Cualquier repositorio del workspace de Bitbucket puede pedir credenciales de este rol.' : 'Cualquier repositorio de la plataforma puede pedir credenciales de este rol.', 'añade a su confianza una condición sobre «sub» con el repositorio y la rama concretos.', r.nombre);
    else if (scope === 'cualquiera') add('oidc-comodin', 'high', `El rol ${r.nombre} confía en cualquier repositorio (${r.sub.join(', ')})`, 'El comodín deja pasar a repositorios de otros.', 'cambia el comodín por el repositorio y la rama concretos.', r.nombre);
    else if (scope === 'organizacion') add('oidc-org', 'medium', `El rol ${r.nombre} confía en todos los repositorios de la organización`, `Condición: ${r.sub.join(', ')}. Cualquier repo de la organización puede asumirlo.`, 'limítalo al repositorio y la rama que despliegan.', r.nombre);
    else if (scope === 'cualquier-rama') add('oidc-cualquier-rama', 'medium', `El rol ${r.nombre} confía en cualquier rama del repositorio`, `Condición: ${r.sub.join(', ')}. Una rama de pruebas o un pull request obtienen las mismas credenciales que producción.`, 'limítalo a la rama principal o al entorno de producción.', r.nombre);
    const admin = r.politicas.filter((x) => /^(AdministratorAccess|IAMFullAccess)$/.test(x));
    if (admin.length) add('ci-admin', 'high', `El CI puede con toda la cuenta de AWS (rol ${r.nombre}: ${admin.join(', ')})`, 'Si el pipeline se ve comprometido, la cuenta entera lo está.', 'cambia esas políticas por una con solo los permisos del despliegue.', r.nombre);
    else if (r.politicas.includes('PowerUserAccess')) add('ci-poweruser', 'medium', `El rol ${r.nombre} del CI tiene PowerUserAccess`, 'Puede tocar casi cualquier servicio de la cuenta.', 'acótalo a lo que despliega.', r.nombre);
  }
  for (const u of aws.usuarios || []) for (const k of u.claves.filter((x) => x.dias > 90 && x.estado === 'Active')) add('clave-vieja', 'medium', `El usuario ${u.nombre} (CI) tiene una clave de acceso de hace ${k.dias} días`, 'Una clave fija y vieja es la credencial más buscada en una filtración.', 'pasa ese CI a OIDC y desactiva la clave; si no se puede, rótala cada 90 días.', `${u.nombre}|${k.dias}`);
  return out;
}
