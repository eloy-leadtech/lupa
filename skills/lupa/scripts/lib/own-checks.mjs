// Chequeos propios de Lupa, los que no hace ninguna herramienta estándar:
// ficheros delicados subidos al repo, datos personales en ficheros de datos y endpoints
// de frameworks que floorplan no detecta (Laravel, Symfony, Django, PHP suelto).
import fs from 'node:fs';
import path from 'node:path';
import { run, posix } from './util.mjs';
import { SKIP_DIRS } from './scanners.mjs';

const skipped = (p) => p.split('/').some((s) => SKIP_DIRS.includes(s));

export function trackedFiles(root, repos) {
  const out = [];
  for (const repo of repos) {
    const dir = path.join(root, repo.path);
    const r = run('git', ['-C', dir, 'ls-files', '-z'], { timeout: 120_000 });
    if (r.status !== 0) continue;
    for (const f of r.stdout.split('\0').filter(Boolean)) out.push(posix(path.join(repo.path === '.' ? '' : repo.path, f)));
  }
  return out.filter((p) => !skipped(p));
}

// ---------------------------------------------------------------- ficheros delicados
const SENSITIVE = [
  { re: /(^|\/)terraform\.tfstate(\.backup)?$/i, sev: 'high', what: 'el estado de Terraform', why: 'guarda en claro contraseñas, claves y la topología de toda la infraestructura' },
  { re: /\.tfvars$/i, sev: 'medium', what: 'variables de Terraform', why: 'suelen llevar credenciales y datos de cada entorno' },
  { re: /(^|\/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i, sev: 'high', what: 'una clave SSH privada', why: 'da acceso a los servidores que la tengan autorizada' },
  { re: /\.(pem|key|p12|pfx|jks|keystore|ppk)$/i, sev: 'high', what: 'una clave o certificado privado', why: 'permite suplantar al servidor o firmar en su nombre' },
  { re: /(^|\/)\.htpasswd$/i, sev: 'high', what: 'un fichero de contraseñas de Apache', why: 'trae usuarios y contraseñas cifradas que se pueden romper offline' },
  { re: /(^|\/)(credentials|service-account|.*-adminsdk-.*|client_secret.*)\.json$/i, sev: 'high', what: 'credenciales de una cuenta de servicio', why: 'dan acceso directo a la nube (Google, Firebase…)' },
  { re: /(^|\/)(kubeconfig|\.kube\/config)$/i, sev: 'high', what: 'la configuración de acceso a Kubernetes', why: 'permite controlar el clúster' },
  { re: /(^|\/)wp-config\.php$/i, sev: 'medium', what: 'la configuración de WordPress', why: 'lleva la contraseña de la base de datos y las claves de sesión' },
  { re: /\.(sql|dump|bak|backup|sqlite3?|db|mdb)$/i, sev: 'medium', what: 'una copia de base de datos', why: 'puede llevar datos reales de clientes' },
  { re: /\.(har)$/i, sev: 'medium', what: 'una grabación de tráfico del navegador', why: 'suele llevar cookies y tokens de sesión' },
  { re: /(^|\/)(public|static|www|dist|build|web)\/.*\.map$/i, sev: 'low', what: 'un mapa de código fuente público', why: 'deja ver el código original del frontend a cualquiera' },
];

export function sensitiveFiles(files) {
  const out = [];
  for (const file of files) {
    const hit = SENSITIVE.find((s) => s.re.test(file));
    if (!hit) continue;
    if (/(^|\/)(tests?|fixtures?|examples?|samples?|docs?)\//i.test(file) && hit.sev !== 'high') continue;
    out.push({
      tool: 'lupa', cat: 'datos', rule: 'fichero-delicado', severity: hit.sev, file, line: 1,
      title: `Está subido al repo ${hit.what}: ${path.posix.basename(file)}`,
      detail: `${path.posix.basename(file)} es ${hit.what}, y ${hit.why}. Cualquiera con acceso al repositorio (o a una copia) lo tiene.`,
      fix: `Arreglo de seguridad: ${file} es ${hit.what} y está en git. No muestres su contenido.\n1. Sácalo del repo (git rm --cached) y añádelo a .gitignore.\n2. Dime qué credenciales o datos contiene (solo el tipo, nunca el valor) para rotarlas o avisar.\n3. Explícame cómo borrarlo también del historial de git (git filter-repo) y que habrá que forzar el push.`,
    });
  }
  return out;
}

// ---------------------------------------------------------------- dependencias sin bloquear
const MANIFESTS = {
  'package.json': ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'],
  'composer.json': ['composer.lock'],
  Pipfile: ['Pipfile.lock'],
  Gemfile: ['Gemfile.lock'],
  'go.mod': ['go.sum'],
};

/** Un manifiesto sin su fichero de bloqueo (ni en su carpeta ni más arriba): nadie sabe qué versiones se instalan. */
export function unlockedDependencies(files) {
  const set = new Set(files);
  const out = [];
  for (const file of files) {
    const base = path.posix.basename(file);
    const locks = MANIFESTS[base];
    if (!locks || /(^|\/)(tests?|fixtures?|examples?|samples?|docs?)\//i.test(file)) continue;
    let dir = path.posix.dirname(file), locked = false;
    for (;;) {
      if (locks.some((l) => set.has(dir === '.' ? l : `${dir}/${l}`))) { locked = true; break; }
      if (dir === '.' || !dir) break;
      dir = path.posix.dirname(dir);
    }
    if (locked) continue;
    out.push({
      tool: 'lupa', cat: 'dependencias', rule: 'sin-fichero-de-bloqueo', severity: 'medium', file, line: 1,
      title: `Las dependencias de ${file} no están bloqueadas`,
      detail: `No hay ${locks[0]} junto a ${base}. Cada instalación puede traer versiones distintas, incluida una comprometida, y no se pueden buscar sus fallos conocidos (CVE) porque no se sabe qué versión se usa.`,
      fix: `Arreglo de cadena de suministro en ${file}: genera y sube su fichero de bloqueo (${locks[0]}), haz que el CI instale solo desde él (npm ci, composer install…) y dime si alguna dependencia queda en una versión con fallos conocidos.`,
    });
  }
  return out;
}

// ---------------------------------------------------------------- datos personales
const DATA_FILE = /\.(csv|tsv|json|jsonl|ndjson|sql|xml|ya?ml|txt|log)$/i;
const PII = [
  { key: 'dni', label: 'DNI/NIE', re: /\b([XYZ]?\d{7,8}[A-HJ-NP-TV-Z])\b/g, ok: dniOk, strong: true },
  { key: 'iban', label: 'IBAN', re: /\b([A-Z]{2}\d{2}(?:\s?\d{4}){4,7})\b/g, ok: ibanOk, strong: true },
  { key: 'card', label: 'tarjeta de crédito', re: /\b((?:\d[ -]?){13,19})\b/g, ok: luhnOk, strong: true },
  { key: 'email', label: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, ok: (m) => !/@(example|test|localhost|email|domain|acme|foo|bar)\./i.test(m) },
  { key: 'phone', label: 'teléfono', re: /(?<![\d.])(?:\+34[ -]?)?[6789]\d{2}[ -]?\d{3}[ -]?\d{3}(?![\d.])/g, ok: () => true },
];

function dniOk(v) {
  const s = v.toUpperCase().replace(/^X/, '0').replace(/^Y/, '1').replace(/^Z/, '2');
  const n = parseInt(s.slice(0, -1), 10);
  return 'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23] === s.slice(-1);
}
function ibanOk(v) {
  const s = v.replace(/\s/g, '');
  const r = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let m = 0; for (const d of r) m = (m * 10 + +d) % 97;
  return m === 1;
}
function luhnOk(v) {
  const d = v.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) { let x = +d[d.length - 1 - i]; if (i % 2) { x *= 2; if (x > 9) x -= 9; } sum += x; }
  return sum % 10 === 0;
}

export function personalData(root, files) {
  const out = [];
  for (const file of files) {
    if (!DATA_FILE.test(file)) continue;
    if (/(^|\/)(package(-lock)?|composer|tsconfig|\.eslintrc|renovate|lerna)\.json$|(^|\/)(\.github|\.gitlab|\.circleci)\//i.test(file)) continue;
    const abs = path.join(root, file);
    let text;
    try { const st = fs.statSync(abs); if (st.size > 20_000_000) continue; text = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    const counts = {}; let firstLine = 0;
    for (const p of PII) {
      p.re.lastIndex = 0; let m, n = 0;
      while ((m = p.re.exec(text)) && n < 10_000) if (p.ok(m[1] || m[0])) { n++; if (!firstLine) firstLine = text.slice(0, m.index).split('\n').length; }
      if (n) counts[p.key] = n;
    }
    const strong = PII.filter((p) => p.strong && counts[p.key]);
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (!strong.length && total < 20) continue; // unos pocos emails sueltos no son una filtración
    const sev = strong.some((p) => counts[p.key] >= 5) ? 'high' : strong.length || total >= 200 ? 'medium' : 'low';
    const desc = PII.filter((p) => counts[p.key]).map((p) => `${counts[p.key]} ${p.label}`).join(', ');
    out.push({
      tool: 'lupa', cat: 'datos', rule: 'datos-personales', severity: sev, file, line: firstLine || 1, counts,
      title: `Datos personales en ${path.posix.basename(file)} (${desc})`,
      detail: `El fichero ${file} contiene ${desc}. Si son reales, es una filtración de datos personales (RGPD); si son de prueba, conviene sustituirlos por datos inventados que no pasen por reales.`,
      fix: `Revisión de datos personales en ${file}: hay ${desc}. No copies ningún valor en tu respuesta.\n1. Dime si parecen reales o de prueba y de dónde salen.\n2. Si son reales, sácalos del repo y del historial, y prepárame el aviso para el DPO.\n3. Si son de prueba, cámbialos por datos generados (que no pasen validación de DNI/IBAN reales).`,
    });
  }
  return out;
}

// ---------------------------------------------------------------- endpoints que floorplan no ve
const LARAVEL = /Route::(get|post|put|patch|delete|options|any|match)\s*\(\s*(?:\[[^\]]*\]\s*,\s*)?['"]([^'"]+)['"]/gi;
const SYMFONY = /#\[Route\(\s*['"]([^'"]+)['"](?:[^\]]*methods:\s*\[([^\]]*)\])?/g;
const SYMFONY_ANN = /@Route\(\s*"([^"]+)"(?:[^)]*methods=\{([^}]*)\})?/g;
const DJANGO = /\b(?:re_)?path\(\s*r?['"]([^'"]*)['"]\s*,\s*([\w.]+)/g;
const AUTH_HINT = /middleware\(\s*\[?[^)]*\b(auth|sanctum|jwt|admin|can:|verified)|login_required|permission_required|IsAuthenticated|@IsGranted|is_granted|#\[IsGranted|requires_auth|denyAccessUnlessGranted/i;

/** Endpoints declarados en PHP (Laravel/Symfony/suelto) y Django, con una pista de si piden login. */
export function extraEndpoints(root, files, knownFiles = new Set()) {
  const out = [];
  const add = (file, line, method, p, framework, authHint) => out.push({ file, line, method: method.toUpperCase(), path: p, framework, authHint });
  for (const file of files) {
    if (knownFiles.has(file)) continue; // floorplan ya saca las rutas de este fichero
    const isPhp = /\.php$/i.test(file), isPy = /(^|\/)urls\.py$/i.test(file);
    if (!isPhp && !isPy) continue;
    let text; try { text = fs.readFileSync(path.join(root, file), 'utf8'); } catch { continue; }
    const lineAt = (i) => text.slice(0, i).split('\n').length;
    const near = (i) => text.slice(Math.max(0, i - 400), i + 400);
    // Laravel: el login va en la propia ruta (->middleware('auth')) o en el grupo que la contiene
    const statement = (i) => text.slice(i, (text.indexOf(';', i) + 1 || text.length));
    const inAuthGroup = (i) => {
      const re = /Route::middleware\(\s*\[?[^)]*\b(auth|sanctum|jwt|admin|verified)[^)]*\)[^;{]*?->\s*group\(\s*function[^{]*\{/g;
      let m;
      while ((m = re.exec(text)) && m.index < i) {
        let depth = 1;
        for (let k = m.index + m[0].length; k < i && depth > 0; k++) depth += text[k] === '{' ? 1 : text[k] === '}' ? -1 : 0;
        if (depth > 0) return true;
      }
      return false;
    };
    if (isPhp) {
      let m, found = false;
      for (const re of [LARAVEL, SYMFONY, SYMFONY_ANN]) {
        re.lastIndex = 0;
        while ((m = re.exec(text))) {
          found = true;
          if (re === LARAVEL) add(file, lineAt(m.index), m[1] === 'match' || m[1] === 'any' ? 'ANY' : m[1], m[2], 'laravel', AUTH_HINT.test(statement(m.index)) || inAuthGroup(m.index));
          else add(file, lineAt(m.index), (m[2] || 'ANY').replace(/['"\s]/g, '').split(',')[0] || 'ANY', m[1], 'symfony', AUTH_HINT.test(near(m.index)));
        }
      }
      // PHP suelto: cada .php que lee la petición es una página que se puede abrir directamente
      if (!found && /\$_(GET|POST|REQUEST|COOKIE|FILES)\b/.test(text) && !/(^|\/)(tests?|vendor|lib|includes?|classes?)\//i.test(file)) {
        const i = text.search(/\$_(GET|POST|REQUEST|COOKIE|FILES)\b/);
        add(file, lineAt(i), /\$_POST|\$_FILES/.test(text) ? 'POST' : 'GET', '/' + file.replace(/^.*?(public|www|htdocs|web)\//, ''), 'php', /\$_SESSION\s*\[\s*['"](user|uid|login|auth|logged)/i.test(text) || /session_start\(\)[\s\S]{0,400}(header\(\s*['"]Location:\s*[^'"]*login)/i.test(text));
      }
    } else {
      // fuera docstrings y comentarios, que en urls.py suelen traer rutas de ejemplo («path('blog/', …)»);
      // se cambian por espacios del mismo largo para no mover los números de línea
      text = text.replace(/("""|''')[\s\S]*?\1/g, (s) => s.replace(/[^\n]/g, ' ')).replace(/#[^\n]*/g, (s) => ' '.repeat(s.length));
      DJANGO.lastIndex = 0; let m;
      while ((m = DJANGO.exec(text))) add(file, lineAt(m.index), 'ANY', '/' + m[1].replace(/^\^|\$$/g, ''), 'django', AUTH_HINT.test(text.slice(m.index, text.indexOf('\n', m.index) + 1 || text.length)));
    }
  }
  return out;
}

/** Rutas con nombre que da miedo: si son públicas, hay que mirarlas primero. */
export const SENSITIVE_PATH = /(admin|internal|debug|actuator|metrics|console|phpinfo|phpmyadmin|backup|export|dump|import|config|settings|env\b|\.env|graphql|graphiql|playground|swagger|api-docs|openapi|users?|accounts?|customers?|clientes?|usuarios?|payments?|pagos?|invoices?|facturas?|orders?|pedidos?|tokens?|keys?|secrets?|upload|files?|reset|delete|remove|exec|shell|cmd|eval|test|staging)/i;
