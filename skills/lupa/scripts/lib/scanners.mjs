// Lanza gitleaks, Semgrep y Trivy y traduce lo que encuentran a un formato común:
// { tool, cat, rule, severity, file, line, title, detail, fix, where? }
// cat: secretos · codigo · dependencias · infra · exposicion · datos
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { run, readJSON, relTo, posix, normSeverity, tmpDir } from './util.mjs';

/** Carpetas que nunca se escanean: dependencias, compilados y la propia salida de floorplan/Lupa. */
export const SKIP_DIRS = ['node_modules', 'vendor', 'dist', 'build', '.next', '.nuxt', 'coverage', '.venv', 'venv', '__pycache__', 'target', '.terraform', 'floorplan', '.git'];
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|e2e|cypress|playwright)(\/|$)|\.(test|spec)\.[a-z]+$/i;

const tmpFile = (name) => path.join(fs.mkdtempSync(path.join(tmpDir(), 'lupa-')), name);
/** En pruebas y datos de ejemplo baja un escalón: casi siempre es ruido. */
const softenInTests = (sev, file) => (TEST_PATH.test(file) ? (sev === 'high' ? 'medium' : 'low') : sev);

// ---------------------------------------------------------------- gitleaks
/** Secretos en el código y en TODO el historial de git de cada repo. Nunca guarda el valor. */
export function runGitleaks(tool, root, repos, log = () => {}) {
  const out = [];
  const targets = repos.length ? repos : [{ path: '.', git: false }];
  for (const repo of targets) {
    const dir = path.join(root, repo.path);
    const report = tmpFile('gitleaks.json');
    const isGit = fs.existsSync(path.join(dir, '.git'));
    const args = isGit
      ? ['git', dir, '--report-format', 'json', '--report-path', report, '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'warn']
      : ['dir', dir, '--report-format', 'json', '--report-path', report, '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'warn'];
    const r = run(tool.path, args);
    if (r.status !== 0) { log(`gitleaks falló en ${repo.path}: ${(r.stderr || r.error?.message || '').slice(0, 300)}`); continue; }
    const head = isGit ? run('git', ['-C', dir, 'rev-parse', 'HEAD']).stdout.trim() : '';
    // ¿sigue el secreto en el código de hoy? Se mira con una pasada sobre los ficheros actuales
    // (misma regla en el mismo fichero); si no está, solo vive en el historial.
    const now = new Set();
    if (isGit) {
      const cur = tmpFile('gitleaks-hoy.json');
      run(tool.path, ['dir', dir, '--report-format', 'json', '--report-path', cur, '--redact', '--no-banner', '--exit-code', '0', '--log-level', 'error']);
      for (const c of readJSON(cur, []) || []) now.add(`${posix(path.relative(dir, path.resolve(dir, c.File || '')))}|${c.RuleID}`);
    }
    for (const f of readJSON(report, []) || []) {
      const fileInRepo = posix(f.File || '');
      const file = posix(path.join(repo.path === '.' ? '' : repo.path, fileInRepo));
      if (SKIP_DIRS.some((d) => file.split('/').includes(d))) continue;
      const onlyHistory = isGit && !now.has(`${fileInRepo}|${f.RuleID}`);
      out.push({
        tool: 'gitleaks', cat: 'secretos', rule: f.RuleID,
        severity: softenInTests(onlyHistory ? 'medium' : 'high', file),
        file, line: f.StartLine || 1,
        commit: isGit ? String(f.Commit || '').slice(0, 8) : '', date: f.Date ? String(f.Date).slice(0, 10) : '',
        inHistoryOnly: onlyHistory, headCommit: head.slice(0, 8),
        title: onlyHistory ? `Hubo un secreto (${f.RuleID}) en ${path.posix.basename(file)}; ya no está, pero sigue en el historial de git` : `Hay un secreto (${f.RuleID}) escrito en ${path.posix.basename(file)}`,
        detail: `${f.Description || f.RuleID}. ${onlyHistory ? `El fichero ya no lo tiene, pero entró en el commit ${String(f.Commit).slice(0, 8)} (${String(f.Date || '').slice(0, 10)}) y cualquiera que clone el repo puede recuperarlo.` : 'Cualquiera con acceso al repositorio puede usarlo.'} Hay que darlo por filtrado: rotarlo en el servicio y sacarlo del código.`,
        fix: `Arreglo de seguridad: secreto (${f.RuleID}) en ${file}:${f.StartLine}${onlyHistory ? ` (solo en el historial, commit ${String(f.Commit).slice(0, 8)})` : ''}. No escribas ni repitas su valor en respuestas, commits o logs.\n1. ${onlyHistory ? 'No hay que tocar el código actual.' : 'Sustituye el literal por una variable de entorno y falla con un error claro si falta.'}\n2. Dame una lista (sin valores) de qué servicio es, para rotarlo: crear uno nuevo, ponerlo en el entorno y revocar el viejo.\n3. Explícame cómo limpiar el historial de git si hace falta (git filter-repo) y avisa de que hay que forzar el push.`,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------- Semgrep
export const SEMGREP_PACKS = ['p/default', 'p/owasp-top-ten', 'p/security-audit'];

/** Fallos de seguridad en el código (inyecciones, XSS, criptografía débil…) más las reglas propias de Lupa. */
export function runSemgrep(tool, root, { rulesFile, packs = SEMGREP_PACKS, log = () => {} } = {}) {
  const report = tmpFile('semgrep.json');
  // En Windows, semgrep-core en paralelo revienta («RPC subprocess failed»): ahí va con un solo proceso.
  const jobs = process.platform === 'win32' ? 1 : Math.max(2, os.cpus().length - 1);
  const args = ['scan', '--json', '--output', report, '--metrics=off', '--disable-version-check', '--quiet', '--timeout', '20', '--max-target-bytes', '2000000', '--jobs', String(jobs)];
  for (const p of packs) args.push('--config', p);
  if (rulesFile) args.push('--config', rulesFile);
  for (const d of SKIP_DIRS) args.push('--exclude', d);
  args.push(root);
  const r = run(tool.path, args, { cwd: root });
  const data = readJSON(report);
  if (!data) { log(`Semgrep no dio resultados: ${(r.stderr || r.error?.message || '').slice(-400)}`); return []; }
  for (const e of data.errors || []) if (e.level === 'error') log(`Semgrep: ${String(e.message || e.type).slice(0, 200)}`);
  const out = [];
  for (const x of data.results || []) {
    const m = x.extra?.metadata || {};
    // las reglas propias llegan con la ruta del fichero delante («lupa.skills.lupa.rules.lupa.exposicion.…»)
    const mine = /(lupa\.(?:jenkins|ci|docker|exposicion|secretos)\.[\w-]+)$/.exec(String(x.check_id));
    const own = !!mine && !!m['lupa-cat'];
    const checkId = own ? mine[1] : String(x.check_id);
    if (!own && m.category && m.category !== 'security') continue; // solo seguridad, nada de estilo
    const file = relTo(root, x.path);
    const rule = checkId.split('.').pop();
    const cat = own ? m['lupa-cat'] : 'codigo';
    out.push({
      tool: 'semgrep', cat, rule: checkId,
      severity: softenInTests(normSeverity(m['lupa-severity'] || x.extra?.severity), file),
      file, line: x.start?.line || 1,
      cwe: [].concat(m.cwe || []).map((c) => String(c).split(':')[0]).join(', '),
      owasp: [].concat(m.owasp || []).join(', '),
      title: own ? x.extra.message.split('\n')[0] : `Posible fallo de seguridad (${rule.replace(/[-_]/g, ' ')}) en ${path.posix.basename(file)}`,
      detail: own ? (m['lupa-detail'] || x.extra.message) : x.extra?.message || rule,
      fix: `Arreglo de seguridad en ${file}:${x.start?.line}: la regla ${x.check_id}${m.cwe ? ` (${[].concat(m.cwe)[0]})` : ''} avisa de esto:\n${x.extra?.message}\n\nComprueba si es un problema real en este contexto. Si lo es, arréglalo con el cambio mínimo, añade una prueba que lo demuestre y explícame en dos frases qué riesgo quitaba. Si no lo es, dime por qué.`,
    });
  }
  return out;
}

// ---------------------------------------------------------------- Trivy
/** Librerías con fallos conocidos (CVE) y servidores mal configurados (Terraform, Docker, Kubernetes…). */
export function runTrivy(tool, root, log = () => {}) {
  const report = tmpFile('trivy.json');
  const args = ['fs', '--scanners', 'vuln,misconfig', '--format', 'json', '--output', report, '--quiet', '--exit-code', '0', '--include-dev-deps'];
  for (const d of SKIP_DIRS.filter((d) => d !== 'vendor')) args.push('--skip-dirs', `**/${d}`);
  args.push(root);
  let r = run(tool.path, args, { cwd: root });
  // Maven Central corta a quien pregunta mucho seguido (HTTP 429). Sin red se pierden algunas
  // dependencias transitivas de Java, pero se escanea todo lo demás en vez de nada.
  if (/429|Too Many Requests/i.test(r.stderr) && !readJSON(report)) {
    log('Maven Central ha frenado a Trivy (429): repito sin consultar internet; en Java pueden faltar dependencias transitivas');
    r = run(tool.path, [...args.slice(0, -1), '--offline-scan', root], { cwd: root });
  }
  const data = readJSON(report);
  if (!data) { log(`Trivy no dio resultados: ${(r.stderr || r.error?.message || '').slice(-400)}`); return []; }
  const out = [];
  for (const res of data.Results || []) {
    const file = relTo(root, path.join(root, res.Target || ''));
    // dependencias: un hallazgo por librería, con todos sus CVE dentro
    const byPkg = new Map();
    for (const v of res.Vulnerabilities || []) {
      const k = `${v.PkgName}@${v.InstalledVersion}`;
      if (!byPkg.has(k)) byPkg.set(k, { pkg: v.PkgName, version: v.InstalledVersion, fixed: new Set(), cves: [] });
      const e = byPkg.get(k);
      e.cves.push({ id: v.VulnerabilityID, sev: normSeverity(v.Severity), title: v.Title || '' });
      if (v.FixedVersion) e.fixed.add(v.FixedVersion);
    }
    for (const e of byPkg.values()) {
      const sev = e.cves.some((c) => c.sev === 'high') ? 'high' : e.cves.some((c) => c.sev === 'medium') ? 'medium' : 'low';
      const fixed = [...e.fixed].join(', ');
      out.push({
        tool: 'trivy', cat: 'dependencias', rule: e.cves.map((c) => c.id).slice(0, 5).join(', '),
        severity: sev, file, line: 1, pkg: e.pkg, version: e.version, cves: e.cves,
        title: `La librería ${e.pkg} ${e.version} tiene ${e.cves.length === 1 ? 'un fallo conocido' : `${e.cves.length} fallos conocidos`}`,
        detail: `${e.cves.slice(0, 4).map((c) => `${c.id}${c.title ? `: ${c.title}` : ''}`).join(' · ')}${e.cves.length > 4 ? ` · y ${e.cves.length - 4} más` : ''}. ${fixed ? `Se arregla subiendo a ${fixed}.` : 'Todavía no hay versión arreglada.'}`,
        fix: `Arreglo de seguridad: ${e.pkg} ${e.version} (declarada en ${file}) tiene ${e.cves.map((c) => c.id).join(', ')}. ${fixed ? `Súbela a ${fixed}` : 'No hay versión arreglada: busca una alternativa o mitígalo'}, actualiza el fichero de bloqueo, pasa las pruebas y dime si el cambio rompe algo.`,
      });
    }
    for (const m of res.Misconfigurations || []) {
      if (m.Status && m.Status !== 'FAIL') continue;
      const line = m.CauseMetadata?.StartLine || 1;
      const resource = m.CauseMetadata?.Resource ? ` (${m.CauseMetadata.Resource})` : '';
      out.push({
        tool: 'trivy', cat: 'infra', rule: m.AVDID || m.ID, severity: normSeverity(m.Severity), file, line,
        title: `${m.Title}${resource}`,
        detail: `${m.Message || m.Description || ''}${m.Resolution ? ` Cómo se arregla: ${m.Resolution}` : ''}`,
        fix: `Arreglo de infraestructura en ${file}:${line}${resource}: ${m.Title} (${m.AVDID || m.ID}).\n${m.Description || ''}\nSolución recomendada: ${m.Resolution || 'ver la regla'}.\nHaz el cambio mínimo en este fichero, explícame qué expone hoy y si el cambio puede afectar a algo que ya está desplegado.`,
      });
    }
  }
  return out;
}
