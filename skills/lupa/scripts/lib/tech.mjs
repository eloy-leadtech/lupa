// La foto de la tecnología: qué lenguajes, runtimes, frameworks, bases de datos, imágenes Docker,
// infraestructura, CI e IA usa el proyecto, en qué versión, y si esa versión sigue con soporte.
import fs from 'node:fs';
import path from 'node:path';
import { eolStatus, purlKey, cleanVersion } from './intel.mjs';

const read = (root, f) => { try { return fs.readFileSync(path.join(root, f), 'utf8'); } catch { return ''; } };
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;

// imágenes Docker y runtimes que endoflife.date no reconoce por purl, por su nombre de producto
const IMAGE_PRODUCT = {
  node: 'nodejs', python: 'python', php: 'php', postgres: 'postgresql', mysql: 'mysql', mariadb: 'mariadb', mongo: 'mongodb',
  redis: 'redis', nginx: 'nginx', httpd: 'apache-http-server', alpine: 'alpine-linux', ubuntu: 'ubuntu', debian: 'debian',
  openjdk: 'eclipse-temurin', 'eclipse-temurin': 'eclipse-temurin', amazoncorretto: 'amazon-corretto', golang: 'go', ruby: 'ruby',
  elasticsearch: 'elasticsearch', rabbitmq: 'rabbitmq', tomcat: 'tomcat', 'mcr.microsoft.com/dotnet/aspnet': 'dotnet', jenkins: 'jenkins',
};
const DB_IMAGES = /^(postgres|mysql|mariadb|mongo|redis|elasticsearch|opensearch|cassandra|couchdb|memcached|mssql|.*sql-server|neo4j|clickhouse)/;
const AI_PKG = /^(openai|@anthropic-ai\/sdk|anthropic|langchain.*|@langchain\/.*|llama[-_]?index.*|llamaindex|@google\/generative-ai|google-generativeai|google-genai|@google\/genai|cohere.*|@azure\/openai|ollama|transformers|ai|@ai-sdk\/.*|mistralai|@mistralai\/.*|groq-sdk|groq|replicate|huggingface_hub|@huggingface\/inference|chromadb|pinecone.*|@pinecone-database\/.*|weaviate.*|qdrant.*|tiktoken)$/i;
const DB_DRIVERS = {
  PostgreSQL: /^(pg|postgres|pg-promise|psycopg2(-binary)?|psycopg|asyncpg|org\.postgresql\/postgresql|github\.com\/lib\/pq|github\.com\/jackc\/pgx.*)$/i,
  MySQL: /^(mysql2?|pymysql|mysqlclient|mysql-connector-python|com\.mysql\/mysql-connector-j|mysql\/mysql-connector-java)$/i,
  MongoDB: /^(mongoose|mongodb|pymongo|motor|org\.mongodb\/.*)$/i,
  Redis: /^(redis|ioredis|predis\/predis|jedis|redis-py)$/i,
  SQLite: /^(sqlite3|better-sqlite3|sqlite)$/i,
  'SQL Server': /^(mssql|tedious|pyodbc|com\.microsoft\.sqlserver\/mssql-jdbc)$/i,
};

function parseImage(ref) {
  let s = String(ref).trim().replace(/^["']|["']$/g, '').split('@')[0];
  if (!s || /^\$|\$\{/.test(s) || s === 'scratch') return null;
  const parts = s.split('/');
  if (parts.length > 1 && /[.:]/.test(parts[0]) && parts[0] !== 'mcr.microsoft.com') parts.shift(); // quita el registro
  const last = parts.pop();
  const [name, tag = ''] = last.split(':');
  const full = [...parts, name].join('/');
  return { name: full, tag, display: `${full}${tag ? ':' + tag : ''}` };
}

/** Busca la tecnología en endoflife.date: primero por purl, luego por nombre conocido. */
function lookup(eol, { purl, image, product }) {
  if (!eol) return null;
  if (purl) { const p = eol.byPurl.get(purlKey(purl)); if (p) return p; }
  if (image) {
    const ns = image.includes('/') ? image : `library/${image}`;
    const p = eol.byPurl.get(`docker/${ns}`.toLowerCase()) || eol.byName.get(IMAGE_PRODUCT[image] || IMAGE_PRODUCT[image.split('/').pop()]);
    if (p) return p;
  }
  if (product) return eol.byName.get(product) || null;
  return null;
}

/**
 * @param packages paquetes de Trivy: { target, type, name, version, purl, direct }
 * @returns { lenguajes, componentes, ecosistemas, ia, basesDeDatos, ci, nube }
 */
export function inventory({ root, files, scan, packages, eol }) {
  const comps = [];
  const add = (c) => {
    const st = c.product ? eolStatus(c.product, c.version) : null;
    comps.push({ tipo: c.tipo, nombre: c.nombre, version: c.version || '', fichero: c.fichero, linea: c.linea || 1, eol: st, nota: c.nota || '' });
  };

  // ---------------------------------------------------------------- imágenes Docker (Dockerfile, compose, k8s, Jenkins)
  for (const f of files) {
    const base = path.posix.basename(f).toLowerCase();
    const isDocker = /^dockerfile/.test(base) || base.endsWith('.dockerfile');
    const isYaml = /\.ya?ml$/.test(base);
    const isJenkins = /^jenkinsfile/.test(base);
    if (!isDocker && !isYaml && !isJenkins) continue;
    const text = read(root, f);
    const refs = [];
    if (isDocker) {
      const stages = new Set();
      for (const m of text.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/gim)) {
        if (!stages.has(m[1].toLowerCase())) refs.push([m[1], m.index]);
        if (m[2]) stages.add(m[2].toLowerCase());
      }
    } else if (isYaml && /^\s*image:\s*\S/m.test(text) && /(services:|kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|CronJob|Job)|containers:)/.test(text)) {
      for (const m of text.matchAll(/^\s*-?\s*image:\s*["']?([^\s"'#]+)/gm)) refs.push([m[1], m.index]);
    } else if (isJenkins) {
      for (const m of text.matchAll(/(?:docker\.image\(\s*|image\s+)['"]([^'"]+)['"]/g)) refs.push([m[1], m.index]);
    }
    for (const [ref, idx] of refs) {
      const img = parseImage(ref); if (!img) continue;
      const product = lookup(eol, { image: img.name });
      const isDb = DB_IMAGES.test(img.name.split('/').pop());
      add({ tipo: isDb ? 'base-de-datos' : 'imagen', nombre: img.display, version: img.tag, fichero: f, linea: lineOf(text, idx), product,
        nota: !img.tag || img.tag === 'latest' ? 'sin versión fija: cada despliegue puede traer otra distinta' : '' });
    }
  }

  // ---------------------------------------------------------------- runtimes declarados
  // «>=16», «*» o «^12 || >=16» no dicen qué versión corre: se apunta, pero no se juzga su soporte.
  // De «^12 || ^14» se toma la más alta; «^20» o «~3.11» sí fijan la rama.
  const specVersion = (spec) => {
    const alts = String(spec).split('||').map((a) => a.trim()).filter(Boolean);
    if (alts.some((a) => /^(>|\*|x|latest)/i.test(a) || /\s-\s/.test(a))) return { open: true, version: cleanVersion(alts[alts.length - 1]) };
    const vs = alts.map(cleanVersion).filter(Boolean).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    return { open: false, version: vs[vs.length - 1] || null };
  };
  const runtime = (nombre, productName, spec, f, text, idx, { noEol = false, nota = '' } = {}) => {
    const sv = specVersion(spec);
    add({ tipo: 'runtime', nombre, version: sv.version || String(spec), fichero: f, linea: idx != null && idx >= 0 ? lineOf(text, idx) : 1,
      product: sv.open || noEol ? null : eol?.byName.get(productName) || null,
      nota: nota || (sv.open ? `rango abierto («${String(spec).trim()}»): no dice qué versión se usa` : /[\^~]/.test(String(spec)) ? 'rama declarada' : '') });
  };
  for (const f of files) {
    const base = path.posix.basename(f);
    if (/(^|\/)(node_modules|vendor|tests?|fixtures?)\//.test(f)) continue;
    if (base === 'package.json') { const t = read(root, f); try { const j = JSON.parse(t); if (j.engines?.node) runtime('Node.js', 'nodejs', j.engines.node, f, t, t.indexOf('"node"')); } catch {} }
    else if (base === '.nvmrc' || base === '.node-version') { const t = read(root, f).trim(); if (cleanVersion(t)) runtime('Node.js', 'nodejs', t, f, t, 0); }
    else if (base === 'composer.json') { const t = read(root, f); try { const j = JSON.parse(t); if (j.require?.php) runtime('PHP', 'php', j.require.php, f, t, t.indexOf('"php"')); } catch {} }
    else if (base === 'runtime.txt' || base === '.python-version') { const t = read(root, f).trim(); if (cleanVersion(t)) runtime('Python', 'python', t, f, t, 0); }
    else if (base === 'pyproject.toml') { const t = read(root, f); const m = /(?:requires-python|^python)\s*=\s*["']([^"']+)/m.exec(t); if (m) runtime('Python', 'python', m[1], f, t, m.index); }
    else if (base === 'go.mod') { const t = read(root, f); const m = /^go\s+(\d+\.\d+)/m.exec(t); if (m) runtime('Go', 'go', m[1], f, t, m.index); }
    // el nivel de compilación de Java no es el JDK que corre: se apunta sin juzgar su soporte
    else if (base === 'pom.xml') { const t = read(root, f); const m = /<(?:java\.version|maven\.compiler\.(?:source|release))>([^<]+)</.exec(t); if (m) runtime('Java (nivel de compilación)', 'eclipse-temurin', m[1].replace(/^1\./, ''), f, t, m.index, { noEol: true, nota: 'nivel de compilación: el JDK instalado puede ser otro' }); }
    else if (/^build\.gradle(\.kts)?$/.test(base)) { const t = read(root, f); const m = /(?:sourceCompatibility\s*=\s*['"]?(?:JavaVersion\.VERSION_)?|languageVersion\.set\(JavaLanguageVersion\.of\(|languageVersion\s*=\s*JavaLanguageVersion\.of\()(\d+(?:[._]\d+)?)/.exec(t); if (m) runtime('Java (nivel de compilación)', 'eclipse-temurin', m[1].replace('_', '.').replace(/^1\./, ''), f, t, m.index, { noEol: true, nota: 'nivel de compilación: el JDK instalado puede ser otro' }); }
    else if (base.endsWith('.tf')) {
      const t = read(root, f);
      const m = /required_version\s*=\s*"([^"]+)"/.exec(t); if (m) runtime('Terraform', 'terraform', m[1], f, t, m.index);
      for (const p of t.matchAll(/(\w+)\s*=\s*\{\s*source\s*=\s*"([^"]+)"\s*(?:version\s*=\s*"([^"]+)")?/g)) add({ tipo: 'infra', nombre: `Proveedor ${p[2]}`, version: p[3] || '', fichero: f, linea: lineOf(t, p.index), nota: p[3] ? '' : 'proveedor sin versión fija' });
    }
  }

  // ---------------------------------------------------------------- librerías y frameworks (de Trivy)
  const ecos = {};
  const seen = new Set();
  const ai = [], dbs = new Map();
  for (const p of packages) {
    const e = (ecos[p.type] ||= { directas: 0, total: 0, ficheros: new Set() });
    e.total++; if (p.direct) e.directas++; e.ficheros.add(p.target);
    const product = lookup(eol, { purl: p.purl });
    const short = p.name.replace(/^.*?[:/](?=[^/:]+$)/, '');
    if (AI_PKG.test(p.name) || AI_PKG.test(short)) ai.push({ nombre: p.name, version: p.version, fichero: p.target });
    for (const [db, re] of Object.entries(DB_DRIVERS)) if (re.test(p.name)) { if (!dbs.has(db)) dbs.set(db, new Set()); dbs.get(db).add(p.target); }
    if (!product) continue;
    const k = `${product.name}|${p.version}|${p.target}`;
    if (seen.has(k)) continue; seen.add(k);
    add({ tipo: product.category === 'framework' ? 'framework' : 'libreria', nombre: p.name, version: p.version, fichero: p.target, linea: p.line || 1, product,
      nota: [p.dev ? 'dependencia de desarrollo' : '', p.resolved ? 'versión resuelta hoy: el repo no fija versiones' : ''].filter(Boolean).join(' · ') });
    comps[comps.length - 1].dev = !!p.dev;
  }
  for (const e of Object.values(ecos)) e.ficheros = [...e.ficheros];

  // ---------------------------------------------------------------- CI y nube
  const ci = files.filter((f) => /(^|\/)(jenkinsfile[^/]*|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.circleci\/config\.ya?ml)$/i.test(f) || /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(f))
    .map((f) => ({ sistema: /jenkins/i.test(f) ? 'Jenkins' : /gitlab/.test(f) ? 'GitLab CI' : /azure/.test(f) ? 'Azure Pipelines' : /bitbucket/.test(f) ? 'Bitbucket' : /circleci/.test(f) ? 'CircleCI' : 'GitHub Actions', fichero: f }));
  const cloud = {};
  for (const f of files.filter((x) => x.endsWith('.tf'))) {
    const t = read(root, f);
    for (const m of t.matchAll(/resource\s+"(aws|azurerm|google|alicloud|oci|digitalocean|kubernetes)_([\w]+)"/g)) { const c = (cloud[m[1]] ||= { recursos: 0, tipos: {} }); c.recursos++; c.tipos[m[2]] = (c.tipos[m[2]] || 0) + 1; }
  }

  const langs = {};
  for (const f of scan.files || []) if (f.category === 'code' && f.lang) { const l = (langs[f.lang] ||= { ficheros: 0, lineas: 0 }); l.ficheros++; l.lineas += f.loc || 0; }
  return {
    lenguajes: Object.entries(langs).map(([lang, v]) => ({ lenguaje: lang, ...v })).sort((a, b) => b.lineas - a.lineas),
    componentes: comps,
    ecosistemas: ecos,
    ia: ai,
    basesDeDatos: [...dbs.entries()].map(([nombre, fs]) => ({ nombre, ficheros: [...fs] })),
    ci, nube: cloud,
  };
}

// sin soporte pesa según qué es: el runtime, el framework o la base de datos de la app, más que una librería
const EOL_SEV = { runtime: 'high', framework: 'high', 'base-de-datos': 'high', imagen: 'medium', libreria: 'medium', infra: 'medium' };
const DOWN = { high: 'medium', medium: 'low', low: 'low' };
const LAB_PATH = /(^|\/)(tests?|__tests__|spec|e2e|fixtures?|examples?|samples?|demos?|labs?|playground|sandbox|docs?)(\/|$)|_lab(\/|$)/i;

/** Hallazgos «tecnología»: lo que está sin soporte, a punto de perderlo, muy atrás o sin versión fija. */
export function techFindings(inv) {
  const out = [];
  for (const c of inv.componentes) {
    const s = c.eol;
    const where = `${c.fichero}${c.linea > 1 ? ':' + c.linea : ''}`;
    if (s?.estado === 'sin-soporte') {
      // una herramienta de desarrollo no llega a producción; un laboratorio o un ejemplo, tampoco
      let sev = c.dev ? 'low' : EOL_SEV[c.tipo] || 'medium';
      if (LAB_PATH.test(c.fichero)) sev = DOWN[sev];
      out.push({ tool: 'lupa', cat: 'tecnologia', rule: 'sin-soporte', severity: sev, file: c.fichero, line: c.linea, componente: c.nombre,
        title: `${s.etiqueta || c.nombre} ${c.version} ya no tiene soporte${s.finSoporte ? ` (desde ${s.finSoporte})` : ''}`,
        detail: `${c.nombre} ${c.version} (${c.tipo}) ya no recibe parches de seguridad: cualquier fallo que se descubra a partir de ahora se queda abierto para siempre. La última versión es ${s.ultima || '?'}.${c.nota ? ` (${c.nota}.)` : ''}`,
        fix: `Actualización de ${c.nombre} ${c.version} (declarado en ${where}): está sin soporte desde ${s.finSoporte || 'hace tiempo'}. Propón el salto a una versión con soporte (la última es ${s.ultima || '?'}), lista los cambios incompatibles que nos afectan en este repo y qué pruebas hay que pasar.` });
    } else if (s?.estado === 'caduca-pronto') {
      out.push({ tool: 'lupa', cat: 'tecnologia', rule: 'caduca-pronto', severity: 'low', file: c.fichero, line: c.linea, componente: c.nombre,
        title: `${s.etiqueta || c.nombre} ${c.version} se queda sin soporte el ${s.finSoporte}`,
        detail: `Quedan menos de seis meses de parches de seguridad para ${c.nombre} ${c.version}. Conviene planificar la subida ya.`,
        fix: `Planifica la actualización de ${c.nombre} ${c.version} (${where}) antes del ${s.finSoporte}: versión destino, cambios incompatibles y esfuerzo estimado.` });
    } else if (s?.estado === 'desactualizado' || s?.estado === 'sin-mantenimiento') {
      out.push({ tool: 'lupa', cat: 'tecnologia', rule: s.estado, severity: 'low', file: c.fichero, line: c.linea, componente: c.nombre,
        title: `${s.etiqueta || c.nombre} ${c.version} va muy por detrás (la última es ${s.ultima})`,
        detail: `${c.nombre} ${c.version} aún recibe parches${s.finSoporte ? ` hasta el ${s.finSoporte}` : ''}, pero está a dos o más versiones grandes de la actual: cuanto más se espere, más cuesta el salto.`,
        fix: `Evalúa subir ${c.nombre} de ${c.version} a ${s.ultima} (${where}): cambios incompatibles, esfuerzo y riesgo.` });
    }
    if (c.nota.startsWith('sin versión fija') || c.nota === 'proveedor sin versión fija') {
      out.push({ tool: 'lupa', cat: 'tecnologia', rule: 'sin-version-fija', severity: 'low', file: c.fichero, line: c.linea, componente: c.nombre,
        title: `${c.nombre} no tiene versión fija`,
        detail: `Sin una versión concreta, cada build puede traer una distinta (incluida una rota o comprometida) y no hay forma de saber qué está desplegado.`,
        fix: `Fija una versión concreta de ${c.nombre} en ${where} (mejor con digest en el caso de imágenes Docker).` });
    }
  }
  return out;
}
