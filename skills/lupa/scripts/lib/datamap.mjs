// El mapa de datos personales: qué modelos, tablas y migraciones guardan datos de personas, de qué
// tipo (pasaporte, DNI, salud, antecedentes…) y si hay pistas de que se cifran. Pensado para apps
// como la de visados, donde lo que más vale es justo eso. También dice qué ficheros llaman a una IA.
import fs from 'node:fs';
import path from 'node:path';

// Cada tipo se compara por trozos enteros del nombre en snake_case («time_penalty» no es «penal»).
export const PII = [
  { tipo: 'pasaporte', re: new RegExp('(^|_)(passport[a-z0-9]*|pasaporte[a-z0-9]*|travel_doc[a-z0-9]*)($|_)', 'i'), peso: 3 },
  { tipo: 'documento de identidad', re: new RegExp('(^|_)(dni|nie|nif|ssn|social_security[a-z0-9]*|national_id[a-z0-9]*|id_card|tax_id|cedula|curp|personal_id|document_number|doc_number)($|_)', 'i'), peso: 3 },
  { tipo: 'datos de pago', re: new RegExp('(^|_)(iban|card_number|cardnumber|credit_card[a-z0-9]*|cvv2?|cvc|pan|account_number|cuenta_bancaria|tarjeta[a-z0-9]*|security_code)($|_)', 'i'), peso: 3 },
  { tipo: 'foto o biometría', re: new RegExp('(^|_)(photo[a-z0-9]*|foto[a-z0-9]*|selfie[a-z0-9]*|biometric[a-z0-9]*|fingerprint_(image|img|template|scan|photo)[a-z0-9]*|huellas?_(dactilar|digital)[a-z0-9]*|dactilar[a-z0-9]*|face_image|face_id|face_scan)($|_)', 'i'), peso: 3, especial: true },
  { tipo: 'salud', re: new RegExp('(^|_)(health[a-z0-9]*|salud|medical[a-z0-9]*|medic[ao]s?|diagnos[a-z0-9]*|disabilit[a-z0-9]*|discapacidad[a-z0-9]*|allerg[a-z0-9]*|alergi[a-z0-9]*)($|_)', 'i'), peso: 3, especial: true },
  { tipo: 'antecedentes penales', re: new RegExp('(^|_)(criminal[a-z0-9]*|arrest[a-z0-9]*|conviction[a-z0-9]*|penal|penales|antecedentes?[a-z0-9]*|deport[a-z0-9]*)($|_)', 'i'), peso: 3, especial: true },
  { tipo: 'origen, religión o ideología', re: new RegExp('(^|_)(ethnic[a-z0-9]*|race|religio[a-z0-9]*|political[a-z0-9]*|union_member[a-z0-9]*|sexual_orient[a-z0-9]*)($|_)', 'i'), peso: 3, especial: true },
  { tipo: 'fecha de nacimiento', re: new RegExp('(^|_)(birth[a-z0-9]*|[a-z0-9]*birth|nacimiento|dob|fecha_nac[a-z0-9]*)($|_)', 'i'), peso: 2 },
  { tipo: 'nacionalidad', re: new RegExp('(^|_)(nationalit[a-z0-9]*|nacionalidad[a-z0-9]*|citizenship[a-z0-9]*|ciudadania|country_of_birth)($|_)', 'i'), peso: 2 },
  { tipo: 'viaje y visado', re: new RegExp('(^|_)(visa|visas|visado[a-z0-9]*|ds_?160|esta|travel_history[a-z0-9]*|entry_date|i_?94|uscis[a-z0-9]*|consulat[a-z0-9]*)($|_)', 'i'), peso: 2 },
  { tipo: 'conversaciones', re: new RegExp('(^|_)(conversation[a-z0-9]*|chat_history|chats?|messages?|transcript[a-z0-9]*|prompts?)($|_)', 'i'), peso: 2 },
  { tipo: 'nombre y apellidos', re: new RegExp('(^|_)(first_name|last_name|full_name|given_name|family_name|surname|apellidos?|nombre)($|_)', 'i'), peso: 1 },
  { tipo: 'dirección', re: new RegExp('(^|_)(address[a-z0-9]*|direccion[a-z0-9]*|street[a-z0-9]*|calle|postal_code|zip_code|zipcode|codigo_postal)($|_)', 'i'), peso: 1 },
  { tipo: 'teléfono', re: new RegExp('(^|_)(phone[a-z0-9]*|telefono[a-z0-9]*|mobile[a-z0-9]*|movil|celular)($|_)', 'i'), peso: 1 },
  { tipo: 'email', re: new RegExp('(^|_)(e_?mail[a-z0-9]*|correo[a-z0-9]*)($|_)', 'i'), peso: 1 },
  { tipo: 'ubicación', re: new RegExp('(^|_)(latitude|longitude|gps|geoloc[a-z0-9]*|ubicacion[a-z0-9]*)($|_)', 'i'), peso: 1 },
];

const MODEL_PATH = /(^|\/)(models?|entities|entity|schemas?|migrations?|prisma|database|db|domain|dtos?)\/|\.(prisma|sql)$|(^|\/)(models?|entity|entities|schema|schemas)\.(py|js|ts|rb|php|java|go)$/i;
const MODEL_MARK = /sequelize\.define|DataTypes\.|@Entity\b|@Column\b|models\.Model\b|new Schema\(|mongoose\.Schema|\$table->|CREATE TABLE|db\.Column\(|Column\(|^\s*model\s+\w+\s*\{|@Table\b|gorm\.Model|BaseModel\)|\b(?:pgTable|mysqlTable|sqliteTable)\(/im;
// nombres de tabla o modelo: una tabla «Message» o «Chat» guarda conversaciones aunque sus campos se llamen «parts»
const TABLE_RES = [
  /\b(?:pgTable|mysqlTable|sqliteTable)\(\s*["'`](\w+)/g, /CREATE TABLE\s+(?:IF NOT EXISTS\s+)?["'`]?(?:\w+["'`]?\.["'`]?)?(\w+)/gi,
  /sequelize\.define\(\s*["'](\w+)/g, /class\s+(\w+)\s*\(\s*(?:models\.Model|Base|db\.Model|SQLModel)/g, /^\s*model\s+(\w+)\s*\{/gm,
  /@Entity\([^)]*\)\s*(?:export\s+)?class\s+(\w+)/g, /Schema::create\(\s*["'](\w+)/g, /mongoose\.model\(\s*["'](\w+)/g,
];
const ENCRYPT_HINT = /encrypt|cipher|EncryptedType|@Encrypted|pgcrypto|pgp_sym|\bkms\b|fernet|libsodium|sodium_|\baes\b|crypt\(|vault/i;
const FIELD_RES = [
  /^\s*["']?([A-Za-z_]\w*)["']?\s*:\s*(?:DataTypes|Sequelize|\{\s*type|String|Number|Date|Boolean|Buffer|Schema\.Types|z\.|Joi\.|Types\.)/gm, // Sequelize, Mongoose, zod
  /@Column[^\n]*\n(?:\s*@\w+[^\n]*\n)*\s*(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_]\w*)\s*[!?]?\s*[:;]/gm, // TypeORM
  /@Column[^\n]*\n(?:\s*@\w+[^\n]*\n)*\s*(?:private|public|protected)\s+[\w<>]+\s+([A-Za-z_]\w*)\s*;/gm, // JPA
  /^\s*([A-Za-z_]\w*)\s*(?::\s*[\w[\]]+\s*)?=\s*(?:models|db|sa|sqlalchemy|mapped_column|Column)\.?\w*\(/gm, // Django, SQLAlchemy
  /\$table->\w+\(\s*['"](\w+)['"]/g, // Laravel
  /^\s*"?([a-z_][a-z0-9_]*)"?\s+(?:varchar|character varying|text|char|int|integer|bigint|smallint|serial|date|timestamp|timestamptz|boolean|bool|bytea|blob|json|jsonb|numeric|decimal|uuid|float|double|real|longtext|mediumtext|tinyint|datetime)\b/gim, // SQL
  /^\s*([a-z_]\w*)\s+(?:String|Int|BigInt|DateTime|Boolean|Bytes|Json|Float|Decimal)\b/gm, // Prisma
  /^\s*([a-z_]\w*)\s*:\s*(?:Optional\[)?(?:str|int|date|datetime|EmailStr|bytes|Decimal)\b/gm, // Pydantic, dataclasses
  /^\s*["']?([A-Za-z_]\w*)["']?\s*:\s*(?:varchar|text|integer|int|bigint|smallint|serial|bigserial|timestamp|date|time|uuid|boolean|json|jsonb|numeric|decimal|real|doublePrecision|char|blob|bytea|customType)\s*\(/gm, // Drizzle
];
// un campo que es solo un identificador de otra cosa (messageId, user_id) no es un dato personal,
// salvo que sea un documento (national_id, passport_id…)
const ID_ONLY = /(^|_)id$/i;

const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const read = (root, f) => { try { const t = fs.readFileSync(path.join(root, f), 'utf8'); return t.length > 2_000_000 ? '' : t; } catch { return ''; } };

export function dataMap(root, files) {
  const out = [];
  for (const f of files) {
    if (/(^|\/)(node_modules|vendor|tests?|__tests__|fixtures?|spec|e2e|docs?)\//i.test(f) || !/\.(js|ts|mjs|cjs|py|php|java|go|rb|kt|prisma|sql)$/.test(f)) continue;
    const text = read(root, f);
    if (!text || (!MODEL_PATH.test(f) && !MODEL_MARK.test(text))) continue;
    if (!MODEL_MARK.test(text) && !/\.(prisma|sql)$/.test(f)) continue;
    const campos = new Map();
    for (const re of FIELD_RES) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(text))) {
        const name = m[1];
        if (campos.has(name) || name.length < 2) continue;
        const kind = PII.find((p) => p.re.test(snake(name)));
        if (kind && ID_ONLY.test(snake(name)) && !['documento de identidad', 'pasaporte'].includes(kind.tipo)) continue;
        if (kind) campos.set(name, { campo: name, tipo: kind.tipo, especial: !!kind.especial, linea: text.slice(0, m.index).split('\n').length });
      }
    }
    for (const re of TABLE_RES) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(text))) {
        const kind = PII.find((p) => p.tipo === 'conversaciones' && p.re.test(snake(m[1].replace(/_v\d+$/i, ''))));
        if (kind && !campos.has(`tabla ${m[1]}`)) campos.set(`tabla ${m[1]}`, { campo: `tabla ${m[1]}`, tipo: kind.tipo, especial: false, linea: text.slice(0, m.index).split('\n').length });
      }
    }
    if (!campos.size) continue;
    const list = [...campos.values()];
    out.push({ fichero: f, campos: list, tipos: [...new Set(list.map((c) => c.tipo))], especial: list.some((c) => c.especial), cifrado: ENCRYPT_HINT.test(text) });
  }
  const resumen = {};
  for (const d of out) for (const c of d.campos) { const r = (resumen[c.tipo] ||= { campos: 0, ficheros: new Set(), especial: c.especial }); r.campos++; r.ficheros.add(d.fichero); }
  for (const r of Object.values(resumen)) r.ficheros = [...r.ficheros];
  return { ficheros: out, resumen };
}

/** Lo grave de verdad: datos de tarjeta guardados, y datos sensibles sin ninguna pista de cifrado. */
export function dataFindings(map) {
  const out = [];
  for (const d of map.ficheros) {
    const at = (c) => c.linea;
    const cvv = d.campos.find((c) => /(^|_)(cvv2?|cvc|security_?code)($|_)/i.test(snake(c.campo)));
    if (cvv) out.push({ tool: 'lupa', cat: 'datos', rule: 'guarda-cvv', severity: 'high', file: d.fichero, line: at(cvv),
      title: `Se guarda el código de seguridad (CVV) de las tarjetas en ${path.posix.basename(d.fichero)}`,
      detail: `El campo «${cvv.campo}» guarda el CVV. Las normas de las tarjetas (PCI-DSS) prohíben guardarlo nunca, ni cifrado: solo se usa en el momento del pago. Si se filtra junto al número, se puede pagar con esas tarjetas.`,
      fix: `Arreglo urgente en ${d.fichero}:${at(cvv)}: elimina el campo ${cvv.campo} del modelo y de la base de datos (migración que lo borre), deja de recibirlo o guardarlo en el código, y dime desde cuándo se guarda para valorar si hay que notificarlo. El cobro debe ir por la pasarela (Stripe, Redsys…), sin que el CVV pase por nuestros sistemas.` });
    const card = d.campos.find((c) => /(^|_)(card_?number|credit_?card|pan)($|_)/i.test(snake(c.campo)));
    if (card && !d.cifrado) out.push({ tool: 'lupa', cat: 'datos', rule: 'tarjeta-sin-cifrar', severity: 'high', file: d.fichero, line: at(card),
      title: `Se guardan números de tarjeta sin rastro de cifrado en ${path.posix.basename(d.fichero)}`,
      detail: `El campo «${card.campo}» guarda el número de tarjeta y en el fichero no hay nada que indique que se cifra. Lo correcto es no guardarlo (token de la pasarela) o, como mínimo, cifrarlo.`,
      fix: `Revisa ${d.fichero}:${at(card)}: sustituye el número de tarjeta por el token de la pasarela de pago. Si hoy hay números guardados, prepara una migración que los elimine y dime cuántos hay, sin mostrarlos.` });
    const sensitive = d.campos.filter((c) => c.especial || ['pasaporte', 'documento de identidad'].includes(c.tipo));
    if (sensitive.length && !d.cifrado) {
      const tipos = [...new Set(sensitive.map((c) => c.tipo))];
      out.push({ tool: 'lupa', cat: 'datos', rule: 'datos-sensibles-sin-cifrar', severity: 'medium', file: d.fichero, line: at(sensitive[0]),
        title: `${tipos.join(', ')}: sin cifrado a nivel de campo en ${path.posix.basename(d.fichero)}`,
        detail: `Se guardan ${sensitive.map((c) => `«${c.campo}»`).join(', ')} (${tipos.join(', ')}) y en el fichero no hay pistas de cifrado. Puede estar cifrada la base de datos entera, pero si alguien saca una copia o una consulta, estos datos salen en claro.${sensitive.some((c) => c.especial) ? ' Salud, antecedentes, biometría u origen son «categorías especiales» del RGPD (art. 9): exigen protección reforzada.' : ''}`,
        fix: `Revisión de datos sensibles en ${d.fichero}: los campos ${sensitive.map((c) => c.campo).join(', ')} guardan ${tipos.join(', ')}. Confirma si hay cifrado (de campo, de columna o de disco) y, si no, propón cifrado a nivel de campo con la clave fuera de la base de datos (KMS), sin romper las búsquedas que se usan hoy.` });
    }
  }
  return out;
}

const AI_IMPORT = /(?:from\s+["'](?:openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[\w-]+|langchain[\w/-]*|@langchain\/[\w-]+|@google\/generative-ai|@google\/genai|cohere-ai|@azure\/openai|ollama|groq-sdk|@mistralai\/mistralai|llamaindex)["']|require\(\s*["'](?:openai|@anthropic-ai\/sdk|langchain[\w/-]*|@langchain\/[\w-]+|ollama|groq-sdk)["']\s*\)|^\s*(?:import|from)\s+(?:openai|anthropic|langchain\w*|llama_index|google\.generativeai|google\.genai|cohere|mistralai|groq|ollama|litellm)\b|\bapi\.openai\.com|\bapi\.anthropic\.com|generativelanguage\.googleapis\.com)/m;

// importar el SDK no basta (el paquete «ai» también da tipos y utilidades): tiene que haber una llamada al modelo
const AI_CALL = /\b(?:streamText|generateText|streamObject|generateObject|embedMany|embed|streamUI)\s*\(|\.(?:chat\.)?completions\.create\(|\.responses\.create\(|\.messages\.(?:create|stream)\(|\.generateContent(?:Stream)?\(|\.(?:invoke|ainvoke|stream|astream|predict)\(|\bChat(?:OpenAI|Anthropic|Ollama|VertexAI|GoogleGenerativeAI|Mistral|Groq)\(|\bollama\.(?:chat|generate)\(|\blitellm\.(?:a?completion)\(|\bpipeline\(\s*["']text-generation/;

/** Ficheros de código que llaman a un modelo de IA. */
export function aiFiles(root, files) {
  return files.filter((f) => {
    if (!/\.(js|jsx|ts|tsx|mjs|cjs|py|php|java|go|rb)$/.test(f) || /(^|\/)(node_modules|vendor|tests?|__tests__)\//.test(f)) return false;
    const text = read(root, f);
    return AI_IMPORT.test(text) && AI_CALL.test(text);
  });
}
