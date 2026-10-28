// Dos mini apps de ensayo, generadas al vuelo para que ningún escáner salte con el propio repo de Lupa:
// un chat con IA (como Lorca) y una gestión de visados con datos personales. Cada fichero
// lleva a propósito los fallos que Lupa debe encontrar.
import fs from 'node:fs';
import path from 'node:path';

const j = (...p) => p.join('');
const FILES = {
  // ---------------------------------------------------------------- chat con IA
  'chat/web/Chat.tsx': `import OpenAI from 'openai';
const client = new OpenAI({ apiKey: process.env.${j('NEXT_PUBLIC_', 'OPENAI_API_KEY')}, dangerouslyAllowBrowser: true });
export function Message({ message }) {
  return <div className="burbuja" dangerouslySetInnerHTML={{ __html: message.content }} />;
}
`,
  'chat/api/chat.ts': `import Anthropic from '@anthropic-ai/sdk';
export async function POST(req) {
  const body = await req.json();
  console.log('chat', req.body);
  const r = await anthropic.messages.create({
    model: 'claude', max_tokens: 1024,
    messages: [{ role: 'system', content: \`Eres Lorca, el asistente. El cliente se llama \${req.body.name}\` }, { role: 'user', content: body.text }],
  });
  return Response.json(r);
}
`,
  'chat/agent/agent.py': `from langchain.agents import load_tools
from transformers import AutoModel
tools = load_tools(["terminal", "llm-math"])
model = AutoModel.from_pretrained("org/modelo", trust_remote_code=True)
respuesta = agent.invoke({"input": pregunta})
`,
  // ---------------------------------------------------------------- visados
  'visados/models/application.js': `module.exports = (sequelize, DataTypes) => sequelize.define('Application', {
  passportNumber: DataTypes.STRING,
  dateOfBirth: DataTypes.DATEONLY,
  nationality: DataTypes.STRING,
  criminalRecord: DataTypes.TEXT,
  cardNumber: DataTypes.STRING,
  cvv: DataTypes.STRING,
  email: DataTypes.STRING,
});
`,
  'visados/migrations/001_applicants.sql': `CREATE TABLE applicants (
  id serial primary key,
  first_name varchar(80),
  passport_number varchar(20),
  dni varchar(12),
  birth_date date,
  photo bytea,
  health_conditions text,
  travel_history jsonb
);
`,
  'visados/db.js': `const url = "${j('postgres', '://visados:S3cr3t', 'P4ssw0rd@db.internal:5432/visados')}?sslmode=disable";
const pool = new Pool({ connectionString: url, ssl: { rejectUnauthorized: false } });
`,
  'visados/storage.js': `const link = await getSignedUrl(s3, new GetObjectCommand({ Bucket: 'docs', Key: key }), { expiresIn: 604800 });
logger.info('subido pasaporte', passport);
`,
  'visados/auth.js': `const hash = crypto.createHash('md5').update(password).digest('hex');
const data = jwt.verify(token, secret, { ignoreExpiration: true });
res.cookie('sid', sid, { httpOnly: false, secure: false });
`,
};

export const EXPECTED_RULES = [
  'lupa.ia.clave-en-el-navegador', 'lupa.ia.sdk-en-el-navegador', 'lupa.ia.respuesta-sin-limpiar', 'lupa.ia.entrada-en-el-prompt-de-sistema',
  'lupa.ia.herramientas-peligrosas', 'lupa.ia.codigo-remoto-del-modelo', 'lupa.web.cookie-insegura', 'lupa.web.hash-debil-de-contrasenas',
  'lupa.web.jwt-sin-verificar', 'lupa.web.tls-desactivado', 'lupa.web.url-firmada-larga', 'lupa.web.logs-con-datos-personales', 'lupa.secretos.cadena-de-conexion',
];

export function writeApps(dir) {
  for (const [f, text] of Object.entries(FILES)) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), text);
  }
  return Object.keys(FILES);
}
