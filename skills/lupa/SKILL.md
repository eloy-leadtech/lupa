---
name: lupa
description: Auditoría visual de seguridad de un proyecto entero (uno o varios repos). Busca secretos (también en el historial de git), fallos de código, librerías con CVE, Terraform, Docker, Kubernetes y Jenkins mal configurados, configuraciones que exponen datos, datos personales subidos al repo y todos los endpoints, y Claude revisa cada endpoint para decir si debería ser público y qué datos suelta. Lo pinta sobre un mapa de floorplan como mapa de calor. Úsalo cuando pidan revisar la seguridad de un proyecto o servidor, buscar puntos débiles, endpoints públicos que no deberían serlo, datos expuestos, superficie de ataque, o digan «lupa» o «auditoría».
argument-hint: "[ruta-del-proyecto]"
allowed-tools: Bash(node ${CLAUDE_SKILL_DIR}/scripts/*), Bash(node ${CLAUDE_SKILL_DIR}/../floorplan/scripts/*)
---

# Lupa

Lupa junta cuatro fuentes y las pinta en el mapa del proyecto:

1. **Escáneres estándar:** gitleaks (secretos, también en todo el historial de git), Semgrep (fallos de código, más las reglas propias de Lupa para Jenkins, Docker y configuraciones expuestas) y Trivy (librerías con CVE y servidores mal configurados: Terraform, Dockerfile, Kubernetes, Helm…).
2. **Chequeos propios:**
   - **Ficheros delicados subidos al repo:** tfstate, claves privadas, copias de BD…
   - **Datos personales sueltos en ficheros de datos:** DNI/NIE, IBAN y tarjetas validados, emails, teléfonos.
   - **El mapa de datos personales:** qué modelos y tablas guardan pasaportes, DNI, salud, antecedentes, fotos, datos de pago…, y si se cifran.
   - **Endpoints que floorplan no ve:** Laravel, Symfony, Django y PHP suelto.
   - **Reglas para apps con IA** (OWASP Top 10 para LLM) **y para web y base de datos:** cookies, hash de contraseñas, JWT, TLS, enlaces firmados, logs con datos personales.
   - **La foto de la tecnología:** lenguajes, runtimes, frameworks, bases de datos, imágenes, Terraform, CI e IA, con versión y ciclo de vida (endoflife.date).
   - **Cada CVE cruzado con KEV** (CISA: se está explotando ya) **y EPSS** (probabilidad de ataque).
3. **Tu revisión, siempre:** cada endpoint (¿es público? ¿debería? ¿qué datos suelta?) y la criba de falsos positivos. Es la parte que ninguna regla hace bien, y no se salta.
4. **El mapa de floorplan:** todo acaba en su Health, más un mapa de calor sobre las tarjetas y un botón «Lupa» con la superficie de ataque.

Proyecto: el argumento si lo hay; si no, la carpeta actual. Puede ser un repo o una carpeta con varios.
Arguments: $ARGUMENTS

## 0. Herramientas

`node ${CLAUDE_SKILL_DIR}/scripts/doctor.mjs`

Si falta alguna, di cuál y el comando de instalación que imprime, y **pregunta antes de instalar nada**. Si el usuario no quiere instalarla, sigue sin ella: esa parte se queda sin mirar, y dilo en el informe.

## 1. El mapa

Si `<raíz>/floorplan/graph.json` no existe, haz el mapa siguiendo `${CLAUDE_SKILL_DIR}/../floorplan/SKILL.md`, **solo los pasos 1 a 5** (scan, leer el esquema, explorar, `architecture.json` y build). Los scripts de floorplan están en `${CLAUDE_SKILL_DIR}/../floorplan/scripts/`. Para un mapa de Lupa:

- Pon `"include": ["code", "config"]`, para que se vean Dockerfile, docker-compose y los ficheros de configuración.
- Crea un nodo `kind: "infra"` («Servidores y despliegue») con Terraform, Docker, Kubernetes, Helm y CI, y otro `kind: "test"` para las pruebas.
- **No hagas el paso 6 (describir cada archivo)** salvo que lo pidan: cuesta unos 1.400 tokens por archivo y Lupa no lo necesita. Las tarjetas salen con su ruta y el resumen del módulo.

Si el mapa ya existe, relanza `build.mjs` para que recoja los cambios del código.

## 2. Escaneo

`node ${CLAUDE_SKILL_DIR}/scripts/scan.mjs <raíz>`

Tarda de segundos a unos minutos; Semgrep es lo lento. Escribe `floorplan/lupa/hallazgos.json`, `superficie.json` y los lotes de revisión en `floorplan/lupa/revision/`. Lo ya revisado en pasadas anteriores se guarda en `lote-00.json` y no se vuelve a pedir.

`--solo gitleaks,semgrep,trivy,propios` lanza solo esas partes y conserva lo demás de la pasada anterior.

## 3. Revisión (siempre)

Cada `lote-NN.md` trae lo que hay que mirar, con el código delante; contesta en su `lote-NN.json`, sin cambiar las claves ni el orden. **Con más de 3 lotes, repártelos entre subagentes en paralelo** (3 a 5 lotes cada uno). Dales la raíz, sus números de lote y la ruta de este SKILL para que lean esta sección, y diles que solo editen sus `lote-NN.json`.

**Endpoints.** Lee el fragmento y abre lo que haga falta para saber si de verdad pide login: el router donde se monta, el middleware global en `server`/`app`, los decoradores y las dependencias. Rellena:

- `publico`: `true` si cualquiera puede llamarlo sin login, `false` si lo exige, `null` si no se puede saber.
- `deberiaSerPublico`: `true` o `false` según lo que hace; `null` si depende del negocio.
- `datos`: qué datos devuelve o cambia, en palabras llanas («emails de clientes», «contraseñas cifradas», «pedidos de otros usuarios», «tarjetas»…).
- `severidad`, una de:
  - `alta`: cualquiera lee o cambia datos de otros, admin sin login, ejecución de comandos o ficheros, IDOR evidente.
  - `media`: público que suelta datos internos, o que permite abusos claros (sin límite en el login, enumerar usuarios).
  - `baja`: detalles menores.
  - `ninguna`: público a propósito y sin riesgo (login, health, catálogo) o bien protegido.
- `titulo`: el problema en una frase corta, de unas 12 palabras («El cupo de mensajes se salta borrando el historial»). Es lo que sale en el informe y en el mapa. Vacío si es `ninguna`.
- `motivo`: una o dos frases en castellano llano. Di qué pasa y por qué importa, no repitas el código.
- `arreglo`: si hay riesgo, una instrucción concreta para arreglarlo, lista para pegar en Claude Code (qué fichero, qué cambiar). Vacío si es `ninguna`.

Mira las **pistas** de cada endpoint y aplica la lista que toque. Cualquier punto que falle sube la severidad:

- **Lleva un identificador en la ruta** (`/solicitudes/:id`, `/chats/{id}`, `/documentos/<pk>`): ¿comprueba que el recurso es del usuario que pide (o de su organización), o vale cualquier id? Es el fallo número uno en apps con expedientes de personas. Que cualquiera con sesión vea el de otro es `alta`.
- **Toca datos personales** (pasaporte, DNI, salud, antecedentes, fotos, datos de pago): ¿los devuelve enteros cuando no hace falta?, ¿a quién?, ¿quedan en logs o en respuestas de error? Apunta en `datos` qué tipos suelta.
- **Sube o sirve documentos:**
  - ¿valida tipo y tamaño?, ¿hay path traversal en el nombre?
  - ¿se guardan en un bucket público?
  - ¿los enlaces firmados caducan en minutos?
  - ¿se puede pedir el documento de otro?
- **Login, registro y recuperación:**
  - ¿hay límite de intentos?
  - ¿se puede averiguar qué emails existen?
  - ¿el token de recuperación es largo, aleatorio, de un solo uso y caduca?
  - ¿el cambio de contraseña pide la actual?
- **Llama a un modelo de IA** (OWASP Top 10 para LLM):
  - **inyección de prompt:** el texto del usuario o de documentos que lee el modelo, ¿puede cambiar sus instrucciones o activar herramientas?
  - **salida del modelo:** ¿se pinta como HTML, se ejecuta o va a una consulta SQL?
  - **herramientas:** ¿qué puede hacer el modelo solo? ¿Hay alguna con permisos de más?
  - **datos entre usuarios:** ¿se puede leer la conversación o los documentos de otro (RAG sin filtro por usuario)?
  - **abuso y coste:** ¿hay login, límite de peticiones y `max_tokens`?
  - **filtraciones:** ¿el prompt de sistema lleva secretos? ¿Las conversaciones se guardan o registran con datos personales sin necesidad?

**Hallazgos.** `veredicto`: `real`, `falso-positivo` o `dudoso`. Solo es falso positivo si el código lo demuestra (datos de prueba, una constante que no es un secreto, una entrada ya validada); ante la duda, `dudoso`. `severidad` (alta/media/baja) solo si hay que recalibrarla. `motivo` breve.

**Extra.** Si al revisar ves algo grave que ninguna herramienta pilló, añádelo a `extra`: `{ "titulo", "severidad", "categoria" (endpoints · secretos · exposicion · datos · codigo · infra · ia), "fichero", "linea", "detalle", "arreglo" }`.

**`huella`:** no la toques. Si el código del endpoint cambia, Lupa lo vuelve a pedir.

**Nunca escribas el valor de un secreto** en los JSON ni en tus respuestas: como mucho el tipo y dónde está.

## 4. Pintar

`node ${CLAUDE_SKILL_DIR}/scripts/merge.mjs <raíz>`

Mete todo en el mapa y escribe `floorplan/lupa/informe.md`, que sirve para tickets. Después de **cada** build de floorplan hay que volver a lanzarlo, porque el build reescribe el mapa sin Lupa.

## 5. Enseñar e informar

`node ${CLAUDE_SKILL_DIR}/../floorplan/scripts/open.mjs <raíz>` (con `--no-open` si tienes navegador integrado, y abre allí la URL).

Luego informa en 4 a 6 líneas, en castellano: lo grave primero, los endpoints abiertos que no deberían, qué se ha quedado sin mirar (herramientas que faltaban, lotes sin revisar) y dónde está `informe.md`. Sin secretos.

## Qué sale del ordenador

- gitleaks y los chequeos propios: nada.
- Semgrep: descarga sus paquetes de reglas de semgrep.dev (con `--metrics=off`; no sube código).
- Trivy: descarga su base de datos de CVE y puede consultar Maven Central por las dependencias de Java. Si Maven corta con un 429, Lupa repite sin red.
- npm, solo en proyectos sin fichero de bloqueo: resuelve las versiones en una carpeta aparte (`--package-lock-only --ignore-scripts`). Descarga metadatos del registro, no instala ni ejecuta nada.
- endoflife.date, CISA KEV y FIRST EPSS: se descargan sus catálogos públicos (caché de un día en `~/.cache/lupa`). Solo se envían números de CVE.
- La revisión: el código que lees va al proveedor de IA de la cuenta con la que trabajas. **Usa la cuenta de la empresa, no una personal.**

## En Jenkins o sin IA

`scan.mjs` y `merge.mjs` funcionan sin Claude: el mapa marca los endpoints como «sin revisar». Para tenerlo todo en CI: `claude -p "/lupa ."` con la cuenta de la empresa.
