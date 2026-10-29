---
name: lupa
description: Auditoría de seguridad de un proyecto entero, código e infraestructura, que el equipo genera y manda como un único informe. En el código busca secretos (también en el historial de git), fallos, librerías con CVE, Terraform, Docker, Kubernetes y Jenkins mal configurados, datos personales y todos los endpoints, que Claude revisa uno a uno. En la infraestructura revisa por dentro cada servidor del proyecto (parches, SSH, contenedores, puertos, secretos en disco, agentes), cómo se comunican entre ellos y qué se ve desde internet. Lo pinta sobre un mapa de floorplan y deja un informe HTML para mandar. Úsalo cuando pidan revisar la seguridad de un proyecto, de sus servidores o VPS, buscar puntos débiles, superficie de ataque, datos expuestos, o digan «lupa» o «auditoría».
argument-hint: "[ruta-del-proyecto]"
allowed-tools: Bash(node ${CLAUDE_SKILL_DIR}/scripts/*), Bash(node ${CLAUDE_SKILL_DIR}/../floorplan/scripts/*)
---

# Lupa

Lupa junta cinco fuentes, las pinta en el mapa del proyecto y deja un informe para mandar:

1. **Escáneres estándar:** gitleaks (secretos, también en todo el historial de git), Semgrep (fallos de código, más las reglas propias de Lupa para Jenkins, Docker y configuraciones expuestas) y Trivy (librerías con CVE y servidores mal configurados: Terraform, Dockerfile, Kubernetes, Helm…).
2. **Chequeos propios:**
   - **Ficheros delicados subidos al repo:** tfstate, claves privadas, copias de BD…
   - **Datos personales sueltos en ficheros de datos:** DNI/NIE, IBAN y tarjetas validados, emails, teléfonos.
   - **El mapa de datos personales:** qué modelos y tablas guardan pasaportes, DNI, salud, antecedentes, fotos, datos de pago…, y si se cifran.
   - **Endpoints que floorplan no ve:** Laravel, Symfony, Django y PHP suelto.
   - **Reglas para apps con IA** (OWASP Top 10 para LLM) **y para web y base de datos:** cookies, hash de contraseñas, JWT, TLS, enlaces firmados, logs con datos personales.
   - **La foto de la tecnología:** lenguajes, runtimes, frameworks, bases de datos, imágenes, Terraform, CI e IA, con versión y ciclo de vida (endoflife.date).
   - **Cada CVE cruzado con KEV** (CISA: se está explotando ya) **y EPSS** (probabilidad de ataque).
3. **La infraestructura viva:** cada servidor del proyecto por dentro, cómo se hablan entre ellos y qué se ve desde internet.
4. **Tu revisión, siempre:** cada endpoint (¿es público? ¿debería? ¿qué datos suelta?) y la criba de falsos positivos. Es la parte que ninguna regla hace bien, y no se salta.
5. **El mapa de floorplan y el informe:** todo acaba en su Health, con un mapa de calor y un botón «Lupa», y en un único HTML que el equipo manda a quien evalúa.

Proyecto: el argumento si lo hay; si no, la carpeta actual. Puede ser un repo o una carpeta con varios.
Arguments: $ARGUMENTS

## 0. Equipo y herramientas

Pregunta, si no lo sabes ya, **de qué equipo es el proyecto** (por ejemplo «Visas» o «Globeful»): sale en el informe y en el nombre del fichero que se manda.

`node ${CLAUDE_SKILL_DIR}/scripts/doctor.mjs`

Si falta algún escáner, ofrece instalarlo con `node ${CLAUDE_SKILL_DIR}/scripts/doctor.mjs --instalar`, que descarga la **versión fijada** de cada uno, comprobada por SHA-256, en `~/.cache/lupa/bin`, sin tocar el sistema ni pedir administrador. **Pregunta antes de instalar nada.** Si el usuario no quiere, sigue sin él: esa parte se queda sin mirar y el informe lo dice.

## 1. El mapa

Si `<raíz>/floorplan/graph.json` no existe, haz el mapa siguiendo `${CLAUDE_SKILL_DIR}/../floorplan/SKILL.md`, **solo los pasos 1 a 5** (scan, leer el esquema, explorar, `architecture.json` y build). Los scripts de floorplan están en `${CLAUDE_SKILL_DIR}/../floorplan/scripts/`. Para un mapa de Lupa:

- Pon `"include": ["code", "config"]`, para que se vean Dockerfile, docker-compose y los ficheros de configuración.
- Crea un nodo `kind: "infra"` («Servidores y despliegue») con Terraform, Docker, Kubernetes, Helm y CI, y otro `kind: "test"` para las pruebas.
- **No hagas el paso 6 (describir cada archivo)** salvo que lo pidan: cuesta unos 1.400 tokens por archivo y Lupa no lo necesita. Las tarjetas salen con su ruta y el resumen del módulo.

Si el mapa ya existe, relanza `build.mjs` para que recoja los cambios del código.

## 2. La infraestructura

No es un servidor: es **toda la infraestructura que usa el proyecto** (servidores de aplicación, bases de datos, proxies, colas, VPS, máquinas de CI…). Se revisa en tres partes; ninguna cambia nada en los servidores.

**a) El inventario.** Busca en el repo qué servidores usa: Terraform (`aws_instance`, `aws_lb`, grupos de seguridad), docker-compose, scripts y pipelines de despliegue (hosts, IP, `ssh`, `scp`, `rsync`), inventarios de Ansible, `.env.example` y dominios. Enséñale al usuario la lista y **pregúntale qué falta**: casi siempre hay algún servidor que no está en el código.

**b) Cada servidor por dentro.** `${CLAUDE_SKILL_DIR}/servidor/lupa-servidor.py` saca una foto de solo lectura: parches, qué escucha, con quién habla, SSH, usuarios con poder, contenedores, agentes de seguridad y ficheros con secretos legibles por cualquiera (sin abrir su contenido). Las fotos van a `<raíz>/floorplan/lupa/servidores/<nombre>.json`.

- **En AWS con SSM** (el agente de SSM en línea y credenciales de la cuenta): `node ${CLAUDE_SKILL_DIR}/scripts/servidores-ssm.mjs <raíz> --instancias i-aaa,i-bbb`, o `--vpc vpc-xxxx` (con `--etiqueta Proyecto=X` si la VPC es compartida), con `--region` y `--perfil` si hace falta. Con `--vpc` primero solo enseña la lista: **enséñasela al usuario, quita lo que no sea del proyecto** y repite con `--confirmar` (o pasa a `--instancias`). Además lee, en solo lectura, las interfaces de red, los grupos de seguridad y los balanceadores, para saber qué se alcanza desde internet y poner nombre a cada IP. **Pide permiso antes**: ejecuta un script como root en sus servidores, aunque solo lea y borre al acabar su carpeta de trabajo (en `/run`, solo de root).
- **Por ssh**, para cada servidor (el usuario lo lanza, o tú si te deja y tiene ssh configurado):
  `ssh <servidor> 'sudo python3 -I -' < ${CLAUDE_SKILL_DIR}/servidor/lupa-servidor.py > <raíz>/floorplan/lupa/servidores/<nombre>.json`
- Necesita Python 3.6 o más reciente en el servidor (Ubuntu, Debian y Amazon Linux lo traen). Sin root la foto sale incompleta y lo dice.

**c) La vista desde internet.** `node ${CLAUDE_SKILL_DIR}/scripts/externo.mjs <raíz> --objetivos dominio.com,1.2.3.4` mira lo que vería cualquiera: puertos abiertos de una lista corta, certificados, cabeceras, la portada y una docena de rutas delicadas (`/.git/HEAD`, `/.env`…). Sin ataques ni fuerza bruta. Con `red-aws.json` añade solas las IP públicas y los balanceadores públicos.

- **Solo objetivos del proyecto.** Confirma con el usuario cada dominio e IP antes de lanzarlo: nunca sistemas de terceros (CDN, SaaS, proveedores), aunque el código los llame.
- Lo que se ve depende de desde dónde se mira: si la IP del usuario está en una lista permitida, se verá más que desde fuera. El informe dice desde qué IP se hizo.

Si el proyecto no tiene servidores propios (todo en un PaaS o serverless), sáltate a) y b), haz c) con sus dominios y dilo en el informe.

**d) El CI/CD.** Cómo llega el código a producción. Los ficheros de pipeline del repo se miran en el escaneo, sean de la plataforma que sean (zizmor para GitHub Actions y reglas comunes para Bitbucket Pipelines, GitLab, Jenkins, Azure o CircleCI). La plataforma se mira aparte:

`node ${CLAUDE_SKILL_DIR}/scripts/cicd.mjs <raíz>`

- Detecta sola la plataforma de cada repo por su remoto: GitHub, Bitbucket Cloud o Bitbucket Server/Data Center. Las tres se miden con las mismas reglas:
  - la rama principal: si está protegida y si en la práctica se revisa antes de mergear;
  - los permisos del CI y sus secretos (solo sus nombres y si están protegidos);
  - si producción pide aprobación;
  - los runners, las claves de despliegue y los webhooks;
  - las alertas de la plataforma;
  - los secretos impresos en los logs de las últimas ejecuciones (`--logs 15` por defecto, `--sin-logs` para no mirarlos).
- **Credenciales, solo de lectura y en variables de entorno** (nunca en el chat):
  - GitHub: la sesión de `gh auth login` o `GH_TOKEN`. En GitHub Enterprise, además, `GH_HOST=<host>` (o `GH_ENTERPRISE_TOKEN`).
  - Bitbucket Cloud: `BITBUCKET_EMAIL` y `BITBUCKET_API_TOKEN` (un token de API de Atlassian, con el email de la cuenta; las contraseñas de aplicación ya no funcionan).
  - Bitbucket Server/Data Center: `BITBUCKET_SERVER_URL` (su dirección web) y `BITBUCKET_SERVER_TOKEN`. El token solo se manda a ese host, nunca al que diga un remoto.

  Los logs se descargan de uno en uno a una carpeta temporal del usuario, se pasan por gitleaks y se borran, también si el proceso se corta. El comando tiene un plazo total de unos 8 minutos para los logs: si no da tiempo, queda como hueco.

  Sin ser administrador del repositorio hay cosas que no se ven: quedan como huecos en el informe.
- `--aws` mira además, en solo lectura, los roles de AWS en los que confía el CI (OIDC) y los usuarios de CI con claves. Úsalo si despliegan en AWS y el usuario tiene acceso a la cuenta. **Pide permiso antes** de descargar los logs y de mirar AWS.

## 3. Escaneo

`node ${CLAUDE_SKILL_DIR}/scripts/scan.mjs <raíz>`

Tarda de segundos a unos minutos; Semgrep es lo lento. Escribe `floorplan/lupa/hallazgos.json`, `superficie.json`, `infra.json` (si hay servidores, red o vista externa) y los lotes de revisión en `floorplan/lupa/revision/`. Lo ya revisado en pasadas anteriores se guarda en `lote-00.json` y no se vuelve a pedir.

`--solo gitleaks,semgrep,trivy,zizmor,propios` lanza solo esas partes y conserva lo demás de la pasada anterior. Los servidores, la red, la vista externa y la plataforma de CI/CD se recalculan siempre a partir de lo recogido en el paso 2: tras recoger de nuevo, basta `--solo propios`.

## 4. Revisión (siempre)

Cada `lote-NN.md` trae lo que hay que mirar, con el código delante; contesta en su `lote-NN.json`, sin cambiar las claves ni el orden. **Con más de 3 lotes, repártelos entre subagentes en paralelo** (3 a 5 lotes cada uno). Dales la raíz, sus números de lote y la ruta de este SKILL para que lean esta sección, y diles que solo editen sus `lote-NN.json`.

Lo medido en los servidores y desde internet no pasa por aquí: es un hecho, no una sospecha.

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

## 5. Pintar

`node ${CLAUDE_SKILL_DIR}/scripts/merge.mjs <raíz> --equipo "<equipo>"`

Mete todo en el mapa y escribe el informe: `floorplan/lupa/informe.html`, con el **mapa interactivo del código dentro** (pestaña «Mapa del código», comprimido, sin la ruta de este equipo y sin nada que pida ejecutar comandos), su copia para mandar `floorplan/lupa/lupa-<equipo>-<proyecto>-<fecha>.html` e `informe.md` para tickets. El equipo se recuerda en `ficha.json`, así que en las siguientes pasadas no hace falta repetirlo. Después de **cada** build de floorplan hay que volver a lanzarlo, porque el build reescribe el mapa sin Lupa.

El informe lleva la **ficha de la pasada** (equipo, quién, cuándo, commit, herramientas) y la **cobertura**: si falta un escáner, quedan avisos sin cribar, endpoints sin revisar, servidores sin auditar o no se hizo la vista externa, sale como «pasada incompleta». Dentro van también los datos en JSON (id `lupa-datos`) con su huella SHA-256.

## 6. Enseñar, informar y mandar

Ábrele el mapa tú, sin pedirle nada: `node ${CLAUDE_SKILL_DIR}/../floorplan/scripts/open.mjs <raíz>` (con `--no-open` si tienes navegador integrado, y abre allí la URL). Arranca el servidor del mapa, así que su barra de preguntas funciona con su Claude Code; no le digas que ejecute `serve.mjs`.

Luego informa en 4 a 8 líneas, en castellano:

- Lo grave primero, del código y de la infraestructura.
- Lo que se ve desde internet y no debería.
- Cómo se comunican los servidores, si hay algo raro: tráfico sin cifrar, IP que nadie sabe qué son.
- Qué se ha quedado sin mirar: escáneres que faltaban, lotes sin revisar, servidores sin auditar.
- **El fichero que hay que mandar**, con su ruta: `floorplan/lupa/lupa-<equipo>-<proyecto>-<fecha>.html`. Se manda tal cual (Teams, correo): es un solo fichero que se abre con doble clic, con el informe y el mapa del código dentro, sin servidor ni nada que instalar. Si la pasada salió incompleta, pregunta si quiere completarla antes de mandarlo.

Sin secretos.

## Qué sale del ordenador

- gitleaks y los chequeos propios: nada.
- `doctor.mjs --instalar`: descarga gitleaks y Trivy de sus releases de GitHub y Semgrep de PyPI, en las versiones fijadas en `herramientas.json`, y comprueba el SHA-256 de cada fichero antes de usarlo.
- Semgrep: descarga sus paquetes de reglas de semgrep.dev (con `--metrics=off`; no sube código).
- Trivy: descarga su base de datos de CVE y puede consultar Maven Central por las dependencias de Java. Si Maven corta con un 429, Lupa repite sin red.
- npm, solo en proyectos sin fichero de bloqueo: resuelve las versiones en una carpeta aparte (`--package-lock-only --ignore-scripts`). Descarga metadatos del registro, no instala ni ejecuta nada.
- endoflife.date, CISA KEV y FIRST EPSS: se descargan sus catálogos públicos (caché de un día en `~/.cache/lupa`). Solo se envían números de CVE.
- Servidores: la foto se hace en cada servidor y vuelve a tu equipo; con SSM pasa por la API de AWS de la propia cuenta. De las IP públicas que se conectan a un servidor (portátiles de personas) solo se guarda cuántas son.
- Vista desde internet: conexiones y peticiones normales a los objetivos del proyecto, y una consulta a checkip.amazonaws.com para saber desde qué IP se mira.
- La revisión: el código que lees va al proveedor de IA de la cuenta con la que trabajas. **Usa la cuenta de la empresa, no una personal.**

## En Jenkins o sin IA

`scan.mjs` y `merge.mjs` funcionan sin Claude: el mapa marca los endpoints como «sin revisar» y el informe sale como «pasada incompleta». Para tenerlo todo en CI: `claude -p "/lupa ."` con la cuenta de la empresa.
