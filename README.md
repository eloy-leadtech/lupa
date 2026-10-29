# Lupa

**La auditoría de seguridad de todo un proyecto, código e infraestructura, en un solo informe para mandar.**

Lupa es un plugin de Claude Code. Le apuntas a un repo, o a una carpeta con varios, y revisa el código, los servidores donde corre y lo que se ve desde internet. Te devuelve dos cosas:

- **El mapa interactivo** de la arquitectura (hecho con [floorplan](https://github.com/haydenschmitty/floorplan)) con cada problema encima: las tarjetas en rojo son graves, en ámbar hay que mirarlas y en azul son menores. Cada aviso trae un botón para mandárselo a Claude y que lo arregle.
- **El informe**: un único fichero HTML, con la nota, lo urgente, los servidores y cómo se comunican, que el equipo manda al equipo de seguridad.

## Para los equipos: de la invitación al informe

1. **Acepta la invitación** al repositorio `eloy-leadtech/lupa` que te llega de GitHub.
2. **Instala el plugin** en Claude Code, con la **cuenta de Leadtech**. Hace falta que tu git pueda leer repos privados de GitHub, con `gh auth login` o una clave SSH:

   ```
   claude plugin marketplace add eloy-leadtech/lupa
   claude plugin install lupa@lupa
   ```

3. **Ábrelo en tu proyecto** y escribe `/lupa`. Claude te irá preguntando:
   - de qué equipo es el proyecto;
   - si puede descargar los escáneres que falten (versiones fijadas, comprobadas por hash, en una carpeta propia);
   - qué servidores usa el proyecto y cómo se llega a ellos (SSM de AWS o ssh);
   - qué dominios e IP públicas son vuestros, para mirarlos desde internet.
4. **Manda el fichero** que te indica al final, `floorplan/lupa/lupa-<equipo>-<proyecto>-<fecha>.html`, por Teams o correo. Es un solo fichero, sin nada externo.

La segunda pasada es más barata: lo ya revisado se recuerda y solo se piden los endpoints y avisos nuevos.

## Qué mira

| | Cómo |
|---|---|
| **Endpoints** | Todos: Express, Next, NestJS, FastAPI, Flask, Django, Spring, Go, Laravel, Symfony y PHP suelto. **Claude revisa cada uno** para decir si es público, si debería serlo y qué datos suelta |
| **Secretos** | gitleaks, en el código y en **todo el historial de git** |
| **Fallos de código** | Semgrep (OWASP Top 10, inyecciones, XSS, criptografía débil…) |
| **Librerías con fallos** | Trivy: CVE de npm, pip, composer, Maven, Go… |
| **Despliegue como código** | Trivy para Terraform, Dockerfile, Kubernetes y Helm. Reglas propias para **Jenkins** (credenciales interpoladas o impresas en el log, `curl \| sh`, TLS desactivado, contenedores privilegiados) y docker-compose (bases de datos abiertas a la red) |
| **Cada servidor por dentro** | Un script de solo lectura en cada servidor del proyecto: parches de seguridad pendientes, si se actualiza solo (y si de verdad funciona), sistema sin soporte, SSH con contraseña o root, cuentas con poder de root, puertos de bases de datos y paneles abiertos en todas las interfaces, contenedores privilegiados, con el socket de Docker o como root, secretos en disco legibles por cualquiera y si hay agente de detección (Wazuh, EDR…) |
| **Cómo se comunican** | Las conexiones reales entre servidores, vistas desde los dos extremos: quién habla con quién, por qué puerto, qué va sin cifrar, qué IP internas nadie sabe qué son. En AWS, además, qué dejan pasar los grupos de seguridad y los balanceadores |
| **Vista desde internet** | Lo que ve cualquiera de los dominios e IP públicas del proyecto: puertos de una lista corta, certificados (caducados, autofirmados), cabeceras, cookies y rutas delicadas (`/.git`, `/.env`, `server-status`, Actuator…). Sin ataques |
| **Configuración expuesta** | Modo depuración (Laravel, Django, PHP), Actuator abierto, CORS abierto, GraphQL con introspección, phpinfo, listado de carpetas, documentación de la API publicada |
| **Datos y ficheros delicados** | tfstate, claves privadas, copias de BD y credenciales de nube subidas al repo. Datos personales en ficheros de datos: DNI/NIE, IBAN y tarjetas validados, emails y teléfonos |
| **Mapa de datos personales** | Qué modelos, tablas y migraciones guardan pasaportes, DNI, fechas de nacimiento, salud, antecedentes, fotos, datos de pago, conversaciones… y si hay pistas de cifrado. Avisa si se guarda el CVV (prohibido) o hay tarjetas o datos de categoría especial (RGPD art. 9) sin cifrar |
| **Apps con IA** (OWASP Top 10 para LLM) | Claves del proveedor de IA que llegan al navegador, respuestas del modelo pintadas como HTML sin limpiar, texto del usuario metido en las instrucciones de sistema, agentes con shell/Python/SQL libre, modelos que ejecutan código al cargarse. Claude revisa además cada endpoint que llama a un modelo: inyección de prompt, herramientas, fugas entre usuarios, abuso y coste |
| **Web y base de datos** | Cookies sin Secure/HttpOnly, contraseñas con MD5/SHA, JWT sin firma o caducidad, conexiones sin comprobar el certificado, cadenas de conexión con contraseña, enlaces firmados a documentos que duran días, logs con datos personales. Claude mira en cada endpoint con un id si se pueden ver datos de otro usuario (IDOR) |
| **Tecnología y obsolescencia** | La foto de lo que se usa: lenguajes, runtimes, frameworks, bases de datos, imágenes Docker, Terraform, CI, IA y el sistema operativo de cada servidor, con versión y ciclo de vida según [endoflife.date](https://endoflife.date) |
| **CVE explotados (KEV)** | Cada CVE se cruza con el catálogo [KEV de la CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (se está explotando ya) y con [EPSS](https://www.first.org/epss/) (probabilidad de ataque), y se marca si la app está expuesta a internet. Los proyectos Node sin fichero de bloqueo se resuelven aparte para poder mirar sus CVE |

Claude además **criba los falsos positivos**: los quita del mapa, pero los deja listados en el panel para que se vea qué se ha descartado y por qué.

## Instalar a mano

Normalmente no hace falta: `/lupa` lo hace contigo. Lo necesario:

1. Node 18 o superior y Claude Code, con la **cuenta de Leadtech**.
2. Los escáneres. `node skills/lupa/scripts/doctor.mjs --instalar` descarga las versiones fijadas en `skills/lupa/herramientas.json` (gitleaks, Trivy, Semgrep) en `~/.cache/lupa/bin`, comprueba el SHA-256 de cada fichero y no toca el sistema. Semgrep necesita Python 3.10 o superior. También valen los del sistema:

   | | Windows | Mac | Linux |
   |---|---|---|---|
   | gitleaks | `winget install --id Gitleaks.Gitleaks -e` | `brew install gitleaks` | binario de sus releases |
   | Trivy | `winget install --id AquaSecurity.Trivy -e` | `brew install trivy` | paquete oficial |
   | Semgrep | `py -m venv C:\dev\tools\semgrep-venv` y `C:\dev\tools\semgrep-venv\Scripts\pip install semgrep` | `brew install semgrep` | `pipx install semgrep` |

   Si falta alguno, Lupa funciona igual, pero esa parte se queda sin mirar y el informe sale como «pasada incompleta».
3. Para los servidores: la CLI de `aws` con acceso a SSM si están en AWS, o ssh. En cada servidor, Python 3.6 o superior (y root, para ver procesos y la config de SSH).

## El informe

Cada pasada deja **`floorplan/lupa/informe.html`** y su copia para mandar, **`lupa-<equipo>-<proyecto>-<fecha>.html`**: un solo fichero, sin nada externo, que se abre con doble clic en cualquier navegador y se imprime a PDF. Tiene dos pestañas: **Informe** y **Mapa del código**, el mapa interactivo completo con cada aviso en su sitio (va comprimido dentro y el navegador lo abre al pulsar la pestaña). Trae:

- **La ficha de la pasada**: equipo, quién la hizo, cuándo, sobre qué commit (y si había cambios sin commitear), con qué versiones de cada herramienta.
- **La cobertura**: si faltaba un escáner, quedaron avisos sin cribar, endpoints sin revisar, servidores sin auditar o no se hizo la vista desde internet, el informe lo dice en la cabecera («pasada incompleta»).
- **La nota**, de la A a la F, con la fórmula explicada en el propio informe.
- **Dónde se pierde la seguridad:** cada bloque es una parte del proyecto, del tamaño de su código y del color de lo peor que tiene dentro.
- **Lo urgente**, por orden.
- **La superficie de ataque:** los endpoints abiertos que no deberían, con lo que sueltan.
- **Servidores y red:** cada servidor por dentro, el diagrama de cómo se comunican, las puertas a internet y lo que se vio desde fuera.
- **Las librerías explotadas (KEV)**, diciendo si la app está expuesta.
- **La tecnología**, con su ciclo de vida.
- **El mapa de datos personales.**

Dentro del HTML van también **los datos en JSON** (`<script id="lupa-datos">`), para comparar equipos o cargarlos en otra herramienta, con su huella SHA-256 en el campo `huella`. Para comprobarla: quita ese campo, vuelve a serializar el resto con `JSON.stringify` y calcula su SHA-256.

`floorplan/lupa/informe.md` tiene un resumen en texto, para tickets.

## Qué sale de tu ordenador

- **gitleaks y los chequeos propios:** nada.
- **`doctor.mjs --instalar`:** descarga gitleaks y Trivy de GitHub y Semgrep de PyPI, en versiones fijadas y comprobadas por hash.
- **Semgrep:** descarga sus reglas de semgrep.dev, con las métricas apagadas. No sube código.
- **Trivy:** descarga su base de datos de CVE y puede preguntar a Maven Central por dependencias de Java.
- **npm**, solo en proyectos sin fichero de bloqueo: resuelve las versiones en una carpeta temporal (`--package-lock-only --ignore-scripts`). No instala ni ejecuta nada del proyecto.
- **endoflife.date, CISA KEV y FIRST EPSS:** catálogos públicos, con caché de un día en `~/.cache/lupa`. Solo se envían números de CVE.
- **Servidores:** la foto se toma en cada servidor y vuelve a tu equipo (con SSM, por la API de AWS de vuestra cuenta). De las IP públicas que se conectan a un servidor solo se guarda cuántas son.
- **Vista desde internet:** conexiones y peticiones normales a los objetivos del proyecto, y una consulta a checkip.amazonaws.com para saber desde qué IP se mira.
- **La revisión de Claude:** el código que revisa va a Anthropic con la cuenta que uses. **Usa siempre la de la empresa.**

Todo lo que genera Lupa se queda en `floorplan/`, que se ignora a sí misma en git.

## En Jenkins

Sin IA, los scripts funcionan solos y el mapa marca los endpoints como «sin revisar»:

```
node <lupa>/skills/lupa/scripts/scan.mjs .
node <lupa>/skills/lupa/scripts/merge.mjs . --equipo "<equipo>"
```

Con IA: `claude -p "/lupa ."` usando una credencial de la empresa.

Antes de esos dos scripts hace falta el mapa (`floorplan/graph.json`), que se crea con `/lupa` la primera vez.

## Límites

- Es una auditoría automática muy amplia, pero **no sustituye un pentest**: no prueba ataques reales.
- «Solo lectura» quiere decir que no cambia configuración ni datos: el auditor trabaja en una carpeta propia de `/run` (solo root, distinta en cada pasada) que borra al acabar, y no pregunta a `iptables` si eso cargaría módulos del kernel. En Amazon Linux, `dnf -C` puede rehacer ficheros de su propia caché.
- La foto de las conexiones es de un momento: una conexión que solo ocurre de noche (una copia de seguridad, un cron) no sale. Varias pasadas a distintas horas la completan.
- La vista desde internet ve lo que se ve desde la IP de quien la lanza: si esa IP está en una lista permitida, verá más que el resto del mundo. El informe dice desde qué IP se hizo.
- Semgrep en Windows va con un solo proceso, porque en paralelo falla. En un proyecto grande tarda unos minutos.
- En Windows con Defender, la regla ASR que bloquea ejecutables poco comunes para los lanzadores `.exe` que pip genera. Lupa llama a Semgrep a través de su Python para esquivarlo.
- floorplan entiende peor C#/.NET: allí salen menos rutas y conexiones.

## Por dentro

- `skills/lupa/`: el skill (`SKILL.md`), los scripts (`scan.mjs`, `merge.mjs`, `doctor.mjs`, `servidores-ssm.mjs`, `externo.mjs`), el auditor de servidores (`servidor/lupa-servidor.py`), las versiones fijadas de los escáneres (`herramientas.json`), las reglas propias de Semgrep (`rules/lupa.yml`) y la pieza del mapa (`assets/lupa-ui.js`).
- `skills/floorplan/`: floorplan, copiado **fijo** en el commit `700645b` y sin modificar (licencia MIT, ver `FIJADO.md`). Lupa se engancha por fuera: mete sus avisos en el Health de floorplan y su pieza en el mapa.
- Pruebas: `npm test`.
