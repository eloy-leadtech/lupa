# Lupa

**Encuentra los puntos débiles de todo un proyecto y te los pinta sobre su mapa.**

Lupa es un plugin de Claude Code. Le apuntas a un repo, o a una carpeta con varios, y te devuelve el mapa interactivo de la arquitectura (hecho con [floorplan](https://github.com/haydenschmitty/floorplan)) con cada problema de seguridad encima: las tarjetas en rojo son graves, en ámbar hay que mirarlas y en azul son menores. Cada aviso trae un botón para mandárselo a Claude y que lo arregle.

## Qué mira

| | Cómo |
|---|---|
| **Endpoints** | Todos: Express, Next, NestJS, FastAPI, Flask, Django, Spring, Go, Laravel, Symfony y PHP suelto. **Claude revisa cada uno** para decir si es público, si debería serlo y qué datos suelta |
| **Secretos** | gitleaks, en el código y en **todo el historial de git** |
| **Fallos de código** | Semgrep (OWASP Top 10, inyecciones, XSS, criptografía débil…) |
| **Librerías con fallos** | Trivy: CVE de npm, pip, composer, Maven, Go… |
| **Servidores y despliegue** | Trivy para Terraform, Dockerfile, Kubernetes y Helm. Reglas propias para **Jenkins** (credenciales interpoladas o impresas en el log, `curl \| sh`, TLS desactivado, contenedores privilegiados) y docker-compose (bases de datos abiertas a la red) |
| **Configuración expuesta** | Modo depuración (Laravel, Django, PHP), Actuator abierto, CORS abierto, GraphQL con introspección, phpinfo, listado de carpetas, documentación de la API publicada |
| **Datos y ficheros delicados** | tfstate, claves privadas, copias de BD y credenciales de nube subidas al repo. Datos personales en ficheros de datos: DNI/NIE, IBAN y tarjetas validados, emails y teléfonos |
| **Mapa de datos personales** | Qué modelos, tablas y migraciones guardan pasaportes, DNI, fechas de nacimiento, salud, antecedentes, fotos, datos de pago, conversaciones… y si hay pistas de cifrado. Avisa si se guarda el CVV (prohibido) o hay tarjetas o datos de categoría especial (RGPD art. 9) sin cifrar |
| **Apps con IA** (OWASP Top 10 para LLM) | Claves del proveedor de IA que llegan al navegador, respuestas del modelo pintadas como HTML sin limpiar, texto del usuario metido en las instrucciones de sistema, agentes con shell/Python/SQL libre, modelos que ejecutan código al cargarse. Claude revisa además cada endpoint que llama a un modelo: inyección de prompt, herramientas, fugas entre usuarios, abuso y coste |
| **Web y base de datos** | Cookies sin Secure/HttpOnly, contraseñas con MD5/SHA, JWT sin firma o caducidad, conexiones sin comprobar el certificado, cadenas de conexión con contraseña, enlaces firmados a documentos que duran días, logs con datos personales. Claude mira en cada endpoint con un id si se pueden ver datos de otro usuario (IDOR) |
| **Tecnología y obsolescencia** | La foto de lo que se usa: lenguajes, runtimes, frameworks, bases de datos, imágenes Docker, Terraform, CI e IA, con versión y ciclo de vida según [endoflife.date](https://endoflife.date): sin soporte, caduca pronto o muy desactualizado |
| **CVE explotados (KEV)** | Cada CVE se cruza con el catálogo [KEV de la CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (se está explotando ya) y con [EPSS](https://www.first.org/epss/) (probabilidad de ataque), y se marca si la app está expuesta a internet. Los proyectos Node sin fichero de bloqueo se resuelven aparte para poder mirar sus CVE |

Claude además **criba los falsos positivos**: los quita del mapa, pero los deja listados en el panel para que se vea qué se ha descartado y por qué.

## Instalar

1. Node 18 o superior y Claude Code, con la **cuenta de Leadtech**.
2. Los escáneres:

   | | Windows | Mac | Linux |
   |---|---|---|---|
   | gitleaks | `winget install --id Gitleaks.Gitleaks -e` | `brew install gitleaks` | binario de sus releases |
   | Trivy | `winget install --id AquaSecurity.Trivy -e` | `brew install trivy` | paquete oficial |
   | Semgrep | `py -m venv C:\dev\tools\semgrep-venv` y `C:\dev\tools\semgrep-venv\Scripts\pip install semgrep` | `brew install semgrep` | `pipx install semgrep` |

   Si falta alguno, Lupa funciona igual, pero esa parte se queda sin mirar y lo dice.
3. El plugin:

   ```
   claude plugin marketplace add <ruta-o-repo-de-lupa>
   claude plugin install lupa@lupa
   ```

## Usar

Dentro del proyecto, en Claude Code:

```
/lupa
```

O con una ruta: `/lupa C:\repos\mi-proyecto`. Claude hace el mapa si no existe, lanza los escáneres, revisa los endpoints y abre el resultado en el navegador. En el mapa:

- **Botón «Lupa»:** el resumen por tipo de problema y la superficie de ataque (endpoints abiertos que no deberían, públicos, sin revisar).
- **Botón «Health»:** la lista completa, con «Ver en el mapa» y «Arreglar con Claude» en cada aviso.
- **Tarjetas:** el número de la esquina es cuántos avisos tiene dentro. Al hacer clic en un endpoint se ve lo que dijo Claude de él.

En el panel de Lupa se elige qué pinta el mapa: **Riesgo** (calor por gravedad) o **Datos personales** (dónde viven los datos de personas).

### El informe

Cada pasada deja **`floorplan/lupa/informe.html`**: un solo fichero, sin nada externo, que se abre en cualquier navegador y se imprime a PDF. Es lo que se manda a quien evalúa. Trae:

- **La nota**, de la A a la F, con la fórmula explicada en el propio informe.
- **La foto de dónde se pierde la seguridad:** cada bloque es una parte del proyecto, del tamaño de su código y del color de lo peor que tiene dentro.
- **Lo urgente**, por orden.
- **La superficie de ataque:** los endpoints abiertos que no deberían, con lo que sueltan.
- **Las librerías explotadas (KEV)**, diciendo si la app está expuesta.
- **La tecnología**, con su ciclo de vida.
- **El mapa de datos personales.**
- **Cómo se ha hecho y qué se ha quedado sin mirar.**

`floorplan/lupa/informe.md` tiene un resumen en texto, para tickets.

La segunda pasada es más barata: lo ya revisado se recuerda y solo se piden los endpoints y avisos nuevos.

## Qué sale de tu ordenador

- **gitleaks y los chequeos propios:** nada.
- **Semgrep:** descarga sus reglas de semgrep.dev, con las métricas apagadas. No sube código.
- **Trivy:** descarga su base de datos de CVE y puede preguntar a Maven Central por dependencias de Java.
- **npm**, solo en proyectos sin fichero de bloqueo: resuelve las versiones en una carpeta temporal (`--package-lock-only --ignore-scripts`). No instala ni ejecuta nada del proyecto.
- **endoflife.date, CISA KEV y FIRST EPSS:** catálogos públicos, con caché de un día en `~/.cache/lupa`. Solo se envían números de CVE.
- **La revisión de Claude:** el código que revisa va a Anthropic con la cuenta que uses. **Usa siempre la de la empresa.**

Todo lo que genera Lupa se queda en `floorplan/`, que se ignora a sí misma en git.

## En Jenkins

Sin IA, los dos scripts funcionan solos y el mapa marca los endpoints como «sin revisar»:

```
node <lupa>/skills/lupa/scripts/scan.mjs .
node <lupa>/skills/lupa/scripts/merge.mjs .
```

Con IA: `claude -p "/lupa ."` usando una credencial de la empresa.

Antes de esos dos scripts hace falta el mapa (`floorplan/graph.json`), que se crea con `/lupa` la primera vez.

## Límites

- Es una auditoría automática muy amplia, pero **no sustituye un pentest**: no ejecuta la aplicación ni prueba ataques reales.
- Semgrep en Windows va con un solo proceso, porque en paralelo falla. En un proyecto grande tarda unos minutos.
- floorplan entiende peor C#/.NET: allí salen menos rutas y conexiones.

## Por dentro

- `skills/lupa/`: el skill (`SKILL.md`), los scripts (`scan.mjs`, `merge.mjs`, `doctor.mjs`), las reglas propias de Semgrep (`rules/lupa.yml`) y la pieza del mapa (`assets/lupa-ui.js`).
- `skills/floorplan/`: floorplan, copiado **fijo** en el commit `700645b` y sin modificar (licencia MIT, ver `FIJADO.md`). Lupa se engancha por fuera: mete sus avisos en el Health de floorplan y su pieza en el mapa.
- Pruebas: `npm test`.
