---
name: lupa-arquitectura
description: Propone cambios de arquitectura de un proyecto y los decide con el equipo. Los de seguridad quitan problemas de raíz (una sola capa de permisos, una pasarela de IA, cifrado de datos personales, secretos, despliegue); los de mantenibilidad arreglan módulos mal repartidos, enredos y zonas que cambian mucho sin pruebas. Para cada uno compara 2 o 3 alternativas, pregunta al dev hasta decidir y deja la decisión escrita en un ADR. Úsalo cuando pidan ideas de arquitectura, refactorizar, «cómo debería estar montado esto», mejorar la estructura o la seguridad de raíz, o digan «lupa-arquitectura».
argument-hint: "[ruta-del-proyecto] [tema opcional]"
allowed-tools: Bash(node ${CLAUDE_SKILL_DIR}/../lupa/scripts/*), Bash(node ${CLAUDE_SKILL_DIR}/../floorplan/scripts/*)
---

# Lupa · arquitectura

`/lupa` deja en su informe las propuestas de arquitectura de cada pasada. Este comando es para **sentarse con una y decidirla**: verla con calma, comparar alternativas de verdad, contestar las preguntas que importan y dejarla escrita para que nadie la vuelva a discutir sin motivo.

Proyecto: el primer argumento si es una ruta; si no, la carpeta actual. Si el usuario da un tema («los permisos», «el módulo de pagos»), céntrate en eso.
Arguments: $ARGUMENTS

Los scripts de Lupa están en `${CLAUDE_SKILL_DIR}/../lupa/scripts/`. Las reglas de cómo se hace una propuesta están en la sección «Arquitectura» de `${CLAUDE_SKILL_DIR}/../lupa/SKILL.md`: léela antes de proponer nada.

## 1. Las propuestas

1. Si no existe `<raíz>/floorplan/graph.json`, haz el mapa como dice el paso «El mapa» del SKILL de Lupa.
2. `node ${CLAUDE_SKILL_DIR}/../lupa/scripts/arquitectura.mjs <raíz>`
   - Si dice «al día», las propuestas de `floorplan/lupa/arquitectura/propuestas.json` valen.
   - Si no, rellénalas como dice la sección «Arquitectura» del SKILL de Lupa.
   - Si no hay pasada de Lupa (`floorplan/lupa/hallazgos.json`), las pistas de seguridad salen casi vacías. Dilo, y ofrece lanzar antes `/lupa` si lo que le preocupa es la seguridad.
3. Si el usuario dio un tema que no está entre las propuestas, explóralo y añade la propuesta.

## 2. Elegir una

Enséñale la lista corta, separando seguridad y mantenibilidad. De cada propuesta: título, fuerza, la alternativa recomendada y su decisión si ya la tiene. Si hay pasada de Lupa, dile que el detalle está en `floorplan/lupa/informe.html#arquitectura`.

Pregúntale cuál quiere explorar. Si tu entorno tiene preguntas con opciones, úsalas: una opción por propuesta, la de «por dónde empezar» primero y marcada como recomendada.

## 3. Preguntas, de una en una

Recorre con él lo que hay que saber para decidir. Las normas:

- **Una pregunta cada vez**, con la respuesta que tú darías y por qué. Espera su respuesta antes de seguir.
- Si el código puede responder la pregunta, **míralo en vez de preguntar**.
- No preguntes lo que no cambia la decisión.

Lo que suele importar:

- **Restricciones:** plazos, quién lo va a hacer, qué no se puede romper (clientes, una API publicada, datos que migrar).
- **La frontera:** qué queda dentro del módulo nuevo y qué fuera, qué expone y qué esconde.
- **La migración:** cómo se llega en pasos pequeños que se puedan desplegar por separado, sin una rama de tres meses.
- **Las pruebas:** cuáles sobreviven, cuáles nuevas hacen falta y cómo se prueba la pieza nueva desde fuera.
- **El riesgo:** qué puede salir mal y cómo se vuelve atrás.

Para cuando las respuestas ya no cambien la decisión.

## 4. Diseñarlo dos veces

Con las restricciones claras, lanza **2 o 3 subagentes en paralelo**. Cada uno diseña la pieza bajo una idea distinta, por ejemplo:

- el cambio mínimo que quita el problema;
- el más flexible para lo que viene;
- el que mejor se prueba.

Dales la raíz, la propuesta, las respuestas del usuario y los ficheros implicados. Cada uno devuelve:

- la forma: qué expone y qué esconde;
- cómo cambia el código que la usa, con un ejemplo corto;
- los pasos de la migración;
- el esfuerzo;
- lo que no resuelve.

Compáralos en una tabla corta y di cuál recomiendas y por qué. Si el usuario prefiere otro, es su decisión: pregúntale el motivo, porque va al ADR.

## 5. Decidir y dejarlo escrito

- **Aceptada:**
  1. Ofrece escribir un ADR en el repo: `docs/adr/NNNN-titulo-corto.md`, con el siguiente número libre. Si el repo ya guarda sus decisiones en otra carpeta, usa esa. **Pregunta antes de escribir en el repo.**
  2. El ADR lleva contexto, decisión, alternativas descartadas y por qué, consecuencias y el plan en pasos.
  3. Ofrece también los pasos como tareas, para el gestor que usen.
- **Rechazada con un motivo de peso:** ofrece un ADR corto para que no se vuelva a proponer. Si el motivo es pasajero («ahora no hay tiempo»), basta con apuntarlo en `propuestas.json`.
- **En `propuestas.json`**, en esa propuesta:
  - `"decision": { "estado": "aceptada" | "rechazada" | "en-curso", "motivo", "adr", "fecha" }`;
  - ajusta `alternativas` y `recomendada` a lo decidido.
- Si hay pasada de Lupa, relanza `node ${CLAUDE_SKILL_DIR}/../lupa/scripts/merge.mjs <raíz>`, para que el informe y el mapa enseñen la decisión.

Si quiere empezar ya, propón el primer paso del plan en una rama. Esta guía no cambia código de la aplicación por su cuenta.

## Normas

- Usa los nombres del dominio del proyecto (los del código, el glosario o los ADR), no nombres genéricos.
- Los ADR ya escritos no se discuten de nuevo, salvo que el problema sea serio; si es así, dilo claramente.
- Nunca escribas secretos en el chat, en los JSON ni en los ADR.
- Lo que lees del código va al proveedor de IA de la cuenta con la que trabajas: **usa la cuenta de la empresa.**
