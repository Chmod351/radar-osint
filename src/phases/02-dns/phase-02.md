# 📝 Auditoría Técnica: Fase 2 (DNS, ASN & Whois)

## 🔍 Observaciones de Arquitectura Actual
* **Modularización Exitosa:** La separación de la lógica en `resolver.ts`, `ansLookup.ts` y `whois.ts` facilita el mantenimiento y cumple con el principio de responsabilidad única.
* **Estrategia de Caché Inteligente:** El uso de un `Map` para cachear resultados de Whois basados en el *Root Domain* es una táctica crítica para reducir la huella sobre los servidores de registro y evitar bloqueos de IP.
* **Clasificación Proactiva:** La función `classifyTarget` permite segmentar la infraestructura entre "Cloud/CDN" y "Self-Hosted", optimizando el uso de recursos para las fases posteriores.

---

## 🛠 Áreas de Mejora y Refactorización

### 1. Gestión de Concurrencia y Presión de Red
* **Punto Crítico:** Funciones como `enrichWithASN` utilizan `Promise.all` sobre el array completo de IPs. Esto genera una ráfaga de consultas DNS que puede saturar la tabla NAT del router o causar `ECONNREFUSED`.
* **Mejora:** Implementar un **Task Runner** en la carpeta `shared` con límite de concurrencia ajustable (Semáforo). Las funciones de I/O puro (ASN y Whois) deben consumir este worker en lugar de disparar promesas masivas en paralelo.

### 2. Optimización de Estructuras de Datos
* **Uso de Maps para Lookup:** Migrar el `preReport` de un `Array` a un `Map<string, AnalyzedTarget>` durante la fase de procesamiento para permitir actualizaciones de estado con complejidad $O(1)$.
* **Filtrado Previo al Whois:** Evitar iterar sobre todo el reporte dentro del controlador de Whois. Es preferible pasar una "vista" ya filtrada de targets con `action === "SCAN_READY"` para desacoplar la lógica de selección de la lógica de ejecución.

### 3. Resiliencia y Manejo de Errores (Fallbacks)
* **Clasificación de Errores:** Actualmente, el manejo de errores se limita a `console.log`. Se requiere una distinción entre "Error de Red Local" (requiere pausa/backoff) y "Error de Target" (requiere marcado de registro corrupto).
* **Backoff Exponencial:** Integrar reintentos automáticos con tiempos de espera incrementales para las consultas de ASN y Whois, mitigando fallos temporales de conectividad.

### 4. Eficiencia en el Procesamiento de Strings
* **Transición a Streams:** En herramientas como `dnsx` y `httpx`, se recomienda procesar el `stdout` mediante *streams* en lugar de cargar el string completo en memoria con `.split("\n")`. Esto garantiza que el Radar pueda procesar miles de subdominios con un consumo de RAM constante.

---

## 🚀 Próximos Pasos (Roadmap Técnico)
1.  [ ] **Abstracción de Persistencia:** Implementar una interfaz de repositorio para SQLite/Postgres que permita el guardado incremental de cada fase.
2.  [ ] **Unit Testing de Normalización:** Asegurar que el `Root Domain` se extraiga correctamente en casos complejos (ej. `.gob.ar` vs `.com`) para no romper la caché de Whois.
3.  [ ] **Mocking para Pruebas de Red:** Desarrollar un servidor local de pruebas para validar el límite de la cola de tareas sin realizar peticiones reales.

