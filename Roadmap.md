# Roadmap: Proyecto RADAR

Este documento define la arquitectura, evolución técnica y objetivos de escalabilidad del **Radar de Infraestructura Nacional**. El proyecto busca mapear la soberanía tecnológica y las dependencias de red en el sector público.

---

## 🎯 Visión del MVP (v1.0)
El objetivo es transformar el script secuencial en una herramienta de reconocimiento activa, resiliente y capaz de manejar volúmenes masivos de datos sin saturar la infraestructura local ni el stack de red.

### 1. Refactor de Estructuras de Datos
* **De Arrays a Sets/Maps:** Migrar el almacenamiento en memoria para garantizar unicidad y búsquedas $O(1)$. 
    * `Set<string>` para subdominios y activos únicos.
    * `Map<string, TargetData>` para asociar metadatos a dominios/IPs.
* **Normalización Estricta:** Implementar limpieza de entradas (lowercase, trim, remoción de protocolos) antes de la indexación.

### 2. Motor de Concurrencia (Semáforo de Red)
* **Implementación de Task Queue:** Sustituir `Promise.all()` por una cola con límite de concurrencia configurable (max 10-15 workers).
* **Segmentación por Etapas:**
    1.  Reconocimiento DNS y Whois (Bajo impacto).
    2.  Fingerprinting HTTP/HTTPS (httpx/curl).
    3.  Escaneo de Puertos Críticos (nmap) solo sobre objetivos validados.
* **Jitter e Intervalos:** Añadir retardos aleatorios para evitar bloqueos por IDS/IPS y reducir el estrés sobre la tabla NAT del router/VPN.

### 3. Persistencia y Abstracción de Datos
* **Capa de Acceso a Datos (DAL):** Implementar una interfaz de repositorio para desacoplar la lógica de negocio del motor de base de datos.
* **SQLite con Bun:** Uso inicial de SQLite por su alto rendimiento en entornos locales.
* **Commit Inmediato:** Guardar el progreso de cada tarea individualmente para permitir la recuperación ante fallos o interrupciones (Checkpointing).

### 4. Resiliencia y Fallbacks
* **Manejo de Errores Sistémicos:** Clasificar errores (Red local vs. Target rechazado).
* **Retry con Backoff Exponencial:** Implementar reintentos automáticos para errores de red temporales (`ECONNREFUSED`, `ETIMEDOUT`) con tiempos de espera incrementales.

---

## 📈 Escalabilidad y Futuro (v2.0+)

### 1. Motor de Saneamiento ("The Healer")
* **Reprocesamiento Automático:** Script encargado de filtrar registros con estado `failed` o datos incompletos para disparar consultas de recuperación.
* **Rotación de Identidad:** Capacidad de reintentar tareas fallidas utilizando diferentes gateways o configuraciones de VPN.

### 2. Análisis de Correlación y Grafo de Dependencias
* **Detección de Patrones:** Consultas SQL para identificar infraestructuras compartidas (IPs repetidas en múltiples municipios, mismos rangos de ASN, proveedores de Cloud dominantes).
* **Mapeo de Soberanía:** Identificar el porcentaje de datos alojados en servidores extranjeros vs. nacionales.



### 3. Interfaz de Comando (CLI) y Automatización
* **Soporte de Flags:** Implementar parámetros (`--target`, `--depth`, `--fast`, `--db-sync`) para permitir ejecuciones granulares sin disparar todo el motor.
* **Escaneo Condicional:** Lógica para disparar scripts de `nmap --script vuln` automáticamente solo cuando se detecten versiones de software obsoletas en los headers.

### 4. Abstracción de Dependencias (Refactor de Arquitectura)
* **Inyección de Dependencias:** Evaluar la abstracción de herramientas externas (nmap, httpx) mediante wrappers para facilitar su reemplazo por librerías nativas o herramientas más ligeras en el futuro.

---

## 🛠️ Stack Tecnológico
* **Runtime:** Bun (por su motor JavaScriptCore y soporte nativo SQLite).
* **Lenguaje:** TypeScript (Tipado estricto para modelos de datos de red).
* **DB:** SQLite (con interfaz preparada para migración a PostgreSQL).
* **Networking:** VPN forzada a nivel de sistema operativo para asegurar el anonimato del tráfico.
