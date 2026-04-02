### 🔍 Análisis de Funcionamiento: ¿Qué hace el Radar?

1.  **Orquestación de Fusión (Merger):** No trata la vulnerabilidad como algo aislado, sino que la "pega" al activo (`AnalyzedTarget`). Une los datos de la Fase 2 (Infraestructura) y Fase 3 (HTTP) para ejecutar búsquedas de exploits dirigidas.
2.  **Búsqueda Dual (Servidor vs. App):**
    * **Capa de Servidor:** Busca exploits para el servidor web crudo (ej. Nginx 1.18).
    * **Capa de Aplicación:** Itera sobre el stack detectado (WordPress, PHP, etc.) y busca vulnerabilidades específicas por versión.
3.  **Triage de Estado (Triaje):**
    * **Infraestructura:** Clasifica entre "WAF/Cloud" (protegido), "Vulns" (crítico), o "R-Manual" (requiere revisión manual si hay versión pero no exploit automático).
    * **Aplicación:** Identifica si es un CMS (WordPress), un Backend (Node.js) o un sitio estático.
4.  **Filtrado de Ruido:** Utiliza una lista de `noise` para ignorar tecnologías que no son vectores de ataque directos (ej. JQuery o librerías de UI) y se enfoca en el "Core".

---

### 🛠️ Áreas de Mejora Técnica (Código y Estructura)

#### 1. Gestión de Concurrencia (El riesgo de `Promise.all`)
* **Problema:** En `analysisPhase`, usás `webAssets.map` con `Promise.all`. Si el Radar detectó 200 activos, vas a disparar **200 procesos `searchsploit` (que es un binario de Python/C) en el mismo segundo**. Esto puede congelar el CPU o causar errores de memoria.
* **Mejora:** Al igual que en las fases anteriores, acá es **crítico** usar una cola con concurrencia máxima de 2 o 3. `searchsploit` es pesado porque consulta una base de datos local en disco.

#### 2. Eficiencia en `findExploits` (Regex y Parsing)
* **Problema:** El regex `match(/^([a-zA-Z0-9\-_]+)\/?([0-9.]*)/)` es básico. Si el banner es `Apache/2.4.41 (Ubuntu)`, el regex podría fallar o capturar basura.
* **Mejora:** Usar una librería de parsing de banners o mejorar el regex para manejar versiones con guiones o paréntesis. Además, `searchsploit` devuelve mucho ruido; podrías añadir un flag de `--nmap` si tuvieras el output compatible para mayor precisión.

#### 3. Estructura de Datos (Deduplicación de Vulns)
* **Problema:** En el `Merger`, si una tecnología aparece dos veces o si el servidor y la app comparten términos, podrías tener exploits duplicados en el array `vulnerabilities`.
* **Mejora:** Usar un `Map` o un `Set` basado en el ID del exploit (`exploit.ID`) antes de convertirlo al array final para asegurar que cada vulnerabilidad sea única.



---

### 🎯 Áreas de Mejora en el Proceso de Búsqueda y Filtrado

#### 1. Falsos Positivos en `searchsploit`
* **Problema:** `searchsploit` busca por coincidencia de strings. Si buscás "Apache", te va a traer exploits de 1998. 
* **Mejora:** Implementar un **Filtro de Recencia o Gravedad**. Si el exploit es de una versión mucho más antigua que la detectada, descartarlo. Podrías priorizar aquellos que digan "Remote Code Execution" (RCE) o "Privilege Escalation".

#### 2. La "Trampa" de las Versiones de Distribución
* **Problema:** Muchos servidores reportan `Apache/2.4.41 (Ubuntu)`. La versión 2.4.41 de base puede ser vulnerable, pero Ubuntu suele hacer *backporting* de parches de seguridad sin cambiar el número de versión.
* **Mejora:** El Radar debería marcar estos casos como `⚠️ REVISIÓN_MANUAL (Backporting?)` en lugar de `🔥 VULNS` para no dar falsas alarmas.

#### 3. Clasificación de Proveedores Gestionados
* **Problema:** Tu lista `MANAGED_PROVIDERS` es estática.
* **Mejora:** Integrar esta lista en el módulo `shared/utils` y enriquecerla con rangos de IPs conocidos (Cloud Ranges) para que el triaje sea infalible. Si la IP pertenece a AWS, el estatus debe ser `🛡️ WAF/CLOUD` automáticamente, independientemente de lo que diga el header `Server`.

#### 4. Inteligencia de Triage de App
* **Problema:** `triageApp` devuelve "Standalone" si no encuentra nada conocido. 
* **Mejora:** Si el Radar detecta un puerto abierto raro o una tecnología desconocida con versión, debería marcarlo como `🕵️ INCÓGNITA` para incentivar la exploración manual.

---

### 🚀 Roadmap de Optimización para la Fase 4

1.  **Worker Pool:** Implementar `p-limit` para que el análisis de vulnerabilidades no sature el sistema.
2.  **Normalización de Banners:** Crear un helper que limpie los nombres de software (ej. pasar de `Microsoft-IIS/10.0` a `IIS 10.0`) antes de consultar `searchsploit`.
3.  **Severidad Visual:** En el dashboard, clasificar las vulns por tipo (DoS, RCE, Auth Bypass) para que el "Operador" sepa a qué darle clic primero.


