🛠 Áreas de Mejora y Refactorización
1. El Problema del Bloqueo Secuencial (Bun.sleep)

    Punto Crítico: En runHttpPhase, el uso de await Bun.sleep(Math.random() * 6000) dentro de un bucle for...of garantiza un sigilo extremo, pero sacrifica la eficiencia. Si tenés 100 dominios, el radar podría tardar hasta 10 minutos solo en esta fase de forma innecesaria.

    Mejora: Implementar el Task Runner (discutido en la Fase 2) con un límite de concurrencia bajo (ej. 3 o 5 workers). Esto permite procesar varios dominios simultáneamente manteniendo el retraso aleatorio (jitter) individual para no disparar alertas de DOS.

2. Eficiencia en el Fingerprinting (WhatWebService)

    Punto Crítico: La clase WhatWebService genera, lee y borra un archivo temporal por cada escaneo. Esto genera una fricción innecesaria de I/O en el disco, especialmente en entornos de contenedores o despliegues rápidos.

    Mejora: Utilizar el flujo de stdout directo de execa para parsear el JSON en memoria. Solo se debería recurrir a archivos temporales si el output de la herramienta externa supera el buffer de memoria del sistema.

3. Validación de Protocolo y Redirecciones

    Punto Crítico: analyzeHeaders utiliza redirect: "follow". Si bien es útil para llegar al destino final, podrías estar perdiendo información valiosa sobre cabeceras de seguridad o servidores intermedios (como balanceadores de carga) que solo aparecen en el primer salto.

    Mejora: Capturar el rastro de redirecciones o realizar un chequeo previo del certificado SSL/TLS para identificar configuraciones erróneas en el protocolo HTTPS de las municipalidades.

4. Enriquecimiento de Datos de Seguridad

    Punto Crítico: El objeto security solo chequea la presencia de cabeceras.

    Mejora: Validar el contenido de dichas cabeceras. Una cabecera Content-Security-Policy mal configurada (ej. unsafe-inline) es casi tan peligrosa como no tenerla.

🚀 Próximos Pasos (Roadmap Técnico)

    [ ] Paralelización Controlada: Migrar el bucle for a un sistema de colas con concurrencia limitada para reducir el tiempo total de ejecución sin comprometer el sigilo.

    [ ] Parser de Memoria: Refactorizar WhatWebService para procesar JSON desde el buffer de salida, eliminando la dependencia de archivos temporales en /tmp.

    [ ] Mapeo de Versiones a CVEs: Preparar la estructura http_stack para que la Fase 4 pueda cruzar automáticamente las versiones detectadas con bases de datos de vulnerabilidades conocidas.
