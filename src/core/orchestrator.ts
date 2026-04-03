import { reconPhase } from "../phases/01-recon";
import { dnsPhaseStream } from "../phases/02-dns";
import { fingerprintPhase } from "../phases/03-http";
// import { analysisPhase } from "../phases/04-analysis";
import {dashboard}from "../ui/dashboard.ts";
import { dataSaver,TARGET}from "../shared/utils.ts";
// import { normalizeTarget } from "../shared/urlNormalizer.ts";


import { logger } from "../shared/errorLogger.ts";

export class Orchestrator {

  async start(target: string) {
    logger.info("ORCHESTRATOR", `Radar activado para: ${target}`);
    const finalResults: any[] = [];

    try {
      // 1. Iniciamos la canilla de subdominios
       const subdomainStream = reconPhase(target);
       console.log(1)
      const infraStream = dnsPhaseStream(subdomainStream);
      console.log(2)
      const enrichedStream = fingerprintPhase(infraStream);
console.log(3)

      logger.info("ORCHESTRATOR", "Pipeline conectado. Consumiendo datos en tiempo real...");

      // 2. CONSUMO FINAL: El 'for await' es el motor que succiona los datos
      // Cada 'fullTarget' que llega acá ya pasó por Recon, DNS, ASN, Whois y HTTP.
 // Corregimos la lógica de recolección de resultados
      for await (const result of enrichedStream) {
        if (result) {
          console.log(result)
          finalResults.push(result);
          // Opcional: Update UI en tiempo real aquí si dashboard lo soporta
        }
      }

      logger.info("ORCHESTRATOR", `Escaneo finalizado. Total objetivos: ${finalResults.length}`);

      // 3. Persistencia y Visualización
      if (finalResults.length > 0) {
        await dataSaver(finalResults);
      dashboardRender(finalResults, target)
      } else {
        logger.error("ORCHESTRATOR", "No se obtuvieron resultados válidos para mostrar.");
        return dashboard([]); 
      }

    } catch (e) {
      logger.error("ORCHESTRATOR", "Fallo crítico en la cadena de mando", e);
    }
  }
}

async function dashboardRender(finalResults:any,target:any) {


    // CAPA DE ADAPTACIÓN: Transformamos la data cruda para la UI
    const viewData = finalResults.map(target => {
        const hasPorts = target.open_ports && target.open_ports.length > 0;
        const isWebAlive = target.status_code > 0 && target.status_code < 500;
        
        // Unimos la lógica: Si respeta puertos o web, es prioridad
        const isHighPriority = hasPorts || isWebAlive || target.priority === "HIGH";

        return {
            ...target, // Mantenemos todo el objeto original por las dudas
            host: target.host,
            
            // Forzamos el formato que el dashboard.ts espera leer
            priority: isHighPriority ? "🔴 HIGH" : "⚪ LOW",
            
            // Si HTTP falló pero hay puertos, no mostramos "ERR", mostramos "PORT-ALIVE"
            status: (target.status_code === 0 && hasPorts) ? "PORT-OP" : (target.status_code || "DEAD"),
            
            // Mapeamos infra_type (de tu objeto) a infra_status (del dashboard)
            infra_status: target.infra_type === "P/Self-H" ? "🔍 R-MANUAL" : "🛡️ WAF/CLOUD",
            
            // Traducimos los puertos detectados a la columna 'app'
            app_status: hasPorts 
                ? `🛠️ ${target.open_ports.map((p: any) => p.port).join(",")}` 
                : "✅ STANDALONE",
                
            // HSTS y Server (Fallback si no hay data web pero sí puertos)
            server: target.webserver !== "N/A" ? target.webserver : (hasPorts ? "Service-Open" : "???"),
            cdn: target.cdn || "none"
        };
    });

    return dashboard(viewData);
}


async function main(target: string) {
  const orchestrator = new Orchestrator();
  try {
    await orchestrator.start(target);
  } catch (error) {
    logger.error("MAIN", "Fallo catastrófico", error);
    process.exit(1);
  }
}

if (TARGET) {
  main(TARGET);
}
