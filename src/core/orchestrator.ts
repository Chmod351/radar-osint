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
      const infraStream = dnsPhaseStream(subdomainStream);
      const enrichedStream = fingerprintPhase(infraStream);


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
        return dashboard(finalResults);
      } else {
        logger.error("ORCHESTRATOR", "No se obtuvieron resultados válidos para mostrar.");
        return dashboard([]); 
      }

    } catch (e) {
      logger.error("ORCHESTRATOR", "Fallo crítico en la cadena de mando", e);
    }
  }
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
