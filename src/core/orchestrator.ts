import { reconPhase } from "../phases/01-recon";
import { dnsPhaseStream } from "../phases/02-dns";
import { httpPhase } from "../phases/03-http";
import { analysisPhase } from "../phases/04-analysis";
import {dashboard}from "../ui/dashboard.ts";
import { dataSaver,TARGET}from "../shared/utils.ts";
import { normalizeTarget } from "../shared/urlNormalizer.ts";


import { logger } from "../shared/errorLogger.ts";
import { start } from "repl";

export class Orchestrator {
  private concurrencyLimit = 15;

  async start(target: string) {
    logger.info("ORCHESTRATOR", `Radar activado para: ${target}`);
    const finalResults: any[] = [];

    try {
      // 1. Iniciamos la canilla de subdominios
      const subdomainStream = reconPhase(target);
      const analyzedTargets = dnsPhaseStream(subdomainStream);

      const activeWorkers = new Set<Promise<void>>();

      for await (const target of analyzedTargets ) {
        if (activeWorkers.size >= this.concurrencyLimit) {
          await Promise.race(activeWorkers);
        }

        // El worker ahora llama a una cadena de funciones de "index"
        const worker = this.processRestOfPipeline(target, finalResults).finally(() => {
          activeWorkers.delete(worker);
        });

        activeWorkers.add(worker);
      }

      await Promise.all(activeWorkers);
      
      await dataSaver(finalResults);
      return dashboard(finalResults);

    } catch (e) {
      logger.error("ORCHESTRATOR", "Fallo crítico en la cadena de mando", e);
    }
  }

  /**
   * PIPELINE DE FASES
   * Aquí el orquestador solo delega a los "index" de cada fase.
   * Cada fase recibe un array de 1 elemento para mantener compatibilidad.
   */
  private async processRestOfPipeline(target:any,results:any[]) {
    try {
      // Aquí vendrían las llamadas a Fase 3 y 4
      // Ejemplo: 
      // const webData = await httpPhaseAtómico(target);
      // const report = await analysisPhaseAtómico(webData);
      
      results.push(target); 
      logger.debug("PIPELINE", `Finalizado: ${target.host}`);
    } catch (e) {
      logger.error("PIPELINE", `Error en fases finales para ${target.host}`, e);
    }  }
}


async function main(target:string) {
  
  const orchestrator = new Orchestrator();

  try {
    // El método start es público, así que accedemos directamente
    await orchestrator.start(target);
  } catch (error) {
    logger.error("MAIN", "Fallo catastrófico en la ejecución del Radar", error);
    process.exit(1);
  }
}

if (TARGET) {
  main(TARGET);
}

