import { reconPhase } from "../phases/01-recon";
import { dnsPhase } from "../phases/02-dns";
import { httpPhase } from "../phases/03-http";
import { analysisPhase } from "../phases/04-analysis";
import {dashboard}from "../ui/dashboard.ts";
import { dataSaver,TARGET}from "../shared/utils.ts";
import { normalizeTarget } from "../shared/urlNormalizer.ts";


import { logger } from "../shared/errorLogger.ts";

export class Orchestrator {
  private concurrencyLimit = 15;

  async start(target: string) {
    logger.info("ORCHESTRATOR", `Radar activado para: ${target}`);
    const finalResults: any[] = [];

    try {
      // 1. Iniciamos la canilla de subdominios
      const subdomainStream = reconPhase(target);
      const activeWorkers = new Set<Promise<void>>();

      for await (const subdomain of subdomainStream) {
        if (activeWorkers.size >= this.concurrencyLimit) {
          await Promise.race(activeWorkers);
        }

        // El worker ahora llama a una cadena de funciones de "index"
        const worker = this.processPipeline(subdomain, finalResults).finally(() => {
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
  private async processPipeline(domain: string, results: any[]) {
    try {
      const singleTargetArray = [domain];

      // Fase 2: DNS & Infra (Llamada al index de la fase 02)
      const infrastructure = await dnsPhase(singleTargetArray);
      if (!infrastructure || infrastructure.length === 0) return;

      // Fase 3: HTTP & Fingerprinting (Llamada al index de la fase 03)
      const webAssets = await httpPhase(infrastructure);
      if (!webAssets || webAssets.length === 0) return;

      // Fase 4: Análisis de Vulnerabilidades (Llamada al index de la fase 04)
      const finalReport = await analysisPhase(webAssets);
      
      // Guardamos el resultado atómico
      if (finalReport && finalReport.length > 0) {
        results.push(finalReport[0]);
      }

      logger.debug("PIPELINE", `Flujo completado para: ${domain}`);
    } catch (e) {
      logger.error("PIPELINE", `Error en el flujo de ${domain}`, e);
    }
  }
}




