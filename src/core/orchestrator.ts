import { reconPhase } from "../phases/01-recon/index-recon.ts";
import { dnsPhaseStream } from "../phases/02-dns/index-dns.ts";
import { fingerprintingPhase } from "../phases/03-http/index-http.ts";


import { logger } from "../shared/errorLogger.ts";
import { dashboard } from "../ui/dashboard.ts";

export class Orchestrator {
  private concurrencyLimit = 15;

  async start(target: string) {
    const finalResults: any[] = [];
    const activeWorkers = new Set<Promise<void>>();

    // 1. Fase 1: Recibimos el AsyncIterable de subdominios
    const subdomainStream = reconPhase(target);

    for await (const sub of subdomainStream) {
      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }

      // Creamos un worker que procesa el target por todas las fases
      const worker = (async () => {
        try {
          // 2. Fase 2: DNS + ASN + WHOIS (Usa tu processTarget de index-dns.ts)
          const analyzed = await dnsPhaseStream(sub);
          
          if (analyzed) {
            // 3. Fase 3: HTTP + Nmap (Usa tu processTarget de index-http.ts)
            // Renombramos la importación para evitar conflicto
            const fullyEnriched = await fingerprintingPhase(analyzed);
            
            if (fullyEnriched) {
              finalResults.push(fullyEnriched);
              logger.info("ORCHESTRATOR", `Target completado: ${sub}`);
            }
          }
        } catch (e) {
          logger.error("WORKER", `Error en pipeline para ${sub}: ${e}`);
        }
      })().finally(() => activeWorkers.delete(worker));

      activeWorkers.add(worker);
    }

    await Promise.all(activeWorkers);
    return dashboard(finalResults)
  }
}
 
