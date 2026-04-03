import { reconPhase } from "../phases/01-recon/index-recon.ts";
import { dnsPhaseStream } from "../phases/02-dns/index-dns.ts";
import { fingerprintingPhase } from "../phases/03-http/index-http.ts";
import { TARGET } from "../shared/utils.ts";
import { logger } from "../shared/errorLogger.ts";
import { dashboard } from "../ui/dashboard.ts";

export class Orchestrator {
  private concurrencyLimit = 15;

  async start(target: string) {
    const finalResults: any[] = [];
    const activeWorkers = new Set<Promise<void>>();
logger.info("ORQUESTADOR", "iniciando....")
    // Fase 1: Sigue siendo un Stream (la fuente)
    const subdomainStream = reconPhase(target);
console.log(subdomainStream)
    for await (const sub of subdomainStream) {
      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }

      const worker = (async () => {
        try {
          // LLAMADA ATÓMICA 1: DNS/ASN/WHOIS
          const analyzed = await dnsPhaseStream(sub);
          
          if (analyzed) {
            // LLAMADA ATÓMICA 2: HTTP/NMAP
            const fullyEnriched = await fingerprintingPhase(analyzed);
            
            if (fullyEnriched) {
              finalResults.push(fullyEnriched);
              logger.info("ORCHESTRATOR", `Target completado: ${sub}`);
            }
          }
        } catch (e) {
          logger.error("WORKER", `Error en pipeline para ${sub}: ${e}`);
        }
      })();

      activeWorkers.add(worker);
      worker.finally(() => activeWorkers.delete(worker));
    }

    await Promise.all(activeWorkers);
    console.log(finalResults)
    console.log(`\n[🏁] ESCANEO FINALIZADO. Objetivos: ${finalResults.length}`);
    return dashboard(finalResults);
  }
}
async function main(target:string) {
 
  const orchestrator = new Orchestrator(); 
  try {
    // ACÁ ES DONDE SUCEDE LA MAGIA
    await orchestrator.start(target);
  } catch (error) {
    console.error("💥 Fallo crítico en el arranque:", error);
    process.exit(1);
  }
}

// Ejecutamos
//
 if (TARGET) {
   
main(TARGET);

  }
