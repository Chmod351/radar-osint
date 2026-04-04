import { reconPhase } from "../phases/01-recon/index-recon.ts";
import { dnsPhaseStream } from "../phases/02-dns/index-dns.ts";
import { fingerprintingPhase } from "../phases/03-http/index-http.ts";
import { getErrorMessage, OP_DIR, TARGET } from "../shared/utils.ts";
import { logger } from "../shared/errorLogger.ts";
import { dashboard } from "../ui/dashboard.ts";
import type { AnalyzedTarget } from "../shared/types.ts";
import { normalizeTarget } from "../shared/helper.ts";

export class Orchestrator {
  // por defecto 15
  private concurrencyLimit =  2;

  async start(target: string) {
    const finalResults: AnalyzedTarget[] = [];
    const activeWorkers = new Set<Promise<void>>();
    logger.info("ORQUESTADOR", "iniciando....");
    // Fase 1: Sigue siendo un Stream (la fuente)
    const subdomainStream = reconPhase(target);
    console.log(subdomainStream);
    for await (const sub of subdomainStream) {
      if (activeWorkers.size >= this.concurrencyLimit) {
        await Promise.race(activeWorkers);
      }
      const worker = (async () => {
        try {
          // LLAMADA ATÓMICA 1: DNS/ASN/WHOIS
          const analyzed = await dnsPhaseStream(sub);
          let normalized:AnalyzedTarget=normalizeTarget(analyzed);



          if (normalized) {
            if (normalized.action !== "DUPLICATE_ALIAS" &&  normalized.action !=="SCAN_FAILED") {
            // LLAMADA ATÓMICA 2: HTTP/NMAP
              const fullyEnriched = await fingerprintingPhase(normalized);
              if (fullyEnriched) {
                normalized=normalizeTarget(fullyEnriched);
                finalResults.push(normalized);
                logger.info("ORCHESTADOR", `Target completado: ${sub}`);
              }
            } else {
              finalResults.push(normalized);
              logger.info("ORCHESTADOR", `Omitiendo escaneo profundo para : ${sub}`);
            }
          }
        } catch (e:unknown) {
          logger.error("ORQUESTADOR",getErrorMessage(e) );
        }
      })();

      activeWorkers.add(worker);
      worker.finally(() => activeWorkers.delete(worker));
    }

    await Promise.all(activeWorkers);
    console.log(finalResults);
    console.log(`\n[🏁] ESCANEO FINALIZADO. Objetivos: ${finalResults.length}`);
    const path = `${OP_DIR}/${TARGET}.json`;

    logger.warn(`[💾] Guardando ${finalResults.length} objetivos en ${path}...`, "<----");

    const normalizedFinalData = finalResults.map(target => normalizeTarget(target));
    await Bun.write(Bun.file(path), JSON.stringify(normalizedFinalData,null,2));
    return dashboard(normalizedFinalData);
  }
}





async function main(target:string) {
 
  const orchestrator = new Orchestrator(); 
  try {
    // ACÁ ES DONDE SUCEDE LA MAGIA
    await orchestrator.start(target);
  } catch (error) {
    logger.error("ORQUESTADOR:",`ERROR AL INTENTAR EJECUTAR EL ORQUESTADOR ${error}`);
    process.exit(1);
  }
}

// Ejecutamos
//
if (TARGET) {
   
  main(TARGET);

}
