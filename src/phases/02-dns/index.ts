import { resolveSingleDomain, enrichWebData, classifyTarget } from "./resolver.ts";
import { getASNInfo } from "./ansLookup.ts";
import { getWhoisIntel } from "./whois.ts";
import { withRetry } from "../../shared/retry.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget } from "../../shared/types.ts";

// Agregamos un límite para la Fase 2 también, para que sea rápida
const DNS_CONCURRENT = 10; 

async function processTarget(subdomain: string): Promise<AnalyzedTarget | null> {
  try {
    const resolved = await withRetry(`DNS:${subdomain}`, () => resolveSingleDomain(subdomain));
    if (!resolved || resolved.ip === "0.0.0.0") return null;

    const [asnInfo, webInfo] = await Promise.all([
      withRetry(`ASN:${resolved.ip}`, () => getASNInfo(resolved.ip)),
      withRetry(`WEB:${subdomain}`, () => enrichWebData(subdomain))
    ]);

    const baseData = {
      ...resolved,
      ...webInfo,
      asn: asnInfo.asn,
      asn_owner: asnInfo.prefix,
      phase: 2
    };

    const analyzed = classifyTarget(baseData) as AnalyzedTarget;

    if (analyzed.action === "SCAN_READY") {
      analyzed.whois = await withRetry(`Whois:${subdomain}`, () => getWhoisIntel(subdomain));
    }

    return analyzed;
  } catch (error: any) {
    return null;
  }
}

export async function* dnsPhaseStream(subdomainStream: AsyncIterable<string>): AsyncGenerator<AnalyzedTarget> {
  logger.info("PHASE-02", "Iniciando análisis DNS/ASN con workers internos...");
  
  const workers = new Set<Promise<AnalyzedTarget | null>>();

  for await (const subdomain of subdomainStream) {
    if (workers.size >= DNS_CONCURRENT) {
      const finished = await Promise.race(workers);
      workers.delete(finished);
      if (finished) yield finished;
    }

    const worker = processTarget(subdomain);
    workers.add(worker);
    worker.then(() => workers.delete(worker));
  }

  // Limpieza final
  const results = await Promise.all(workers);
  for (const res of results) {
    if (res) yield res;
  }
}
