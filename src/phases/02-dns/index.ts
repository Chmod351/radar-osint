import {getMetadata,httpCheck,classifyTarget,domainResolver} from './resolver.ts'
import {enrichWithASN} from './ansLookup.ts'
import  {whoisController} from './whois.ts'
import type { AnalyzedTarget } from "../../shared/types";


export async function dnsPhase(allDomains: string[]) {
  console.log("iniciando fase dns")
  
  const domainsResolved = await domainResolver(allDomains);
  const domainsWithASN = await enrichWithASN(domainsResolved);
  const httpUrls = await httpCheck(domainsResolved);
  const metadata = await getMetadata(httpUrls);

  // 1. Clasificación rápida para armar la cola de trabajo
  const preReport= domainsWithASN.map(domain => {
    const webData = metadata.find(m => m.input === domain.host || m.url?.includes(domain.host));

    const baseData = {
      host: domain.host,
      ip: domain.ip,
      asn: domain.asn,
      asn_owner: domain.prefix,
      country: domain.country,
      url: webData?.url || `http://${domain.host}`,
      status_code: webData?.status_code || 0,
      title: webData?.title || "N/A",
      webserver: webData?.webserver || "N/A",
      cdn: webData?.webserver?.toLowerCase().includes("cloudflare") ? "cloudflare" : "none"
    };

    return classifyTarget(baseData) as AnalyzedTarget
  });
  
    await whoisController(preReport);
  console.log("--FASE 2 TERMINADA");
  return preReport;
}
