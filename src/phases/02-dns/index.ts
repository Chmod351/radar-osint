import {getMetadata,httpCheck,classifyTarget,domainResolver} from './resolver.ts'
import {enrichWithASN} from './ansLookup.ts'



export async function dnsPhase(allDomains:string[]){

    const domainsResolved = await domainResolver(allDomains);
    // 3. Enriquecimiento con ASN (Usamos las IPs de domainsResolved)
    const domainsWithASN = await enrichWithASN(domainsResolved);

    // 4. Validación HTTP (Filtramos quién responde)
    const httpUrls = await httpCheck(domainsResolved);

    // 5. Metadata Detallada (Títulos, Servers, etc.)
    const metadata = await getMetadata(httpUrls);

  // 6. CLASIFICACIÓN Y FUSIÓN
    // Primero armamos el preReport
    const preReport = domainsWithASN.map(domain => {
      const webData = metadata.find(m =>
        m.input === domain.host ||
        m.url?.includes(domain.host)
      );

      // Armamos el objeto base
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

      // 7. Aplicamos la clasificación AQUÍ
      return classifyTarget(baseData);
    });
  return preReport
}
