import { execa } from "execa";
import { logger } from "../../shared/errorLogger.ts";
import { CDN_PROVIDERS, getErrorMessage, SENSORS } from "../../shared/utils.ts";
import type { AnalyzedTarget } from "../../shared/types.ts";
import { emptyWhois } from "./whois.ts";


export interface ResolvedDomain {
  host: string;
  ip: string;
}

export interface WebMetadata {
  url: string;
  status_code: number;
  title: string|null;
  webserver: string |null;
  cdn: number | null;
}

/**
 * 1. RESOLVER DOMINIO 
 * Recibe UN dominio, devuelve host e ip.
 */

const globalFingerprints= new Set<string>();
export async function resolveSingleDomain(domain: string): Promise<ResolvedDomain | null> {
  try {
    // Ejecución directa para un solo target.
    const { stdout } =await execa("dnsx", [
      "-json",
      "-silent",
      "-nc",
      "-a",
      "-resp"],
    { input:domain,
      timeout: 10000 });

    if (!stdout.trim()) return null;

    const data = JSON.parse(stdout);
    return {
      host: data.host,
      ip: data.a?.[0] || "0.0.0.0",
    };
  } catch (e:unknown) {
    logger.error("RESOLVER-SINGLE-DOMAIN", getErrorMessage(e));
    // No logueamos error aquí para no ensuciar si el dominio simplemente no existe
    return null;
  }
}

/**
 * 2. ENRIQUECIMIENTO WEB 
 * Valida HTTP y obtiene metadata en un solo paso.
 */
export async function enrichWebData(host: string): Promise<WebMetadata> {
  try {
    const { stdout } = await execa("httpx-toolkit", [
      "-silent",
      "-no-color",
      "-title",
      "-web-server",
      "-status-code",
      // "-threads",
      "-json",
      // "50",
    ], { input:host, 
      timeout: 20000 });

    if (!stdout.trim()) throw new Error("No web response");

    const data = JSON.parse(stdout);
   

    let cdn: number = CDN_PROVIDERS.NONE;
    const serverHeader = (data.web_server || data.server || "").toLowerCase();

    // 2. Mapeo de firmas (Fácil de expandir)
    const signatures: Record<string, number> = {
      "cloudflare": CDN_PROVIDERS.CLOUDFLARE,
      "akamai":     CDN_PROVIDERS.AKAMAI,
      "cloudfront": CDN_PROVIDERS.CLOUDFRONT,
      "fastly":     CDN_PROVIDERS.FASTLY,
      "incapsula":  CDN_PROVIDERS.INCAPSULA,
      "sucuri":     CDN_PROVIDERS.UNKNOWN_CDN, 
    };

    // Buscamos la firma en el header 'server'
    for (const [key, value] of Object.entries(signatures)) {
      if (serverHeader.includes(key)) {
        cdn = value;
        break; 
      }
    }


    
    
    return {
      url: data.url || `http://${host}`,
      // Manejo de discrepancias entre versiones de httpx-toolkit
      status_code: data.status_code || data["status-code"] || 0,
      title: data.title || "N/A",
      webserver: data.web_server || data.server || data.webserver || "N/A",
      cdn: cdn,
    };  } catch (e) {
    // Fallback: Si falla el escaneo profundo, devolvemos lo básico
    logger.error("ENRICH", `${host} fallo con error: ${e}, mandando fallback`);
    return {
      url: `http://${host}`,
      status_code: 0,
      title: "N/A",
      webserver: "N/A",
      cdn: CDN_PROVIDERS.NONE,
    };
  }
}

/**
 * 3. CLASIFICADOR DE TARGET 
 *  para decidir qué hacer con el target.
 */
export function classifyTarget(domainData: AnalyzedTarget):AnalyzedTarget {
  const cloudKeywords = [
    "amazon", "google", "microsoft", "cloudflare", "akamai",
    "fastly", "ovh", "digitalocean", "linode", "vercel", "github",
  ];
 
  const fingerprint=`${domainData.ip}_${domainData.status_code}_${domainData.title}`;
  const asnOwner = domainData.asn_owner?.toLowerCase() || domainData.asn?.toLowerCase() || "";
  const isCloud = cloudKeywords.some(key => asnOwner.includes(key));

  if (globalFingerprints.has(fingerprint)) {
    return {
      ...domainData,
      priority:SENSORS.PRIORITY.LOW,
      infra_type:isCloud ? SENSORS.INFRA_TYPE.CLOUD: SENSORS.INFRA_TYPE.SELF_HOSTED,
      action:SENSORS.ACTION.DUPLICATE,
      whois:emptyWhois,
      vulnerabilities: [],
    };
    
  }
  globalFingerprints.add(fingerprint);

  return {
    ...domainData,
    priority: isCloud ? SENSORS.PRIORITY.LOW : SENSORS.PRIORITY.HIGH,
    infra_type: isCloud ? SENSORS.INFRA_TYPE.CLOUD: SENSORS.INFRA_TYPE.SELF_HOSTED,
    action: isCloud ? SENSORS.ACTION.SKIP : SENSORS.ACTION.READY,
    whois:emptyWhois,
    vulnerabilities: [],
  };
}
