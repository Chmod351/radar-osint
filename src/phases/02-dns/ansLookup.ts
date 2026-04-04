import { resolveTxt } from "node:dns/promises";
import { logger } from "../../shared/errorLogger.ts";
import { getErrorMessage } from "../../shared/utils.ts";


export interface ASNIntel {
  asn: string;
  prefix: string;
  country: string;
}


export async function getASNInfo(ip: string): Promise<ASNIntel> {
  // Validamos IP básica para evitar consultas basura
  if (!ip || ip === "0.0.0.0") {
    return { asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" };
  }

  const revIp = ip.split(".").reverse().join(".");
  const query = `${revIp}.origin.asn.cymru.com`;

  try {
    // Timeout implícito de node:dns/promises
    const records = await resolveTxt(query); 
    const firstEntry = records?.[0]?.[0];

    if (firstEntry) {
      const parts = firstEntry.split("|").map(p => p.trim());
      return {
        asn: parts[0] ? `AS${parts[0]}` : "AS_UNKNOWN",
        prefix: parts[1] || "Unknown",
        country: parts[2] || "Unknown",
      };
    }
  } catch (e: unknown) {
    // Si el error es NXDOMAIN, la IP no tiene ASN asociado 
    logger.info("ASN-LOOKUP", getErrorMessage(e));
  }

  return { asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" };
}


