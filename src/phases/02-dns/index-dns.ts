import { resolveSingleDomain, enrichWebData, classifyTarget } from "./resolver.ts";
import { getASNInfo } from "./ansLookup.ts";
import { getWhoisIntel } from "./whois.ts";
import { withRetry } from "../../shared/retry.ts";
import type { AnalyzedTarget } from "../../shared/types.ts";
import { logger } from "../../shared/errorLogger.ts";
import { getErrorMessage } from "../../shared/utils.ts";

// Agregamos un límite para la Fase 2 también, para que sea rápida

export async function dnsPhaseStream(subdomain: string): Promise<AnalyzedTarget | null> {
  try {
    const resolved = await withRetry(`DNS:${subdomain}`, () => resolveSingleDomain(subdomain));
    if (!resolved || resolved.ip === "0.0.0.0") return null;

    const [asnInfo, webInfo] = await Promise.all([
      withRetry(`ASN:${resolved.ip}`, () => getASNInfo(resolved.ip)),
      withRetry(`WEB:${subdomain}`, () => enrichWebData(subdomain)),
    ]);

    const baseData = {
      ...resolved,
      ...webInfo,
      asn: asnInfo.asn,
      asn_owner: asnInfo.prefix,
    };

    const analyzed = classifyTarget(baseData) as AnalyzedTarget;

    if (analyzed.action === "SCAN_READY") {
      analyzed.whois = await withRetry(`Whois:${subdomain}`, () => getWhoisIntel(subdomain));
    }

    return analyzed;
  } catch (error: unknown) {
    logger.error("DNS-PHASE", getErrorMessage(error));
    return null;
  }
}

