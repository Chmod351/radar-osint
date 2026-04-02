import { resolveSingleDomain, enrichWebData, classifyTarget } from "./resolver.ts";
import { getASNInfo } from "./ansLookup.ts";
import { getWhoisIntel } from "./whois.ts";
import { withRetry } from "../../shared/retry.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget } from "../../shared/types.ts";

/**
 * PROCESADOR INDIVIDUAL DE TARGETS
 * Esta función es la "unidad de trabajo" del Radar.
 * Se encarga de transformar un string (subdominio) en un objeto analizado completo.
 */
async function processTarget(subdomain: string): Promise<AnalyzedTarget | null> {
  console.log(subdomain,".----------> target")
  try {
    // 1. RESOLUCIÓN DNS (Paso crítico inicial)
    // Usamos retry porque un fallo DNS temporal mataría el target sin razón.
    logger.debug("fase 2", "iniciando .....")
    const resolved = await withRetry(`DNS:${subdomain}`, () => resolveSingleDomain(subdomain));
    console.log(resolved,"resolvedddddd")
    if (!resolved || resolved.ip === "0.0.0.0") {
      return null; // Si no hay IP, no hay nada que escanear
    }

    // 2. ENRIQUECIMIENTO EN PARALELO (ASN y WEB)
    // Ejecutamos ASN y HTTP al mismo tiempo para ganar velocidad.
    logger.debug("iniciando servicio paralelo", " asninfo y webinfo")
    const [asnInfo, webInfo] = await Promise.all([
      withRetry(`ASN:${resolved.ip}`, () => getASNInfo(resolved.ip)),
      withRetry(`WEB:${subdomain}`, () => enrichWebData(subdomain))
    ]);

    // 3. CONSOLIDACIÓN INICIAL Y CLASIFICACIÓN
    const baseData = {
      ...resolved,
      ...asnInfo,
      ...webInfo,
      asn_owner: asnInfo.prefix // Adaptación para el clasificador
    };
logger.debug("iniciando en analyzed", "pasando a clasificador")
    const analyzed = classifyTarget(baseData) as AnalyzedTarget;
console.log(analyzed)
    // 4. WHOIS TÁCTICO (Solo si es un target de interés)
    // El Whois es lento, solo lo disparamos si el clasificador dice que es SCAN_READY
    if (analyzed.action === "SCAN_READY") {
      try {
        // getWhoisIntel ya maneja su propia caché interna por root domain
        logger.debug("WHOIS", "disparando whois")
        analyzed.whois = await withRetry(`Whois:${subdomain}`, () => getWhoisIntel(subdomain));
      } catch (e) {
        logger.debug("WHOIS", `Fallo definitivo en Whois para ${subdomain} tras reintentos.`);
      }
    }

    return analyzed;

  } catch (error: any) {
    logger.error("PHASE-02", `Error procesando ${subdomain}: ${error.message}`);
    return null;
  }
}

/**
 * ENTRADA PRINCIPAL DE LA FASE 2
 * Transforma un flujo de subdominios en un flujo de targets analizados.
 * * @param subdomainStream - Iterador asincrónico que viene de la Fase 1
 */
export async function* dnsPhaseStream(subdomainStream: AsyncIterable<string>): AsyncGenerator<AnalyzedTarget> {
  logger.info("PHASE-02", "Iniciando pipeline de análisis DNS/ASN/Whois...");

  for await (const subdomain of subdomainStream) {
    // Procesamos el target actual
    const result = await processTarget(subdomain);

    // Si el proceso fue exitoso, lo emitimos (yield) para la siguiente fase
    if (result) {
      yield result;
    }
  }

  logger.info("PHASE-02", "Pipeline de Fase 2 completado.");
}
