import { getWebIntel } from "./client.ts";
import { scanPorts } from "./portsScan.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget } from "../../shared/types";

/**
 * CONFIGURACIÓN DE RENDIMIENTO
 * MAX_CONCURRENT: Cuántos hosts procesamos en paralelo. 
 * No queremos saturar la red ni que nos bloqueen por ruido excesivo.
 */

export async function fingerprintingPhase(target: AnalyzedTarget): Promise<AnalyzedTarget> {
  const host = target.host;

  try {
    // Disparamos las 3 consultas en paralelo para este host específico
    const [httpData, openPorts] = await Promise.all([
      getWebIntel(target.url),
      scanPorts(host)
    ]);
    
    logger.debug("HTTPDATA", JSON.stringify(httpData))
    logger.debug("OPENPORTS", JSON.stringify(openPorts))
    logger.debug("TARGET", JSON.stringify(target))
    return {
      ...target,
      http_intel: httpData.http_intel,
      http_stack: httpData.http_stack,
      open_ports: openPorts || [],
      phase: 3 // Marcamos que pasó la fase de fingerprinting
    };
  } catch (error: any) {
    logger.error("PHASE-03", `Fallo crítico analizando ${host}: ${error.message}`);
    return { ...target, error: "Fingerprinting failed" };
  }
}
