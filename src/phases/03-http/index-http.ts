import { getWebIntel } from "./client.ts";
import {  scanPortsSafe } from "./portsScan.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget } from "../../shared/types";


export async function fingerprintingPhase(target: AnalyzedTarget): Promise<AnalyzedTarget> {
  const host = target.host;

  try {
    // Disparamos las 2 consultas en paralelo para este host específico
    const [httpData, openPorts] = await Promise.all([
      getWebIntel(target.url),
      await scanPortsSafe(host),
    ]);
    
    return {
      ...target,
      http_intel: httpData.http_intel,
      http_stack: httpData.http_stack,
      open_ports: openPorts || [],
      phase: 3, 
    };
  } catch (error: any) {
    logger.error("PHASE-03", `Fallo crítico analizando ${host}: ${error.message}`);
    return { ...target, error: "Fingerprinting failed" };
  }
}
