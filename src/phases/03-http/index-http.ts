import { getWebIntel } from "./client.ts";
import {  scanPortsSafe } from "./portsScan.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget, HttpIntel } from "../../shared/types";
import { normalizeHttpIntel } from "../../shared/helper.ts";
import { getErrorMessage } from "../../shared/utils.ts";


export const normalizedIntel: HttpIntel={
  protocol:"Unknown",
  status:0,
  security:{
    hsts:false,
    csp:false,
    xfo:false,
    nosniff:false,
  },server:"Unknown",
  poweredBy:"Unknown",
  cookies:"N/A",
  error:"",
};
export async function fingerprintingPhase(target: AnalyzedTarget): Promise<AnalyzedTarget> {
  const host = target.host;

  try {
    // Disparamos las 2 consultas en paralelo para este host específico
    const [httpData, openPorts] = await Promise.all([
      getWebIntel(target.url),
      scanPortsSafe(host),
    ]);
    
    const httpIntelNormalized=normalizeHttpIntel(httpData.http_intel as HttpIntel);
    return {
      ...target,
      http_intel: httpIntelNormalized || normalizedIntel,
      http_stack: httpData.http_stack,
      open_ports: openPorts || [],
    };
  } catch (error: unknown) {
    logger.error("PHASE-03", getErrorMessage(error));

    return { ...target,
      http_intel:{ ...normalizedIntel,
        error:getErrorMessage(error)?? "Fallo el fingerprinting", 
      },
      http_stack:target.http_stack,
      open_ports:target.open_ports, 
    };
  }
}
