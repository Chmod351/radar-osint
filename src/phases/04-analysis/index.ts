import { logger } from "../../shared/errorLogger.ts"; 
import { httpPhaseAndVulnerabilityPhaseMerger } from "./vulnScanner.ts";

export async function analysisPhase(webAssets: any[]) {
  logger.info("PHASE 4:", "Fase 4 iniciada...");
  // USAMOS MAP + PROMISE.ALL PARA PROCESAR TODO EL ARRAY
  const finalReport = await Promise.all(
    webAssets.map(async (asset) => {
      // Llamamos al merger para CADA asset
      return await httpPhaseAndVulnerabilityPhaseMerger(asset);
    }),
  );

 
  logger.info("PHASE 4:",  "Fase 4 terminada ");
  return finalReport; 
}
