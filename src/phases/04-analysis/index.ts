import { httpPhaseAndVulnerabilityPhaseMerger } from "./vulnScanner.ts";

export async function analysisPhase(webAssets: any[]) {
  console.log("iniciando fase 4");

  // USAMOS MAP + PROMISE.ALL PARA PROCESAR TODO EL ARRAY
  const finalReport = await Promise.all(
    webAssets.map(async (asset) => {
      // Llamamos al merger para CADA asset
      return await httpPhaseAndVulnerabilityPhaseMerger(asset);
    })
  );

  console.log("-- FASE 4 TERMINADA --");
  return finalReport; // ESTO garantiza que sea un Array para el dashboard
}
