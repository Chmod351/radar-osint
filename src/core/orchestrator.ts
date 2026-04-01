import { reconPhase } from "../phases/01-recon";
import { dnsPhase } from "../phases/02-dns";
import { httpPhase } from "../phases/03-http";
import { analysisPhase } from "../phases/04-analysis";
import {dashboard}from "../ui/dashboard.ts"
import { dataSaver,TARGET}from "../shared/utils.ts"
import {normalizeTarget}from "../shared/urlNormalizer.ts"


 
async function runRadar(target: string) {
  try{
  // Fase 1: ¿Qué hay afuera?
  const subdomains = await reconPhase(target);

  // Fase 2: ¿Dónde viven? (IPs + ASN)
  const infrastructure = await dnsPhase(subdomains);

  // Fase 3: ¿Qué corre ahí? (HTTP + Tech Stack)
  const webAssets = await httpPhase(infrastructure);

  // Fase 4: ¿Es peligroso? (Vulns + Clasificación)
  const finalReport = await analysisPhase(webAssets);

  await dataSaver(finalReport)
  return dashboard(finalReport)
  }catch(e){
   console.log(e)
  }
}

if (TARGET){
runRadar(normalizeTarget(TARGET))
}
