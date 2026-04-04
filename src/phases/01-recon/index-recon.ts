import { logger } from "../../shared/errorLogger.ts";
import { streamAllSubdomains } from "./subdomainFinder.ts";

export function reconPhase(target:string){
  logger.info("PHASE-01",`Iniciando reconocimiento de subdominios para ${target}`);
  const domains= streamAllSubdomains(target); 
  return domains;
}
