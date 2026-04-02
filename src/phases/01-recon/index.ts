import { logger } from "../../shared/errorLogger.ts";
import {streamAllSubdomains} from "./subdomainFinder.ts";

export function reconPhase(target:string){
  logger.debug("recon iniciando", `${target}`)
  return streamAllSubdomains(target); 
}
