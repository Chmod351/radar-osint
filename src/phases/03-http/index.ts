import {runHttpPhase}from './client.ts'
import type { AnalyzedTarget } from "../../shared/types";

export async function httpPhase(infrastructure:AnalyzedTarget[]){
  console.log("iniciando http fase")
const webAssets = await runHttpPhase(infrastructure)
console.log("--FASE 3 TERMINADA")
console.log(webAssets)
return webAssets
}
