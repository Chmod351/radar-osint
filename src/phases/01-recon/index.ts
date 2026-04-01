import {getAllSubdomains} from "./subdomainFinder.ts"

export async function reconPhase(target:string){
  console.log("entrando en recon...")
const subdomains= await getAllSubdomains(target)
console.log("--FASE 1 : TERMINADA")
return subdomains
}
