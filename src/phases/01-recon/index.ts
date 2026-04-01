import {getAllSubdomains} from "./subdomainFinder.ts"

export async function subDomainsPhase(target:string){
const subdomains= await getAllSubdomains(target)
return subdomains
}
