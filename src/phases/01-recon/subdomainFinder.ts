import { execa } from "execa";
import {subfinder,assetfinder} from "../../shared/utils.ts";
/*  ========================= */
/* 1. buscamos subdominios */
/* ========================= */

async function runSubdomainFinderThroughApi(target: string) {
  try {
    const { stdout } = await execa(subfinder, ["-d", target, "-silent"]);
    return stdout.split("\n").filter(Boolean);
  } catch (e) {
    console.log(e);
  }
}

async function runSubdomainFinderThroughCertificates(target: string) {
  try {
    const { stdout } = await execa(assetfinder, ["--subs-only", target]);
    return stdout.split("\n").filter(Boolean);
  } catch (e) {
    console.log(e);
  }
}

// deduplica y arma la coleccion
export async function getAllSubdomains(target: string) {
  try{
  const res = await Promise.allSettled([
    runSubdomainFinderThroughApi(target),
    runSubdomainFinderThroughCertificates(target)
  ]);

  const allSubdomains = new Set<string>();

  res.forEach((result, index) => {
    if (result.status === "fulfilled" && result.value) {
      result.value.forEach(sub => allSubdomains.add(sub));
      console.log(`[+] Fuente ${index === 0 ? "Subfinder" : "Assetfinder"} completada.`);
    } else {

      console.error(`[-] Fuente ${index === 0 ? "Subfinder" : "Assetfinder"} falló.`);
    }
  });

  return Array.from(allSubdomains);
  }catch(e){
     console.log(e);
  }
}



/* import readline from "readline"; */
/*  */
/* async function* runSubdomainStream(cmd: string, args: string[]): AsyncIterable<string> { */
/*   try { */
/*     const childProcess = execa(cmd, args, { */
/*       stdout: "pipe", */
/*       stderr: "pipe" */
/*     }); */
/*  */
/*     // Creamos una interfaz de lectura línea por línea */
/*     const rl = readline.createInterface({ */
/*       input: childProcess.stdout!, */
/*       terminal: false */
/*     }); */
/*  */
/*     for await (const line of rl) { */
/*       const cleanLine = line.trim().toLowerCase(); */
/*       if (cleanLine) yield cleanLine; */
/*     } */
/*  */
/*     await childProcess; // Esperamos a que el proceso cierre limpio */
/*   } catch (e) { */
/*     console.error(`[!] Error en el stream de ${cmd}:`, e); */
/*   } */
/* } */
/*  */
/* export async function getAllSubdomains(target: string): Promise<string[]> { */
/*   const allSubdomains = new Set<string>(); */
/*   console.log(`[*] Iniciando recolección de streams para: ${target}`); */
/*  */
/*   // Definimos las fuentes como promesas que consumen sus respectivos streams */
/*   const sources = [ */
/*     { name: "Subfinder", stream: runSubdomainStream("subfinder", ["-d", target, "-silent"]) }, */
/*     { name: "Assetfinder", stream: runSubdomainStream("assetfinder", ["--subs-only", target]) } */
/*   ]; */
/*  */
/*   try { */
/*     // Procesamos todas las fuentes en paralelo */
/*     await Promise.all(sources.map(async (source) => { */
/*       for await (const sub of source.stream) { */
/*         allSubdomains.add(sub); */
/*       } */
/*       console.log(`[+] Fuente ${source.name} finalizada.`); */
/*     })); */
/*  */
/*     console.log(`[#] Recolección total completada: ${allSubdomains.size} subdominios únicos.`); */
/*     return Array.from(allSubdomains); */
/*  */
/*   } catch (e) { */
/*     console.error("[!] Error crítico en el orquestador:", e); */
/*     return Array.from(allSubdomains); // Devolvemos lo que llegamos a recolectar */
/*   } */
/* } */
