import { execa } from "execa"


const subfinder = "subfinder"
const assetfinder = "assetfinder"


/*  ========================= */
/* 1. buscamos subdominios */
/* ========================= */

async function runSubdomainFinderThroughApi(target: string) {
  try {
    const { stdout } = await execa(subfinder, ["-d", target, "-silent"]);
    console.log(subfinder, " completado")
    return stdout.split("\n").filter(Boolean)
  } catch (e) {
    console.log(e)
  }
}

async function runSubdomainFinderThroughCertificates(target: string) {
  try {
    const { stdout } = await execa(assetfinder, ["--subs-only", target])
    console.log(assetfinder, " completado")
    return stdout.split("\n").filter(Boolean)
  } catch (e) {
    console.log(e)
  }
}

// deduplica y arma la coleccion
export async function getAllSubdomains(target: string) {
  const res = await Promise.allSettled([
    runSubdomainFinderThroughApi(target),
    runSubdomainFinderThroughCertificates(target)
  ]);

  const allSubdomains = new Set<string>();

  res.forEach((result, index) => {
    if (result.status === "fulfilled" && result.value) {
      result.value.forEach(sub => allSubdomains.add(sub));
      console.log(`[+] Fuente ${index === 0 ? 'Subfinder' : 'Assetfinder'} completada.`)
    } else {

      console.error(`[-] Fuente ${index === 0 ? 'Subfinder' : 'Assetfinder'} falló.`);
    }
  })

  return Array.from(allSubdomains)
}


