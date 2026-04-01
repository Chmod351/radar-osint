import { execa } from "execa"
import type { AnalyzedTarget,SearchSploitOutput,SearchSploitResult } from "../../shared/types"


export async function findExploits(detectedServer: string) {
  // 1. Limpieza y validación inicial
  if (!detectedServer || ["N/A", "Unknown", "???", "cloudflare", "github.com"].includes(detectedServer.toLowerCase())) {
    return [];
  }

  // 2. Extracción de Identidad (Familia)
  // Ejemplo: "Apache/2.4.7 (Ubuntu)" -> "apache"
  const serverFamily = detectedServer.split(/[/\s(]/)[0].toLowerCase();
  
  // 3. Extracción de Versión (Completa y Mayor.Menor)
  // Ejemplo: "2.4.7" -> full: "2.4.7", short: "2.4"
  const versionMatch = detectedServer.match(/\d+\.\d+\.\d+|\d+\.\d+/);
  const version = versionMatch ? versionMatch[0] : "";
  const shortVersion = version ? version.split('.').slice(0, 2).join('.') : "";

  const query = `${serverFamily} ${version}`.trim();
  console.log(`[📡] Radar buscando: "${query}"`);

  try {
    const { stdout } = await execa("searchsploit", ["--json", query]);
    if (!stdout) return [];

    const data = JSON.parse(stdout) as SearchSploitOutput;
    const results = data.Results || [];

    // 4. FILTRO DINÁMICO INTELIGENTE
    return results.filter((exploit: SearchSploitResult) => {
      const title = exploit.Title.toLowerCase();

      // REGLA 1: Match de Familia Obligatorio
      if (!title.includes(serverFamily)) return false;

      // REGLA 2: Exclusión de "Hermanos Ruidosos" (Específico para Apache)
      // Si buscamos el servidor web "apache", no queremos "tomcat", "cxf", "openmeetings", etc.
      if (serverFamily === "apache") {
        const apacheNoise = ["tomcat", "cxf", "openmeetings", "xerces", "shoutbox", "camel", "struts"];
        if (apacheNoise.some(noise => title.includes(noise))) return false;
      }

      // REGLA 3: Flexibilidad de Versión
      // Retornamos true si el título contiene la versión exacta (2.4.7)
      // O si contiene la versión corta (2.4) y un operador de rango (<, <=)
      const hasExactVersion = version ? title.includes(version) : false;
      const hasShortVersionRange = shortVersion ? (title.includes(shortVersion) && title.includes('<')) : false;
      
      // Si no hay versión detectada, dejamos pasar la familia (mejor prevenir)
      if (!version) return true;

      return hasExactVersion || hasShortVersionRange;
    });
  } catch (e) {
    console.log(e)
    // Si searchsploit falla o no encuentra nada (exit code != 0)
    return [];
  }
}



export function exploitController(item:AnalyzedTarget):string{

 const vulns = item.vulnerabilities || [];
 const serverLower=item.webserver.toLowerCase();
 const isUnknown= ['n/a','???','unknown'].includes(serverLower);
 const isManaged=['cloudflare','github','akamai'].includes(serverLower);

   // 2. Nueva lógica de alerta con "Matices"
let vulnAlert;

if (item.status_code === "ERR" || isUnknown) {
    // Si el host está caído o no detectamos nada, no podemos decir "OK"
    vulnAlert = "⚪ N/A"; 
} else if (isManaged) {
    // Si es un WAF o infraestructura ajena, el radar no aplica
    vulnAlert = "🛡️ WAF"; 
} else if (vulns.length > 0) {
    // Si encontramos algo real con el nuevo filtro dinámico
    vulnAlert = `🔥 ${vulns.length} VULNS`;
} else {
    // Si el servidor es conocido (ej: nginx/1.29) y searchsploit no dió matches
    vulnAlert = "✅ CLEAN";
}
return vulnAlert
}

export async function httpPhaseAndVulnerabilityPhaseMerger(enrichedItem: AnalyzedTarget): Promise<AnalyzedTarget> {
    let allExploits: SearchSploitResult[] = [];

    // 1. Buscamos por el Servidor principal (Apache, Nginx, etc.)
    if (enrichedItem.webserver !== "N/A") {
        const serverExploits = await findExploits(enrichedItem.webserver);
        allExploits = [...allExploits, ...serverExploits];
    }

    // 2. BUSQUEDA POR STACK (Lo que WhatWeb encontró: WordPress, JQuery, etc.)
    if (enrichedItem.http_stack && enrichedItem.http_stack.length > 0) {
        for (const tech of enrichedItem.http_stack) {
            // No buscamos cosas genéricas como "UncommonHeaders"
            if (["WordPress", "PHP", "JQuery"].includes(tech.name)) {
                const techQuery = `${tech.name} ${tech.version !== "unknown" ? tech.version : ""}`;
                console.log(`[📡] Radar buscando Tech Stack: "${techQuery}"`);
                const techExploits = await findExploits(techQuery);
                allExploits = [...allExploits, ...techExploits];
            }
        }
    }

    return {
        ...enrichedItem, // Mantiene WHOIS, ASN y todo lo anterior
        vulnerabilities: allExploits
    };
}
