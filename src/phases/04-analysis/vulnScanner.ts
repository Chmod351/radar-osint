import { execa } from "execa";
import type { AnalyzedTarget,SearchSploitResult } from "../../shared/types";
import {noise} from "../../shared/utils";
import { logger } from "../../shared/errorLogger";



export async function findExploits(detectedServer: string) {
  // 1. Limpieza y validación inicial
  if (!detectedServer || ["N/A", "Unknown", "???", "cloudflare", "github.com"].includes(detectedServer.toLowerCase())) {
    return [];
  }

const match = detectedServer.match(/^([a-zA-Z0-9\-_]+)\/?([0-9.]*)/);
  if (!match) return [];

  const family = match[1].toLowerCase(); // apache, microsoft-iis, nginx...
  const version = match[2];              // 2.4.59, 7.5, 1.17...

  // 2. Búsqueda balanceada: Si hay versión, buscamos el combo. Si no, solo la familia.
  const query = version ? `${family} ${version}` : family;
  
  try {
    const { stdout } = await execa("searchsploit", ["--json", query]);
    const data = JSON.parse(stdout);
    let results = data.Results || [];

    // 3. El Filtro ya no es restrictivo si la búsqueda es específica
    return results.filter(exploit => {
       const title = exploit.Title.toLowerCase();
       // Solo verificamos que el nombre del software esté en el título
       return title.includes(family);
    });
  } catch (e) { 
    const err= `${detectedServer} FALLÓ EL RESOLVER ${e}`;
     logger.error("FINDEXPLOITS", err );
    return []; 
  }
}


const MANAGED_PROVIDERS = [
  "cloudflare", "akamai", "github", "amazon", "aws", "cloudfront", 
  "google", "gws", "azure", "microsoft-edge", "incapsula", "sucuri"
];

function isInfrastructureManaged(item: AnalyzedTarget): boolean {
  const server = item.webserver.toLowerCase();
  const cdn = item.cdn?.toLowerCase() || "none";
  const owner = item.asn_owner?.toLowerCase() || "";

  return (
    cdn !== "none" || 
    MANAGED_PROVIDERS.some(p => server.includes(p)) ||
    MANAGED_PROVIDERS.some(p => owner.includes(p))
  );
}

export function triageInfra(serverExploits: SearchSploitResult[], item: AnalyzedTarget): string {
  const server = item.webserver;
  const serverLower = server.toLowerCase();
  
  const isUnknown = ["n/a", "???", "unknown"].includes(serverLower);
  if (item.status_code === "ERR" || isUnknown) return "⚪ N/A";

  if (isInfrastructureManaged(item)) return "🛡️ WAF/CLOUD";

  // Usamos serverExploits que viene del Merger
  if (serverExploits.length > 0) {
    return `🔥 ${serverExploits.length} VULNS`;
  }

  const hasVersion = /[0-9]+\.[0-9]+/.test(server);
  if (hasVersion) return "🔍 R-MANUAL";

  if (server !== "N/A") return "⚠️ GENÉRICO";

  return "✅ OK";
}


export function triageApp(appExploits: SearchSploitResult[], stack: any[]): string {
  // 1. Prioridad Máxima: Si encontramos vulnerabilidades reales
  if (appExploits.length > 0) {
    return `💀 APP-VULN (${appExploits.length})`;
  }

  // 2. Definimos qué es "Stack Real" (Software, no headers)
  const isNoise:string[] = noise;

  const cleanStack = stack.filter(t => 
    !isNoise.some(n => t.name.includes(n))
  );

  // 3. Criterio CMS (WordPress, etc.)
  const cms = cleanStack.find(t => ["WordPress", "Joomla", "Drupal", "Zimbra"].includes(t.name));
  if (cms) {
    const version = cms.version !== "unknown" ? ` v${cms.version}` : "";
    return `📱 ${cms.name}${version} (R-M)`;
  }

  // 4. Criterio Frameworks/Backend (Next.js, Express, PHP, etc.)
  const backend = cleanStack.find(t => ["Next.js", "Express", "PHP", "Python", "Java", "Node.js"].includes(t.name));
  if (backend) {
    return `⚙️ ${backend.name}`;
  }

  // 5. Si no hay nada de lo anterior pero el stack limpio tiene algo (ej. Apache, Nginx)
  if (cleanStack.length > 0) {
    return `🛠️ ${cleanStack[0].name}`;
  }

  return "✅ STANDALONE";
}


export async function httpPhaseAndVulnerabilityPhaseMerger(enrichedItem: AnalyzedTarget): Promise<AnalyzedTarget> {
    let techExploits: SearchSploitResult[] = [];
    let serverExploits: SearchSploitResult[] = [];

    // 1. Capa de Servidor
    if (enrichedItem.webserver !== "N/A") {
        serverExploits = await findExploits(enrichedItem.webserver);
    }

    // 2. Capa de Aplicación (Stack)
    if (enrichedItem.http_stack && enrichedItem.http_stack.length > 0) {
        for (const tech of enrichedItem.http_stack) {
              const isNoise = noise.includes(tech.name);
              if (!isNoise) {
                 const techQuery = `${tech.name} ${tech.version !== "unknown" ? tech.version : ""}`;
                 console.log(`[🎯] Radar apuntando a: "${techQuery}"`);
                  const results = await findExploits(techQuery);
                 techExploits = [...techExploits, ...results];
               }
        }
    }

    return {
        ...enrichedItem,
        vulnerabilities: [...serverExploits, ...techExploits], // Unión para el reporte global
        infra_status: triageInfra(serverExploits, enrichedItem),
        app_status: triageApp(techExploits, enrichedItem.http_stack || [])
    };
}
