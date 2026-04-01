
import { resolveTxt } from "node:dns/promises";
import { classifyTarget, getTechStack, type Technology } from "./mediumNoise.ts"
import { findExploits,exploitController } from "../processors/vulnerabilitySearch.ts";

const RESULTS_BASE = process.env.RESULTS_BASE || "./results";
const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
const OP_DIR = `${RESULTS_BASE}/${TARGET}`



if (!TARGET) {
  console.error("[-] Uso: bun src/index.ts <dominio>");
  process.exit(1);
}





////////////////////////////////////////////////////////////////
//
//
//
//  http phase separar luego 
//
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
];

const getRandomAgent = () => USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

async function analyzeHeaders(url: string) {
  try {
    // Aseguramos que el agente sea un string y no undefined
    const agent = getRandomAgent() || USER_AGENTS[0];

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": agent // Ahora TS sabe que es string
      } as Record<string, string>, // Forzamos el tipo para evitar el error de overload
      redirect: "follow",
    });

    const headers = Object.fromEntries(response.headers.entries());

    return {
      protocol: new URL(url).protocol,
      status: response.status,
      security: {
        hsts: !!headers["strict-transport-security"],
        csp: !!headers["content-security-policy"],
        xfo: !!headers["x-frame-options"],
        nosniff: !!headers["x-content-type-options"],
      },
      server: headers["server"] || "Unknown",
      poweredBy: headers["x-powered-by"] || "N/A",
      cookies: response.headers.get("set-cookie") ? "Present" : "None"
    };
  } catch (e) {
    return null;
  }
}

async function runHttpPhase(previousData: any[]) {
  console.log(`[⚡] Iniciando Fase HTTP para ${previousData.length} dominios...`);

  const results = [];

  for (const item of previousData) {
    await Bun.sleep(Math.random() * 6000)
    console.log(`[+] Analizando: ${item.url}`);

    const httpData = await analyzeHeaders(item.url);
    //
    // -------------------------- tech data phase--------------------------
    //
    let techStack: Technology[] = [];
    if (item.status_code === 200 || (httpData && httpData.status === 200)) {
      const techData = await getTechStack(item.url)
      techData ? techStack = techData : []
    }



    const enrichedItem = {
      ...item,
      http_intel: httpData || { error: "Unreachable" },
      http_stack: techStack
    };


    //------------ VULNERABILITYS---------//
    let exploits: string[] | [] = []
    if (enrichedItem.webserver !== "N/A") {
      exploits = await findExploits(enrichedItem.webserver)

    }
    const finalItem = {
      ...enrichedItem,
      vulnerabilities: exploits
    };

    results.push(finalItem);

    // PERSISTENCIA: Guardamos "en caliente"
    // Así, si se corta, el JSON tiene el progreso actual.
    await Bun.write(`${OP_DIR}/lowNoice.json`, JSON.stringify(results, null, 2));
  }

  return results;
}





/* ========================= */
/* 6. ORQUESTADOR */
/* ========================= */

async function main(target: string) {
  try {
const preReport=[]


    // 8. FASE HTTP (Solo a los que están vivos)
    const finalReport = await runHttpPhase(preReport);
    console.log(finalReport)
    // 9. REPORTE VISUAL (Con la nueva info de prioridad)
    const tableFriendlyReport = finalReport.map(item => {
      const intel = item.http_intel || {};
      const stack = item.http_stack || {};
     const vulnAlert= exploitController(item)
     
      
      const sec = intel.security || {};
      const realStatus = item.http_intel.status || item.status || "ERR"
      console.log(realStatus)
      // 1. Prioridad: ¿Es realmente HIGH? 
      // Si tiene un server viejo (2.4.6/7) o es un punto de entrada (svn, mail, chat), es HIGH.
      // Si es un 301 genérico a www, podría ser LOW.
      const criticalKeywords = [
        'svn', 'git', 'api', 'dev', 'stg', 'test', 'mail',
        'vpn', 'admin', 'db', 'ssh', 'backup', 'internal'
      ];
      const hasCriticalName = criticalKeywords.some(key => item.host.includes(key));
      const isLive = item.status_code === 200;
      // Un HIGH real es: o está vivo (200), o es un servicio crítico (mail, svn, etc)
      const isCritical = isLive || hasCriticalName;

      const priorityLabel = isCritical ? "🔴 HIGH" : "⚪ LOW";

      // 2. Server: Buscamos el dato más completo. 
      // Priorizamos 'webserver' (trae el OS) sobre 'intel.server' (más genérico).
      const serverInfo = item.webserver && item.webserver !== "N/A"
        ? item.webserver
        : (intel.server || "???");

      // 3. Formateo de Seguridad: Símbolos puros.
      const formatSec = (val: any) => {
        if (intel.error === "Unreachable") return "--";
        return val ? "✔️" : "❌";
      };
      // 4. Formateo de Tecnologías (Resumen)
      // Mostramos solo los nombres para que la tabla no se ensanche infinito
      // Ej: "Apache, Google-Analytics"
      const techSummary = stack.length > 0
        ? stack.map((t: Technology) => t.name).join(", ").slice(0, 30)
        : "--";

      return {
        host: item.host.padEnd(25),
        priority: priorityLabel,
        status: realStatus ? realStatus : "ERR",
        HSTS: formatSec(sec.hsts),
        server: serverInfo.slice(0, 20), // Recortamos para que entre en la terminal
        exploits: vulnAlert,
        tech: techSummary,
      };
    }); console.log(`\n[🏁] REPORTE FINAL GENERADO: ${finalReport.length} entradas.`);
    console.table(tableFriendlyReport.slice(0, 20));

    // El Bun.write ya se hizo dentro de runHttpPhase, pero lo hacemos una vez más para asegurar
    await Bun.write(`${OP_DIR}/lowNoice.json`, JSON.stringify(finalReport, null, 2));

  } catch (e) {
    console.error("[!] Error crítico en el orquestador de lowNoise", e);
  }
}

main(TARGET)
