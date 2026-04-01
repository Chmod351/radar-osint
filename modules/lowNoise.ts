import { execa } from "execa"
import { resolveTxt } from "node:dns/promises";
import { classifyTarget, getTechStack, type Technology } from "./mediumNoise.ts"
import { findExploits,exploitController } from "../processors/vulnerabilitySearch.ts";

const RESULTS_BASE = process.env.RESULTS_BASE || "./results";
const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
const subfinder = "subfinder"
const assetfinder = "assetfinder"
const OP_DIR = `${RESULTS_BASE}/${TARGET}`

interface HttpCheck {
  host: string,
  ip: string
}



if (!TARGET) {
  console.error("[-] Uso: bun src/index.ts <dominio>");
  process.exit(1);
}

console.log("target identificado")

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
async function getAllSubdomains(target: string) {
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

/*  ========================= */
/* 2. Resolvemos los subdominios */
/* ========================= */

// resuelve los subdominios y los filtra
async function domainResolver(subdomains: string[]) {
  try {
    const { stdout } = await execa("dnsx", [
      "-json",
      "-silent",
      "-nc",
      "-a",
      "-resp"
    ], {
      input: subdomains.join("\n")
    })

    const resolved = stdout.split("\n").filter(Boolean).map((line) => {
      const data = JSON.parse(line);
      return {
        host: data.host,
        ip: data.a?.[0] || "0.0.0.0", // tomamos la primer ipv4
      }
    })
    console.log(`[✓] ${resolved.length} dominios resolvieron correctamente.`);
    return resolved;
  } catch (e) {
    console.log(e)
    return [];
  }
}



async function httpCheck(resolvedDomains: HttpCheck[]) {
  console.log(`[+] Lanzando HTTP Check (Fase 3) para ${resolvedDomains.length} dominios...`);

  const hostList = resolvedDomains.map(d => d.host).join("\n");

  try {
    const { stdout } = await execa('httpx-toolkit', [
      "-silent",
      "-no-color",
      "-threads", "50"
    ], {
      input: hostList,
      timeout: 300000
    });

    const res = stdout.split("\n").filter(Boolean)

    if (res.length === 0 && resolvedDomains.length > 0) {
      throw new Error("httpx devolvio un output vacio");
    }
    console.log(`[✓] ${res.length} dominios http validados`)
    return res
  } catch (e) {
    console.warn("[!]  FALLÓ o dio error. Fallback...");

    return resolvedDomains.map(d => `http://${d.host}`);
  }
}


/*  ========================= */
/* 3. obtenemos metadata */
/* ========================= */

async function getMetadata(httpDomainsValidated: string[]) {
  console.log(`[+]  Intentando obtener metada de  ${httpDomainsValidated.length} dominios...`)


  try {
    const { stdout } = await execa('httpx-toolkit', [
      "-silent",
      "-no-color",
      "-title",
      "-web-server",
      "-status-code",
      "-json",
      "-threads",
      "50"], {
      input: httpDomainsValidated.join("\n"),
      timeout: 300000
    });

    console.log(`[✓] Metadata obtenida `)
    return stdout.split("\n")
      .filter(Boolean)
      .map(line => JSON.parse(line));

  } catch (e) {
    console.error("[-] Error en getMetadata:", e);
    return []
  }
}


async function getASN(ip: string): Promise<{ asn: string, prefix: string, country: string }> {
  const revIp = ip.split('.').reverse().join('.');
  const query = `${revIp}.origin.asn.cymru.com`;

  try {
    const records = await resolveTxt(query); // Función directa
    const firstEntry = records?.[0]?.[0];
    if (firstEntry) {
      const parts = firstEntry.split('|').map(p => p.trim());
      return {
        asn: parts[0] ? `AS${parts[0]}` : "AS_UNKNOWN",
        prefix: parts[1] || "Unknown",
        country: parts[2] || "Unknown"
      };
    }
  } catch (e) {
    console.log(e)
    return {
      asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown"
    }
  }

  return { asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" };
}



export async function enrichWithASN(resolvedDomains: { host: string, ip: string }[]) {
  console.log(`[+] Consultando ASN para ${resolvedDomains.length} IPs...`);

  const enriched = await Promise.all(resolvedDomains.map(async (item) => {
    const intel = await getASN(item.ip);
    // Usamos ...intel para que las propiedades salgan del objeto y entren a 'item'
    return { ...item, ...intel };
  }));

  return enriched;
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
    // 1. Recolección
    const allDomains = await getAllSubdomains(target);

    // 2. Resolución DNS (Acá obtenemos las IPs)
    const domainsResolved = await domainResolver(allDomains);


    // 3. Enriquecimiento con ASN (Usamos las IPs de domainsResolved)
    const domainsWithASN = await enrichWithASN(domainsResolved);

    // 4. Validación HTTP (Filtramos quién responde)
    const httpUrls = await httpCheck(domainsResolved);

    // 5. Metadata Detallada (Títulos, Servers, etc.)
    const metadata = await getMetadata(httpUrls);

    // 6. CLASIFICACIÓN Y FUSIÓN
    // Primero armamos el preReport
    const preReport = domainsWithASN.map(domain => {
      const webData = metadata.find(m =>
        m.input === domain.host ||
        m.url?.includes(domain.host)
      );

      // Armamos el objeto base
      const baseData = {
        host: domain.host,
        ip: domain.ip,
        asn: domain.asn,
        asn_owner: domain.prefix, // Cymru suele poner el nombre en el campo prefix o similar
        country: domain.country,
        url: webData?.url || `http://${domain.host}`,
        status_code: webData?.status_code || 0,
        title: webData?.title || "N/A",
        webserver: webData?.webserver || "N/A",
        cdn: webData?.webserver?.toLowerCase().includes("cloudflare") ? "cloudflare" : "none"
      };

      // 7. Aplicamos la clasificación AQUÍ
      return classifyTarget(baseData);
    });




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
