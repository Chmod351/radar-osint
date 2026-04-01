import {USER_AGENTS} from "../../shared/utils.ts"
import type { AnalyzedTarget } from "../../shared/types";
import {  getTechStack, type Technology } from "./serverFingerprinting.ts"

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

export async function runHttpPhase(previousData: AnalyzedTarget[]) {
  console.log(`[⚡] Iniciando Fase HTTP para ${previousData.length} dominios...`);

  const results = [];

  for (const item of previousData) {
    await Bun.sleep(Math.random() * 6000)
    console.log(`[+] Analizando: ${item.url}`);

    const httpData = await analyzeHeaders(item.url);
 
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

    results.push(enrichedItem)
  }

  return results;
}


