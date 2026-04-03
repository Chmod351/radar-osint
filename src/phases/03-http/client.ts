import { USER_AGENTS } from "../../shared/utils.ts";
import { logger } from "../../shared/errorLogger.ts";
import { execa } from "execa";
import { unlink, readFile } from "node:fs/promises";

export interface Technology {
  name: string;
  version: string;
}

/**
 * Sensor WhatWeb: Fingerprinting profundo de tecnologías.
 * Se encarga de la ejecución binaria y el filtrado de ruido.
 */
export class WhatWebService {
  private noise = [
    "IP", "HTTPServer", "Country", "Date", "BaseID",
    "Title", "HTML5", "Script", "X-UA-Compatible", "Email"
  ];

  async scan(target: string): Promise<Technology[]> {
    const tempFile = `/tmp/whatweb_${Date.now()}_${Math.random().toString(36).slice(2)}.json`;
    try {
      // Ejecución con timeout para no bloquear el pipeline si WhatWeb se cuelga
      await execa("whatweb", [
        "--color=never",
        `--log-json=${tempFile}`,
        target
      ], { reject: false, timeout: 25000 });

      const rawContent = await readFile(tempFile, "utf-8");
      await unlink(tempFile);

      if (!rawContent || rawContent.trim() === "") return [];

      const parsed = JSON.parse(rawContent);
      return this.parsePlugins(parsed[0]?.plugins || {});

    } catch (error: any) {
      logger.debug("WHATWEB", `Fallo en escaneo de ${target}: ${error.message}`);
      try { await unlink(tempFile); } catch { }
      return [];
    }
  }

  private parsePlugins(plugins: any): Technology[] {
    return Object.entries(plugins)
      .filter(([name]) => !this.noise.includes(name))
      .map(([name, details]: [string, any]) => ({
        name,
        version: details.version?.[0] || details.string?.[0] || "unknown"
      }))
      .filter(t => 
        t.version !== "unknown" || 
        ["Nginx", "Apache", "PHP", "WordPress", "Docker", "Cloudflare", "Laravel"].includes(t.name)
      );
  }
}

const scanner = new WhatWebService();

/**
 * Análisis de Headers: Seguridad y Metadatos.
 */
const getRandomAgent = () => USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)] || USER_AGENTS[0];

async function analyzeHeaders(url: string) {
  try {
    const agent = getRandomAgent();
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": agent } as Record<string, string>,
      redirect: "follow",
      signal: controller.signal
    });

    clearTimeout(id);
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
      poweredBy: headers["x-powered-by"] || headers["server"] || "N/A",
      cookies: response.headers.get("set-cookie") ? "Present" : "None"
    };
  } catch (e: any) {
    return { error: "Unreachable", status: 0 };
  }
}

/**
 * Orquestador de Inteligencia Web.
 * Ejecuta headers y WhatWeb en paralelo para maximizar throughput.
 */
export async function getWebIntel(url: string) {
  const [intel, stack] = await Promise.all([
    analyzeHeaders(url),
    scanner.scan(url)
  ]);

  return {
    http_intel: intel ||{error:"Unreachable"},
    http_stack: stack || [],
  };
}
