import { execa } from "execa";
import { unlink, readFile } from "node:fs/promises";




export function parseWhatWeb(rawJson: any) {
  if (!rawJson || rawJson.length === 0) return [];

  const plugins = rawJson[0].plugins;
  const techStack = Object.entries(plugins).map(([name, details]: [string, any]) => {
    return {
      name,
      version: details.version ? details.version[0] : (details.string ? details.string[0] : "unknown")
    };
  });

  // Filtramos ruido técnico (como IP o HTTPServer que ya tenemos)
  const blacklist = ["IP", "HTTPServer", "Country"];
  return techStack.filter(t => !blacklist.includes(t.name));
}

export interface Technology {
  name: string;
  version: string;
}

export class WhatWebService {
  /**
   * Ejecuta WhatWeb usando Execa para asegurar compatibilidad con el entorno Docker/Cali.
   */
  async scan(target: string): Promise<Technology[]> {
    const tempFile = `/tmp/whatweb_${Date.now()}.json`;
    try {
      // 1. Ejecutamos WhatWeb guardando en un archivo real
      await execa("whatweb", [
        "--color=never",
        `--log-json=${tempFile}`,
        target
      ], { reject: false });

      // 2. Leemos el archivo
      const rawContent = await readFile(tempFile, "utf-8");

      // 3. Borramos el temporal para no dejar basura
      await unlink(tempFile);

      if (!rawContent || rawContent.trim() === "") return [];

      const parsed = JSON.parse(rawContent);
      return this.parsePlugins(parsed[0]?.plugins || {});

    } catch (error) {
      console.error("[!] Error en sensor (File Mode):", error);
      // Intentar borrar el archivo si quedó ahí
      try { await unlink(tempFile); } catch { }
      return [];
    }
  }



  private parsePlugins(plugins: Technology): Technology[] {
    // 1. Blacklist de plugins que NO aportan valor táctico
    const noise = [
      "IP", "HTTPServer", "Country", "Date", "BaseID",
      "Title", "HTML5", "Script", "X-UA-Compatible", "Email"
    ];

    return Object.entries(plugins)
      .filter(([name]) => !noise.includes(name)) // Filtramos el ruido
      .map(([name, details]: [string, any]) => {
        // Priorizamos version, luego string (donde a veces WhatWeb mete la OS o distro)
        const version = details.version?.[0] || details.string?.[0] || "unknown";

        return { name, version };
      })
      // 2. Filtro extra: Si es 'unknown', solo nos interesa si es una tecnología "pesada"
      // (Ej: Preferimos saber que hay un 'Nginx' aunque no sepamos la versión, 
      // pero no nos importa un 'Script' unknown).
      .filter(t => t.version !== "unknown" || ["Nginx", "Apache", "PHP", "WordPress", "Docker"].includes(t.name));
  }
}


// --- Lógica de ejecución ---
const scanner = new WhatWebService();

export async function getTechStack(target: string) {
  if (!target) {
    console.log("No se detecto un target");
  }
  try {
    const techStack = await scanner.scan(target);
    if (techStack.length > 0) {
      return techStack;
    } else {
      console.log(`[-] No se detectaron tecnologías adicionales en ${target}.`);
    }
  } catch (e) {
    console.log("fallo whatweb", e);
  }
}
