import { exploitController } from "../phases/04-analysis/vulnScanner.ts"
import { criticalKeywords } from "../shared/utils.ts"
import type { Technology } from "../phases/03-http/serverFingerprinting.ts"
import type { AnalyzedTarget, HttpIntel } from "../shared/types";

/**
 * Determina la prioridad basada en el nombre del host y el estado de red.
 */
function calculatePriority(item: AnalyzedTarget): "🔴 HIGH" | "⚪ LOW" {
  const hasCriticalName = criticalKeywords.some(key => item.host.includes(key));
  // Usamos el status_code de la fase 2 o el de la fase 3 si existe
  const isLive = item.status_code === 200 || item.status_code === 301 || item.http_intel?.status === 200;
  
  return (isLive || hasCriticalName) ? "🔴 HIGH" : "⚪ LOW";
}

/**
 * Procesa y formatea la información del servidor y tecnologías.
 */
function ServerInfo(item: AnalyzedTarget, intel: Partial<HttpIntel>, stack: Technology[]) {
  const serverInfo = item.webserver && item.webserver !== "N/A"
    ? item.webserver
    : (intel.server || "???");

  const formatSec = (val: boolean | undefined) => {
    if (intel.error === "Unreachable") return "--";
    return val ? "✔️" : "❌";
  };

  const techSummary = stack.length > 0
    ? stack.map((t: Technology) => t.name).join(", ").slice(0, 30)
    : "--";

  return {
    serverInfo,
    formatSec,
    techSummary
  };
}

/**
 * Renderiza la tabla final en la terminal.
 */
export function dashboard(finalReport: AnalyzedTarget[]): void {
  const tableFriendlyReport = finalReport.map(item => {
    // Definimos valores por defecto para los datos opcionales de las fases
    const intel: Partial<HttpIntel> = item.http_intel || {};
    const stack: Technology[] = item.http_stack || [];
    const sec = intel.security || { hsts: false, csp: false, xfo: false, nosniff: false };
    
    // Lógica de status: preferimos el status real de la petición HTTP
    const realStatus = item.http_intel?.status || item.status_code || "ERR";
    
    // Obtenemos alertas del controlador de vulnerabilidades
    const vulnAlert = exploitController(item);
    const priorityLabel = calculatePriority(item);

    const { serverInfo, formatSec, techSummary } = ServerInfo(item, intel, stack);

    return {
      host: item.host.padEnd(25),
      priority: priorityLabel,
      status: realStatus,
      HSTS: formatSec(sec.hsts),
      server: serverInfo.slice(0, 20),
      exploits: vulnAlert,
      tech: techSummary,
    };
  });

  console.log(`\n[🏁] REPORTE FINAL GENERADO: ${finalReport.length} objetivos analizados.`);
  console.table(tableFriendlyReport.slice(0, 25));
}
