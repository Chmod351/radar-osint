import { noise } from "../shared/utils.ts";
import type { Technology } from "../phases/03-http/client.ts";
import type { AnalyzedTarget } from "../shared/types";
import { calculatePriority } from "../domain/calculatePriority.ts";
import { calculateStatus } from "../domain/calculateStatus.ts";

const REAL_TECH_FILTER = (t: Technology) => {
 
  return !noise.some(n => t.name.includes(n));
};

/**
 * Renderiza la tabla final en la terminal.
 */
export function dashboard(finalReport: AnalyzedTarget[]): void {

const sortedReport = finalReport.sort((a, b) => {
    // Ponemos los que tienen puertos abiertos primero
    const aPorts = a.open_ports?.length || 0;
    const bPorts = b.open_ports?.length || 0;
    return bPorts - aPorts; 
});
  const tableFriendlyReport = sortedReport.map(item => {
    const intel = item.http_intel || {};
    // FILTRAMOS AQUÍ: Solo lo que no sea ruido
    const rawStack = item.http_stack || [];
    const cleanStack = rawStack.filter(REAL_TECH_FILTER);
    const portsSummary = item.open_ports && item.open_ports.length > 0
      ? item.open_ports.map(p => `${p.port}/${p.service}`).join(", ")
      : "--";
   
    const sec = intel.security  || { hsts: false };
    
    // Usamos las funciones que ya corregiste
    const realStatus = calculateStatus(item);
    const priorityLabel = calculatePriority(item);

    // Mandamos el stack limpio para el resumen de texto
    const { serverInfo, techSummary } = ServerInfo(item, intel, cleanStack);

    return {
      host: item.host.substring(0, 40), // Limitar para que no rompa la terminal
      priority: priorityLabel,
      status: realStatus && item.action ==="DUPLICATE_ALIAS" ? realStatus + "/D": realStatus,
      HSTS: (intel.error === "Unreachable") ? "--" : (sec.hsts ? "✔️" : "❌"),
      server: serverInfo.slice(0, 15),
      infra: item.infra_status || "⚪ N/A",
      ports:portsSummary,
      app: item.app_status || "✅", 
      tech: techSummary.substring(0,20),
      cdn: item.cdn 
    };
  });

  console.table(tableFriendlyReport.slice(0,40));
}
