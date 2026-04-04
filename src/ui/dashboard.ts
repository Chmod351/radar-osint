import { criticalKeywords,noise } from "../shared/utils.ts";
import type { Technology } from "../phases/03-http/client.ts";
import type { AnalyzedTarget, HttpIntel } from "../shared/types";
import { calculatePriority } from "../domain/calculatePriority.ts";

const REAL_TECH_FILTER = (t: Technology) => {
 
  return !noise.some(n => t.name.includes(n));
};

/**
 * Determina la prioridad basada en el nombre del host y el estado de red.
 */


function calculateStatus(item:AnalyzedTarget){
  if(item.ip==="0.0.0.0"){
    return "DEAD";
  }

   return item.http_intel?.status || item.status_code || "ERR";

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
      cdn: item.cdn || "none"
    };
  });

  console.table(tableFriendlyReport.slice(0,25));
}
