import { criticalKeywords,noise } from "../shared/utils.ts";
import type { Technology } from "../phases/03-http/client.ts";
import type { AnalyzedTarget, HttpIntel } from "../shared/types";

const REAL_TECH_FILTER = (t: Technology) => {
 
  return !noise.some(n => t.name.includes(n));
};

/**
 * Determina la prioridad basada en el nombre del host y el estado de red.
 */
function calculatePriority(item: AnalyzedTarget): "🟣 CRITICAL" | "🔴 HIGH" | "🟡 MEDIUM" | "⚪ LOW" {
  // 0. Los muertos no son prioridad
  if (item.ip === "0.0.0.0" || item.http_intel?.error === "Unreachable") return "⚪ LOW";

  let score = 0;

  // 1. EL SANTO GRIAL: Puertos de Bases de Datos (Exposición masiva)
  const dbPorts = [3306, 5432, 27017, 1521]; 
  const hasDB = item.open_ports?.some(p => dbPorts.includes(p.port));
  if (hasDB) score += 100; // Esto lo hace crítico instantáneamente

  // 2. ACCESO REMOTO: SSH, FTP, RDP
  const remotePorts = [21, 22, 23, 3389];
  const hasRemote = item.open_ports?.some(p => remotePorts.includes(p.port));
  if (hasRemote) score += 50;

  // 3. INFRAESTRUCTURA PROPIA (Más jugoso que un Cloudflare)
  if (item.infra_type === "P/Self-H") score += 20;

  // 4. PALABRAS CLAVE (Lo que ya tenías)
  if (criticalKeywords.some(key => item.host.includes(key))) score += 30;

  // 5. STACK VULNERABLE (PHP es un imán de problemas en manos inexpertas)
  if (item.http_stack?.some(s => s.name === "Cookies" && s.version === "PHPSESSID")) score += 10;

  // Clasificación final
  if (score >= 100) return "🟣 CRITICAL"; // Bases de datos expuestas
  if (score >= 50)  return "🔴 HIGH";     // Puertos de gestión o keywords sensibles
  if (score >= 20)  return "🟡 MEDIUM";   // Sitios vivos en infra propia
  return "⚪ LOW";
}


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
   

    const sec = intel.security || { hsts: false };
    
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
