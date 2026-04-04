import type { AnalyzedTarget, HttpIntel, Technology } from "../shared/types";

export function calculateStatus(item:AnalyzedTarget){
  if (item.ip==="0.0.0.0"){
    return "DEAD";
  }

  return item.http_intel?.status || item.status_code || "ERR";

}


export function getServerInfo(item: AnalyzedTarget, intel: Partial<HttpIntel>, stack: Technology[]) {
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
    techSummary,
  };
}
