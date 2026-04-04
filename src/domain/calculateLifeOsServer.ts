import type { AnalyzedTarget } from "../shared/types";

export function scoreLifeOfServer(item:AnalyzedTarget):number {
  let score = 0; 
  const currentStatus = Number(item.http_intel?.status || item.status_code || 0);
  const isLive = [200, 301, 302, 403].includes(currentStatus);

  if (isLive) {
    score += 5; // Puntaje base por estar online
  
    // Si además es un código de "éxito" o "redirección", sumamos interés
    if ([200, 301, 302, 403].includes(currentStatus)) {
      score += 5; 
    }
  }
  return score;
}
