import type { AnalyzedTarget } from "../shared/types";
import { scoreExposure } from "./calculateExposure";
import { scoreImpact } from "./calculateImpact";
import { scoreLifeOfServer } from "./calculateLifeOsServer";
import { scoreWeakness } from "./calculateWeakness";

export function calculatePriority(item: AnalyzedTarget): "🟣 CRIT" | "🔴 HIGH" | "🟡 MED" | "⚪ LOW" {
  // 0. Los muertos no son prioridad
  const isLive=scoreLifeOfServer(item);
  const exposure=scoreExposure(item);
  const impact =scoreImpact(item);
  const weakness = scoreWeakness(item);

  const total = isLive + exposure + impact + weakness; 

  // Clasificación final
 
  if (item.ip === "0.0.0.0" || item.http_intel?.error === "Unreachable") return "⚪ LOW";
  if (total >= 100) return "🟣 CRIT"; // Bases de datos expuestas
  if (total >= 50)  return "🔴 HIGH";     // Puertos de gestión o keywords sensibles
  if (total >= 20)  return "🟡 MED";   // Sitios vivos en infra propia
  return "⚪ LOW";
}

