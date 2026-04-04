import type { AnalyzedTarget } from "../shared/types";
import { criticalKeywords } from "../shared/utils";

export function scoreImpact(item:AnalyzedTarget) {
  let score = 0;

  // Dominio sensible
  const sensitive = criticalKeywords;
  if (sensitive.some(k => item.host.includes(k))) score += 40;

  // Infra propia
  if (item.infra_type === "P/Self-H") score += 10;
  //STACK VULNERABLE (PHP es un imán de problemas en manos inexpertas)
  if (item.http_stack?.some(s => s.name === "Cookies" && s.version === "PHPSESSID")) score += 10;


  return score;
}
