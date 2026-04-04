import type { AnalyzedTarget } from "../shared/types";

export function scoreExposure(item:AnalyzedTarget) {
  let score = 0;

  const ports = item.open_ports?.map(p => p.port) || [];

  // Web base
  if (ports.includes(80) || ports.includes(443)) score += 10;


  // Acceso remoto
  // Puertos no estándar expuestos (alto valor)
  const dangerous = [21, 22, 23, 3389, 1723, 5900];
  const internal = [135, 139, 445, 2000]; // RPC, SMB, SCCP, etc

  if (ports.some(p => dangerous.includes(p))) score += 40;
  if (ports.some(p => internal.includes(p))) score += 30;

  // DBs 
  const db = [3306, 5432, 27017, 1521];
  if (ports.some(p => db.includes(p))) score += 70;

  // Superficie inflada
  if (ports.length > 5) score += 20;

  return score;
}
