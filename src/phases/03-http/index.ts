import { getWebIntel } from "./client.ts";
// import { getTechStack } from "./serverFingerprinting.ts";
import { scanPorts } from "./portsScan.ts";
import { logger } from "../../shared/errorLogger.ts";
import type { AnalyzedTarget } from "../../shared/types";

/**
 * CONFIGURACIÓN DE RENDIMIENTO
 * MAX_CONCURRENT: Cuántos hosts procesamos en paralelo. 
 * No queremos saturar la red ni que nos bloqueen por ruido excesivo.
 */
const MAX_CONCURRENT = 3;

/**
 * Procesa un único objetivo enriqueciéndolo con HTTP Intel, Tech Stack y Puertos.
 */
async function processTarget(target: AnalyzedTarget): Promise<AnalyzedTarget> {
  const host = target.host;

  try {
    // Disparamos las 3 consultas en paralelo para este host específico
    const [httpData, openPorts] = await Promise.all([
      getWebIntel(target.url),
      scanPorts(host)
    ]);
    
    logger.debug("HTTPDATA", JSON.stringify(httpData))
    logger.debug("OPENPORTS", JSON.stringify(openPorts))
    logger.debug("TARGET", JSON.stringify(target))
    return {
      ...target,
      http_intel: httpData.http_intel,
      http_stack: httpData.http_stack,
      open_ports: openPorts || [],
      phase: 3 // Marcamos que pasó la fase de fingerprinting
    };
  } catch (error: any) {
    logger.error("PHASE-03", `Fallo crítico analizando ${host}: ${error.message}`);
    return { ...target, error: "Fingerprinting failed" };
  }
}

/**
 * FASE 3: SERVER FINGERPRINTING (STREAMING MODE)
 * Recibe un AsyncIterable de la Fase 2 y emite resultados conforme se procesan.
 */
export  async function* fingerprintPhase(infrastructureStream: AsyncIterable<AnalyzedTarget>): AsyncGenerator<AnalyzedTarget> {
  logger.info("PHASE-03", "Iniciando Pipeline de Fingerprinting (HTTP + Web + Nmap)");

  // Usamos un set para manejar la concurrencia activa
  const workers = new Set<Promise<AnalyzedTarget>>();

  for await (const target of infrastructureStream) {
    // Si llegamos al límite de trabajadores, esperamos a que uno termine
    if (workers.size >= MAX_CONCURRENT) {
      const finishedWorker = await Promise.race(workers);
      workers.delete(workers.find(w => w === finishedWorker) || Array.from(workers)[0]);
      yield finishedWorker;
    }

    // Creamos un nuevo trabajador para el target actual
    const worker = processTarget(target);
    logger.debug("WORKER:", JSON.stringify(worker))
    workers.add(worker);
    
    // Limpieza automática del set cuando el worker termina
    worker.then(() => workers.delete(worker));
  }

  // Una vez que el stream de entrada se agota, vaciamos los workers restantes
  if (workers.size > 0) {
    const finalResults = await Promise.all(Array.from(workers));
    for (const result of finalResults) {
      yield result;
    }
  }

  logger.info("PHASE-03", "Fingerprinting completado.");
}
