import { execa } from "execa";
import { subfinder, assetfinder } from "../../shared/utils.ts";
import readline from "readline";
import { logger } from "../../shared/errorLogger.ts";

async function* runSubdomainStream(cmd: string, args: string[]): AsyncIterable<string> {

  try {
    const childProcess = execa(cmd, args, {
      stdout: "pipe",
      stderr: "pipe",
    });

    const rl = readline.createInterface({
      input: childProcess.stdout!,
      terminal: false,
    });

    for await (const line of rl) {
      let cleanLine = line.trim().toLowerCase();
  
      // 1. Limpieza de basura Unicode común (u003e, etc)
      cleanLine = cleanLine.replace(/u003e|u003c/g, ""); 

      // 2. Filtro de "Solo caracteres válidos"
      // Un subdominio real solo tiene [a-z0-9.-]
      // Si después de limpiar sigue teniendo basura, lo descartamos.
      if (/^[a-z0-9.-]+$/.test(cleanLine)) {
        yield cleanLine;
      }
    }
    /*  for await (const line of rl) { */
    /* const cleanLine = line.trim().toLowerCase(); */
    /* if (cleanLine) yield cleanLine; */
    /* } */

    await childProcess; 
  } catch (e) {
    logger.error("BIN-STREAM", `Error en stream de ${cmd}:`, e);
  }
}

/**
 * FASE 1: RECON (Paralelismo Real y Deduplicación en Vuelo)
 * Ambas fuentes corren en paralelo. El primero que encuentra, emite.
 */
export async function* streamAllSubdomains(target: string): AsyncIterable<string> {
  const seen = new Set<string>(); // Memoria para evitar duplicados
  logger.info("RECON", `[*] Radar activado: Escaneo paralelo para ${target}`);

  const sources = [
    { name: "Subfinder", cmd: subfinder, args: ["-d", target, "-silent"] },
    { name: "Assetfinder", cmd: assetfinder, args: ["--subs-only", target] },
  ];

  // Cola intermedia para los hallazgos
  const outputQueue: string[] = [];
  let activeSources = sources.length;

  // Mecanismo de señalización para despertar al generador
  let signalResolver: (() => void) | null = null;

  // LANZAMIENTO PARALELO (forEach no bloquea)
  sources.forEach(async (source) => {
    try {
      for await (const sub of runSubdomainStream(source.cmd, source.args)) {
        // DEDUPLICACIÓN EN TIEMPO REAL
        if (!seen.has(sub)) {
          seen.add(sub);
          outputQueue.push(sub);
          
          // Despertamos al generador si está esperando
          if (signalResolver) {
            signalResolver();
            signalResolver = null;
          }
        }
      }
    } finally {
      activeSources--;
      // Notificamos fin de fuente para verificar cierre de flujo
      if (signalResolver) {
        signalResolver();
        signalResolver = null;
      }
      logger.info("RECON", `Fuente ${source.name} completada.`);
    }
  });

  // BUCLE DE EMISIÓN: Mantiene el flujo vivo mientras haya datos o fuentes vivas
  while (activeSources > 0 || outputQueue.length > 0) {
    if (outputQueue.length > 0) {
      yield outputQueue.shift()!;
    } else {
      // Espera eficiente (IDLE) hasta que llegue una señal
      await new Promise<void>((resolve) => {
        signalResolver = resolve;
      });
    }
  }

  logger.info("RECON", `[#] Recon finalizado. Objetivos únicos: ${seen.size}`);
}
