import { logger } from "./errorLogger";

/**
 * Opciones para la estrategia de reintento
 */
interface RetryOptions {
  retries?: number;    // Cantidad de intentos (default 3)
  delay?: number;      // Tiempo inicial en ms (default 1000)
  factor?: number;     // Multiplicador exponencial (default 2)
}

/**
 * Envuelve una función asincrónica con lógica de reintento exponencial.
 * Ideal para DNS, ASN y peticiones HTTP en el pipeline del Radar.
 */
export async function withRetry<T>(
  taskName: string,
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const { retries = 3, delay = 1000, factor = 2 } = options;
  
  let lastError: any;
  let currentDelay = delay;

  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;

      //  No reintentar si el error es definitivo (NXDOMAIN / ENOTFOUND)
      if (error.code === "ENOTFOUND" || error.code === "EAI_NONAME") {
        throw error;
      }

      // Si es el último intento, no esperamos más
      if (i === retries - 1) break;

      logger.error("RESILIENCE", `Fallo en ${taskName} (intento ${i + 1}/${retries}). Reintentando en ${currentDelay}ms...`);
      
      await Bun.sleep(currentDelay);
      
      // Aumentamos el delay exponencialmente
      currentDelay *= factor;
    }
  }

  logger.error("RESILIENCE", `Agotados los reintentos para ${taskName}`);
  throw lastError;
}
