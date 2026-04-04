import { logger } from "./errorLogger";
import { getErrorMessage } from "./utils";

/**
 * Opciones para la estrategia de reintento
 */
interface RetryOptions {
  retries?: number;    // Cantidad de intentos (default 3)
  delay?: number;      // Tiempo inicial en ms (default 1000)
  factor?: number;     // Multiplicador exponencial (default 2)
}

interface SystemError extends Error {
  code?: string;
}
/**
 * Envuelve una función asincrónica con lógica de reintento exponencial.
 * Ideal para DNS, ASN y peticiones HTTP en el pipeline del Radar.
 */

function isSystemError(error: unknown): error is SystemError {
  return error instanceof Error && "code" in error;
}

export async function withRetry<T>(
  taskName: string,
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const { retries = 3, delay = 1000, factor = 2 } = options;
  
  let lastError: unknown;
  let currentDelay = delay;

  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error: unknown) {
      lastError = error;

      //  No reintentar si el error es definitivo (NXDOMAIN / ENOTFOUND)
      if (isSystemError(error)) {
        if (error.code === "ENOTFOUND" || error.code === "EAI_NONAME") {
          throw error; // Salida inmediata si el dominio no existe
        }
      }

      // Si es el último intento, no esperamos más
      if (i === retries - 1) break;

      logger.error("RESILIENCE", `Fallo en ${taskName} (intento ${i + 1}/${retries}): ${getErrorMessage(error)}. Reintentando en ${currentDelay}ms...`);
      
      await Bun.sleep(currentDelay);
      
      // Aumentamos el delay exponencialmente
      currentDelay *= factor;
    }
  }

  logger.error("RESILIENCE", `Agotados los reintentos para ${taskName}`);
  throw lastError;
}
