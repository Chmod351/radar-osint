import { execa } from "execa";
import { logger } from "../../shared/errorLogger.ts";

/**
 * Representa un puerto abierto detectado.
 */
export interface OpenPort {
  port: number;
  service: string;
  protocol: string;
}

/**
 * Parser minimalista para la salida de Nmap (formato normal).
 * Busca líneas como: "80/tcp open  http"
 */
function parseNmapOutput(stdout: string): OpenPort[] {
  const ports: OpenPort[] = [];
  const lines = stdout.split("\n");

  for (const line of lines) {
    const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(.+)$/);
    if (match) {
      ports.push({
        port: parseInt(match[1], 10)||"",
        protocol: match[2] || "",
        service: match[3].trim() || "",
      });
    }
  }
  return ports;
}

/**
 * Ejecuta un escaneo de puertos rápido y no intrusivo.
 */
export async function scanPorts(target: string): Promise<OpenPort[]> {
  try {
    logger.debug("NMAP", `Iniciando escaneo rápido para ${target}`);
    
    /**
     * Argumentos tácticos:
     * -F: Escanea los 100 puertos más comunes (muy rápido).
     * --open: Solo muestra puertos abiertos.
     * -T4: Agresividad de tiempo (nivel 4 de 5, ideal para escaneos rápidos).
     * -n: No hace resolución DNS inversa (ya la hicimos nosotros).
     */
    const { stdout } = await execa("nmap", ["-F", "--open", "-T4", "-n", target], { 
      timeout: 45000 // 45 segundos máximo por host
    });

    if (!stdout) return [];

    const discoveredPorts = parseNmapOutput(stdout);
    
    if (discoveredPorts.length > 0) {
      logger.info("NMAP", `Detectados ${discoveredPorts.length} puertos en ${target}`);
    }

    return discoveredPorts;
  } catch (e: any) {
    // Si nmap no está instalado o falla la red
    if (e.code === 'ENOENT') {
      logger.error("NMAP", "Binario 'nmap' no encontrado en el sistema.");
    } else {
      logger.debug("NMAP", `Fallo escaneo en ${target}: ${e.message}`);
    }
    return [];
  }
}
