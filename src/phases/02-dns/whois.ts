import { execa } from "execa";
import { logger } from "../../shared/errorLogger.ts";

/**
 * CACHÉ GLOBAL DE WHOIS
 * La mantenemos fuera de las funciones para que persista
 * durante todo el streaming del Radar.
 */
const whoisCache = new Map<string, any>();
console.log(whoisCache)
/**
 * 1. OBTENER DOMINIO RAÍZ
 * 
 */
export function getRootDomain(host: string): string {
  const parts = host.split(".");
  // Si tiene TLD de 2 letras seguido de otro (ar, cl, uy, uk...), tomamos 3 partes
  // Ej: x.com.ar -> x.com.ar | mail.google.com -> google.com
  if (parts.length > 2) {
    const last = parts[parts.length - 1];
    const prev = parts[parts.length - 2];
    if (last.length <= 2 && prev.length <= 3) {
      return parts.slice(-3).join(".");
    }
  }
  return parts.slice(-2).join(".");
}

/**
 * 2. PARSER AGNÓSTICO (Tu motor original)
 * 
* */
function parseWhoisAgnostic(rawText: string) {
  const lines = rawText.split("\n");
  const json: any = {};

  for (const line of lines) {
    if (line.startsWith("%") || line.startsWith("#") || !line.includes(":")) continue;
    const [rawKey, ...valueParts] = line.split(":");
    const key = rawKey.trim().toLowerCase().replace(/\s+/g, "_");
    const value = valueParts.join(":").trim();
    if (!value) continue;

    if (json[key]) {
      json[key] = Array.isArray(json[key]) ? [...json[key], value] : [json[key], value];
    } else {
      json[key] = value;
    }
  }
  return json;
}

/**
 * 3. NORMALIZADOR TÁCTICO
 */
function normalizeWhois(rawText: string) {
  const data = parseWhoisAgnostic(rawText);
  const get = (k: string) => Array.isArray(data[k]) ? data[k][0] : data[k];
  const getAll = (k: string) => {
    const val = data[k];
    return val ? (Array.isArray(val) ? val : [val]) : [];
  };

  return {
    registrar: get("registrar") || get("sponsoring_registrar") || "Unknown",
    creationDate: get("creation_date") || get("registered_on") || "Unknown",
    expirationDate: get("registry_expiry_date") || get("expires_on") || "Unknown",
    nameServers: [...new Set([...getAll("nserver"), ...getAll("name_server")])],
    status: [...new Set([...getAll("domain_status"), ...getAll("status")])],
    emails: get("registrant_email") || get("abuse_contact_email") || "N/A",
    raw: rawText.slice(0, 500)
  };
}

/**
 * 4. FUNCIÓN ATÓMICA PRINCIPAL
 * Esta es la que llamará el Orquestador.
 */
export async function getWhoisIntel(host: string): Promise<any | null> {
  const root = getRootDomain(host);

  // Check de caché instantáneo
  if (whoisCache.has(host)) {
    return whoisCache.get(host);
  }
  try {
    const { stdout } = await execa("whois", [host], { timeout: 15000 });
    if (!stdout) return null;

    const info = normalizeWhois(stdout);
    whoisCache.set(root, info); // Guardamos para el próximo subdominio del mismo root
    return info;
  } catch (e) {
    // Si falla, no guardamos nada para que el retry pueda volver a intentarlo
    logger.error("WHOIS", `${host} fallo en obtener informacion:${e}`)
    throw e; 
  }
}
