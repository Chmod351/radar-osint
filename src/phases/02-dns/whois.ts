import { execa } from "execa";
import { logger } from "../../shared/errorLogger.ts";
import type { WhoisIntel } from "../../shared/types.ts";
import { getErrorMessage } from "../../shared/utils.ts";

/**
 * CACHÉ GLOBAL DE WHOIS
 * La mantenemos fuera de las funciones para que persista
 * durante todo el streaming del Radar.
 */
const whoisCache = new Map<string, WhoisIntel>();

type WhoisRawData = Record<string, string | string[]>;
export const emptyWhois: WhoisIntel = {
  registrar: "N/A",
  creationDate: "N/A",
  expirationDate: "N/A",
  nameServers: [],
  status: [],
  emails: "N/A",
  raw: "",
}; 

/**
 * 1. OBTENER DOMINIO RAÍZ
 * 
 */
export function getRootDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;

  // Manejo de TLDs compuestos (ar, cl, co.uk, etc)
  const last = parts[parts.length - 1];
  const prev = parts[parts.length - 2];
  if (last && prev) {
    if (last.length <= 2 && prev.length <= 3) {
      return parts.slice(-3).join(".");
    }
  
    return parts.slice(-2).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * 2. PARSER AGNÓSTICO 
 * 
* */
function parseWhoisAgnostic(rawText: string): WhoisRawData {
  const lines = rawText.split("\n");
  const json: WhoisRawData = {};

  for (const line of lines) {
    // Limpieza de comentarios y líneas sin ":"
    if (line.startsWith("%") || line.startsWith("#") || !line.includes(":")) continue;

    const [rawKey, ...valueParts] = line.split(":");
    if (!rawKey) continue;

    const key = rawKey.trim().toLowerCase().replace(/\s+/g, "_");
    const value = valueParts.join(":").trim();
    if (!value) continue;

    const existing = json[key];
    if (existing) {
      // Si ya existe, convertimos a array o agregamos al existente
      json[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
    } else {
      json[key] = value;
    }
  }
  return json;
}

/**
 * 3. NORMALIZADOR 
* */
export function normalizeWhois(rawText: string): WhoisIntel {
  const data = parseWhoisAgnostic(rawText);

  // Helper para obtener el primer valor (string)
  const get = (k: string): string | undefined => {
    const val = data[k];
    return Array.isArray(val) ? val[0] : val;
  };

  // Helper para obtener todos los valores (array)
  const getAll = (k: string): string[] => {
    const val = data[k];
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
  };

  return {
    registrar: get("registrar") || get("sponsoring_registrar") || "Unknown",
    creationDate: get("creation_date") || get("registered_on") || "Unknown",
    expirationDate: get("registry_expiry_date") || get("expires_on") || "Unknown",
    nameServers: [...new Set([...getAll("nserver"), ...getAll("name_server")])],
    status: [...new Set([...getAll("domain_status"), ...getAll("status")])],
    emails: get("registrant_email") || get("abuse_contact_email") || "N/A",
    raw: rawText.slice(0, 500),
  };
}
/**
 * 4. FUNCIÓN ATÓMICA 
 * * .
 */
export async function getWhoisIntel(host: string): Promise<WhoisIntel> {
  const root = getRootDomain(host);
  
  // Check de caché instantáneo

  if (whoisCache.has(root)) {
    return whoisCache.get(root)!;
  }
  try {
    // Intentamos ejecutar whois con un timeout agresivo
    // Si el puerto 43 está cerrado, esto fallará rápido
    const { stdout } = await execa("whois", [root], { 
      timeout: 8000,
      reject: true, 
    });

    if (!stdout || stdout.includes("No match for")) return emptyWhois;

    const parsed = normalizeWhois(stdout);
    whoisCache.set(root, parsed);
    return parsed;
  } catch (error: unknown) {
    // Silent fail: Si no hay conexión o el comando falla, 
    // no bloqueamos el flujo, simplemente devolvemos null.
    // Esto evita el spam de "Connection refused".
    //
    whoisCache.set(root, emptyWhois);
    logger.error("WHO-IS", getErrorMessage(error));
    return emptyWhois;
  }
}
