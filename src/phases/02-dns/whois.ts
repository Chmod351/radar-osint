import { execa } from "execa";
import type { WhoisIntel,AnalyzedTarget } from "../../shared/types";

export interface WhoisRawData {
  [key: string]: string | string[];
}

// 1. EL MÚSCULO: Obtiene la data cruda del sistema
async function fetchWhoisRaw(target: string): Promise<string | null> {
  try {
    const { stdout } = await execa("whois", [target], { timeout: 10000 });
    return stdout || null;
  } catch (e) {
    console.log(e);
    return null;
  }
}

// 2. EL MOTOR AGNÓSTICO: Convierte TXT a un JSON ruidoso pero completo
function parseWhoisAgnostic(rawText: string): WhoisRawData {
  const lines = rawText.split("\n");
  const json: WhoisRawData = {};

  for (const line of lines) {
    if (line.startsWith("%") || line.startsWith("#") || !line.includes(":")) continue;

    const [rawKey, ...valueParts] = line.split(":");
    const key = rawKey.trim().toLowerCase().replace(/\s+/g, "_");
    const value = valueParts.join(":").trim();

    if (!value) continue;

    if (json[key]) {
      if (Array.isArray(json[key])) {
        (json[key] as string[]).push(value);
      } else {
        json[key] = [json[key] as string, value];
      }
    } else {
      json[key] = value;
    }
  }
  console.log(json,"..parseWhoIsAgnostic");
  return json;
}

// 3.Normaliza la data para el resto del Radar
function getTacticalWhois(rawText: string): WhoisIntel {
  const data = parseWhoisAgnostic(rawText);

  const getFirst = (key: string) => {
    const val = data[key];
    return Array.isArray(val) ? val[0] : val;
  };

  const getAll = (key: string) => {
    const val = data[key];
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
  };
console.log(getAll,"getAll .......");
  return {
    registrar: getFirst("registrar") || getFirst("sponsoring_registrar") || "Unknown",
    creationDate: getFirst("creation_date") || getFirst("registered_on") || "Unknown",
    expirationDate: getFirst("registry_expiry_date") || getFirst("expires_on") || "Unknown",
    nameServers: [...new Set([...getAll("nserver"), ...getAll("name_server")])],
    status: [...new Set([...getAll("domain_status"), ...getAll("status")])],
    emails: getFirst("registrant_email") || getFirst("abuse_contact_email"),
    raw: rawText.slice(0, 500) 
  };
}

// 4. FUNCIÓN PÚBLICA: dnsPhase
async function getWhois(target: string): Promise<WhoisIntel | null> {
  const raw = await fetchWhoisRaw(target);
  if (!raw) return null;
  console.log("obteniendo whois", raw);
  return getTacticalWhois(raw);
}


function getRootDomain(host: string): string {
  const parts = host.split(".");
  // Caso especial para .gob.ar, .com.ar, etc. (3 partes al final)
  if (parts.length > 3 && (host.endsWith(".gob.ar") || host.endsWith(".com.ar"))) {
    return parts.slice(-4).join("."); // sansalvadordejujuy.gob.ar
  }
  return parts.slice(-2).join("."); // dominio.com
}

export async function whoisController(preReport: AnalyzedTarget[]): Promise<AnalyzedTarget[]> {
  const whoisCache = new Map<string, WhoisIntel>();

  for (const target of preReport) {
    if (target.action === "SCAN_READY") {
      // 1. Obtenemos el raíz para el WhoIS (Ej: de 'mail.x.gob.ar' a 'x.gob.ar')
      const root = getRootDomain(target.host);

      if (whoisCache.has(root)) {
        console.log(`[♻️] Reusando WhoIS: ${target.host} <- ${root}`);
        target.whois = whoisCache.get(root);
        continue;
      }

      try {
        const whoisData = await getWhois(root);
        if (whoisData) {
          whoisCache.set(root, whoisData);
          target.whois = whoisData;
          console.log(`[✅] WhoIS obtenido para el cluster: ${root}`);
        }
      } catch (e) {
        console.log(`[❌] Error WhoIS en ${root}, ${e}`);
      }
    }
  }
  return preReport; // Devolvemos el array mutado
}
