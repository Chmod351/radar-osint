import { resolveTxt } from "node:dns/promises";

/*  ========================= */
/* 2.2. IDENTIFICAR TECNOLOGIAS */
/* ========================= */

 async function getASN(ip: string): Promise<{ asn: string, prefix: string, country: string }> {
  const revIp = ip.split('.').reverse().join('.');
  const query = `${revIp}.origin.asn.cymru.com`;

  try {
    const records = await resolveTxt(query); // Función directa
    const firstEntry = records?.[0]?.[0];
    if (firstEntry) {
      const parts = firstEntry.split('|').map(p => p.trim());
      return {
        asn: parts[0] ? `AS${parts[0]}` : "AS_UNKNOWN",
        prefix: parts[1] || "Unknown",
        country: parts[2] || "Unknown"
      };
    }
  } catch (e) {
    console.log(e)
    return {
      asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown"
    }
  }

  return { asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" };
}



export async function enrichWithASN(resolvedDomains: { host: string, ip: string }[]) {
  console.log(`[+] Consultando ASN para ${resolvedDomains.length} IPs...`);

  const enriched = await Promise.all(resolvedDomains.map(async (item) => {
    const intel = await getASN(item.ip);
    // Usamos ...intel para que las propiedades salgan del objeto y entren a 'item'
    return { ...item, ...intel };
  }));

  return enriched;
}

