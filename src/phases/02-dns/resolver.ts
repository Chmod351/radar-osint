import { execa } from "execa"
import type { AnalyzedTarget } from "../../shared/types";

interface HttpCheck {
  host: string,
  ip: string
}


/*  ========================= */
/* 2. Resolvemos los subdominios */
/* ========================= */

// resuelve los subdominios y los filtra
export async function domainResolver(subdomains: string[]) {
  try {
    const { stdout } = await execa("dnsx", [
      "-json",
      "-silent",
      "-nc",
      "-a",
      "-resp"
    ], {
      input: subdomains.join("\n")
    })

    const resolved = stdout.split("\n").filter(Boolean).map((line) => {
      const data = JSON.parse(line);
      return {
        host: data.host,
        ip: data.a?.[0] || "0.0.0.0", // tomamos la primer ipv4
      }
    })
    return resolved;
  } catch (e) {
    console.log(e)
    return [];
  }
}




export async function httpCheck(resolvedDomains: HttpCheck[]) {

  const hostList = resolvedDomains.map(d => d.host).join("\n");

  try {
    const { stdout } = await execa('httpx-toolkit', [
      "-silent",
      "-no-color",
      "-threads", "50"
    ], {
      input: hostList,
      timeout: 300000
    });

    const res = stdout.split("\n").filter(Boolean)

    if (res.length === 0 && resolvedDomains.length > 0) {
      throw new Error("httpx devolvio un output vacio");
    }
    console.log(`[✓] ${res.length} dominios http validados`)
    return res
  } catch (e) {
    console.warn("[!]  FALLÓ o dio error. Fallback...");

    return resolvedDomains.map(d => `http://${d.host}`);
  }
}


/*  ========================= */
/* 3. obtenemos metadata */
/* ========================= */

export async function getMetadata(httpDomainsValidated: string[]) {
  console.log(`[+]  Intentando obtener metada de  ${httpDomainsValidated.length} dominios...`)


  try {
    const { stdout } = await execa('httpx-toolkit', [
      "-silent",
      "-no-color",
      "-title",
      "-web-server",
      "-status-code",
      "-json",
      "-threads",
      "50"], {
      input: httpDomainsValidated.join("\n"),
      timeout: 300000
    });

    console.log(`[✓] Metadata obtenida `)
    return stdout.split("\n")
      .filter(Boolean)
      .map(line => JSON.parse(line));

  } catch (e) {
    console.error("[-] Error en getMetadata:", e);
    return []
  }
}

export function classifyTarget(domainData: {
host: string;
  ip: string;
  asn: string;
  asn_owner: string;
  country: string;
  url: any;
  status_code: any;
  title: any;
  webserver: any;
  cdn: string;
}) {
  const cloudKeywords = [
    "amazon", "google", "microsoft", "cloudflare", "akamai",
    "fastly", "ovh", "digitalocean", "linode", "vercel", "github"
  ];

  const asnOwner = domainData.asn_owner?.toLowerCase() || domainData.asn?.toLowerCase() || "";

  const isCloud = cloudKeywords.some(key => asnOwner.includes(key));

  return {
    ...domainData,
    priority: isCloud ? "LOW" : "HIGH",
    infra_type: isCloud ? "Cloud/CDN" : "P/Self-H",
    action: isCloud ? "SKIP_DEEP" : "SCAN_READY"
  };
}
