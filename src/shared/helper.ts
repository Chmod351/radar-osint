import { emptyWhois, normalizeWhois } from "../phases/02-dns/whois";
import { normalizedIntel } from "../phases/03-http/index-http";
import type { AnalyzedTarget, HttpIntel } from "./types";
import { CDN_PROVIDERS, SENSORS } from "./utils";


export function normalizeHttpIntel(raw:HttpIntel):HttpIntel {
  if (!raw) return normalizedIntel;
  return {
    protocol:Number(raw.protocol) ??null,
    status: Number(raw.status) ||0,
    security:{
      hsts: Boolean(raw.security?.hsts),
      csp: Boolean(raw.security?.csp),
      xfo: Boolean(raw.security?.xfo),
      nosniff: Boolean(raw.security?.nosniff),
    },
    server:raw.server ?? null,
    poweredBy:raw.poweredBy|| null,
    cookies:Boolean(raw.cookies),
    error:raw.error ?? null,
  }; 
}
export function normalizeTarget(raw: AnalyzedTarget): AnalyzedTarget {

  // Si es nulo, generamos el "Grado Cero" del objeto para que el resto del sistema no explote
  if (!raw) {
    return {
      host: raw.host,
      ip: "0.0.0.0",
      app_status: false,
      url: null,
      status_code: 0,
      title: null,
      webserver: null,
      cdn: CDN_PROVIDERS.NONE,
      infra_type: SENSORS.INFRA_TYPE.UNKNOWN,
      infra_status: SENSORS.INFRA_STATUS.NOT_AVAILABLE,
      priority: SENSORS.PRIORITY.LOW,
      action: SENSORS.ACTION.SCAN_FAILED,
      http_stack: [],
      open_ports: [],
      vulnerabilities: [],
      http_intel: normalizedIntel,
      whois: emptyWhois,
      asn: null,
      asn_owner: null,
      country: null,
      whois_raw: null,
    };
  }

  // Si no es nulo, aplicamos tu lógica de limpieza habitual

  return {
    host: raw.host,
    ip: raw.ip || "0.0.0.0",

    app_status:raw.app_status ?? true,
    whois_raw:raw.whois_raw  || null,
    asn: raw.asn || null,
    asn_owner: raw.asn_owner || null,
    country: raw.country || null,
    url: raw.url,
    status_code: Number(raw.status_code) || 0,
    title: raw.title || null,
    webserver: raw.webserver || null,
    cdn: raw.cdn || CDN_PROVIDERS.NONE,
    infra_type: raw.infra_type || SENSORS.INFRA_TYPE.UNKNOWN,
    infra_status:raw.infra_status ||SENSORS.INFRA_STATUS.REVIEW_REQUIRED,
    priority: raw.priority ||SENSORS.PRIORITY.LOW,
    action: raw.action || SENSORS.ACTION.READY,

    // Aquí está la magia: fallback a array vacío para evitar TypeErrors
    http_stack: Array.isArray(raw.http_stack) ? raw.http_stack : [],
    open_ports: Array.isArray(raw.open_ports) ? raw.open_ports : [],
    vulnerabilities: Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [],

    // Si no hay datos, devolvemos null explícito, no un campo faltante
    http_intel: raw.http_intel ? normalizeHttpIntel(raw.http_intel) : normalizedIntel,
    whois: (typeof raw.whois === "object" && raw.whois !== null) 
      ? raw.whois 
      : (typeof raw.whois_raw === "string" ? normalizeWhois(raw.whois_raw) : emptyWhois) };
}
