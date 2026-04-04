import { normalizeWhois } from "../phases/02-dns/whois";
import type { AnalyzedTarget, HttpIntel } from "./types";


function normalizeHttpIntel(raw:HttpIntel) {
  return {
    protocol:raw.protocol||"Unknown",
    status: Number(raw.status) ||0,
    security:{
      hsts: Boolean(raw.security?.hsts),
      csp: Boolean(raw.security?.csp),
      xfo: Boolean(raw.security?.xfo),
      nosniff: Boolean(raw.security?.nosniff),
    },
    server:raw.server || "Unknown",
    poweredBy:raw.poweredBy|| "Unknown",
    cookies:raw.cookies||"N/A",
    error:raw.error || "",
  }; 
}
function normalizeTarget(raw: any): AnalyzedTarget {
  return {
    host: raw.host || "unknown",
    ip: raw.ip || "0.0.0.0",

    app_status:raw.app_status || "N/A",
    whois_raw:raw.whois_raw  || "N/A",
    asn: raw.asn || "N/A",
    asn_owner: raw.asn_owner || "N/A",
    country: raw.country || "N/A",
    url: raw.url || "",
    status_code: Number(raw.status_code) || 0,
    title: raw.title || "N/A",
    webserver: raw.webserver || "N/A",
    cdn: raw.cdn || "none",
    infra_type: raw.infra_type || "Unknown",
    infra_status:raw.infra_status || "Unknown",
    priority: raw.priority || "⚪ LOW",
    action: raw.action || "SCAN_READY",

    // Aquí está la magia: fallback a array vacío para evitar TypeErrors
    http_stack: Array.isArray(raw.http_stack) ? raw.http_stack : [],
    open_ports: Array.isArray(raw.open_ports) ? raw.open_ports : [],
    vulnerabilities: Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [],

    // Si no hay datos, devolvemos null explícito, no un campo faltante
    http_intel: raw.http_intel ? normalizeHttpIntel(raw.http_intel) : null,
    whois: (typeof raw.whois === "object" && raw.whois !== null) 
      ? raw.whois 
      : (typeof raw.whois_raw === "string" ? normalizeWhois(raw.whois_raw) : null)  };
}
