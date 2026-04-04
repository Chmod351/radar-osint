export interface Technology {
  name: string;
  version: string;
}

export interface OpenPort {
  port: number;
  service: string;
  protocol: string;
}
export interface WhoisIntel {
  registrar: string;
  creationDate: string;
  expirationDate: string;
  nameServers: string[];
  status: string[];
  emails: string;
  raw: string; 
}

export interface SecurityHeaders {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  nosniff: boolean;
}

export interface HttpIntel {
  protocol: string;
  status: number;
  security: SecurityHeaders;
  server: string;
  poweredBy: string;
  cookies: string;
  error?: string | null;
}

export interface Fingerprint {
server:string,
version:string,
product:string,
}

export interface AnalyzedTarget {
  // Datos de Red e Infraestructura
  host: string;
  ip: string;
  asn: string;
  asn_owner: string;
  country: string;
  url: string;
  
  // Metas detectados
  status_code: number | string;
  title: string;
  webserver: string;
  cdn: string;
  infra_type: "Cloud/CDN" | "P/Self-H" | "Unknown";
  // Inteligencia y Análisis
  priority: "HIGH" | "LOW" | "CRITICAL"|"MEDIUM";
  action: "SCAN_READY" | "SKIP_DEEP" | "DUPLICATE_ALIAS" | "SCAN_FAILED"
  
  // Datos de Fase 3 (Opcionales hasta que pase por la fase)
  http_intel: HttpIntel;
  http_stack: Technology[];
  open_ports:OpenPort[]

  // Datos de Fase 4
  vulnerabilities: SearchSploitResult[]
  infra_status:string,
  app_status:string,

  whois: WhoisIntel;
  whois_raw: string;
}




export interface SearchSploitResult {
  Title: string;
  Path: string;
}

export interface SearchSploitOutput {
  Results: SearchSploitResult[] | []
}
