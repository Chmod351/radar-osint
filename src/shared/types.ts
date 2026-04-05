export interface Technology {
  name: string;
  version: string|null;
}

export interface OpenPort {
  port: number;
  service: string |null;
  protocol: number
}
export interface WhoisIntel {
  registrar: string |null;
  creationDate: string |null;
  expirationDate: string |null;
  nameServers: string[];
  status: string[];
  emails: string |null;
  raw: string; 
}

export interface SecurityHeaders {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  nosniff: boolean;
}

export interface HttpIntel {
  protocol: number |null;
  status: number;
  security: SecurityHeaders;
  server: string |null;
  poweredBy: string |null;
  cookies: boolean;
  error?: string | null;
}

export interface Fingerprint {
server:string,
version:string,
product:string,
}

export interface ASNIntel extends ASNinAnalyzedTarget {
   prefix: string |null;
}

interface ASNinAnalyzedTarget{
  asn: string |null ;
  country: string |null; 
}

export interface AnalyzedTarget extends ASNinAnalyzedTarget {
  // Datos de Red e Infraestructura
  host: string
  ip: string;
  asn_owner: string |null;
  url: string;
  
  // Metas detectados
  status_code: number;
  title: string |null;
  webserver: string |null;
  cdn: number | null;
  infra_type: number;
  // Inteligencia y Análisis
  priority: number;
  action: number;
  
  // Datos de Fase 3 (Opcionales hasta que pase por la fase)
  http_intel: HttpIntel;
  http_stack: Technology[];
  open_ports:OpenPort[]

  // Datos de Fase 4
  vulnerabilities: SearchSploitResult[]
  infra_status:number;
  app_status:boolean;

  whois: WhoisIntel;
  whois_raw: string | null
}




export interface SearchSploitResult {
  Title: string;
  Path: string;
}

export interface SearchSploitOutput {
  Results: SearchSploitResult[] | []
}
