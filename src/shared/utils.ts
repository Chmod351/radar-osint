import { logger } from "./errorLogger";
import type { AnalyzedTarget } from "./types";



export const USER_AGENTS :string[]= [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
];
export const noise:string[]= ["UncommonHeaders", "Cookies", "HttpOnly", "Content-Language", 
  "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", 
  "X-Content-Type-Options", "Access-Control-Allow-Methods", 
  "Meta-Refresh-Redirect", "RedirectLocation", "PasswordField",
  "X-Powered-By"];



export const criticalKeywords:string[] = [
  "gov","gob","policia","salud","banco",
  "sistemas","system", "staging",
  "svn", "git", "api", "dev", "stg", "test", "mail",
  "vpn", "admin", "db", "ssh", "backup", "internal",
];

export const PHASES={
ORCHESTRATOR:"ORCHESTRATOR",
}as const;


export const SENSORS = {
  INFRA_TYPE: {
    UNKNOWN: 0,
    CLOUD: 1,
    SELF_HOSTED: 2,
  },
  INFRA_STATUS: {
    ERROR: 0,
    NOT_AVAILABLE: 1,
    MANAGED: 2,
    VULNERABLE: 3,
    REVIEW_REQUIRED: 4,
    SECURE: 5
  },
  PRIORITY: {
    LOW: 0,
    MEDIUM: 1,
    HIGH: 2,
    CRITICAL: 3,
  },
  ACTION: {
    SCAN_FAILED: 0,
    DUPLICATE: 1,
    SKIP: 2,
    READY: 3
  }
} as const;

export const PROTOCOLS = {
  UNKNOWN: 0,
  HTTP: 1,
  HTTPS: 2,
  SSH: 3,
  FTP: 4,
  DNS: 5,
  DATABASE: 6,
  MAIL: 7 // SMTP/IMAP
} as const;

export const CDN_PROVIDERS = {
  NONE: 0,
  CLOUDFLARE: 1,
  AKAMAI: 2,
  CLOUDFRONT: 3,
  FASTLY: 4,
  INCAPSULA: 5,
  UNKNOWN_CDN: 99
} as const;


// ----------------
export const noiseSet = new Set(noise);
export const isRealTech = (techName: string) => !noiseSet.has(techName);
export const subfinder = "subfinder";
export const assetfinder = "assetfinder";
export const RESULTS_BASE = process.env.RESULTS_BASE || "./results";
export const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
export const OP_DIR = `${RESULTS_BASE}/${TARGET}`;
// ----------------




export async function dataSaver(finalReport:AnalyzedTarget){
  try {
    await Bun.write(`${OP_DIR}/report.json`,JSON.stringify(finalReport,null,2));
  } catch (error:unknown){
    logger.error("FINAL-REPORT", getErrorMessage(error));
  }
}


export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}






