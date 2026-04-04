import type { AnalyzedTarget, Fingerprint } from "../shared/types";



function fingerprintServer(server?: string): Fingerprint {
  if (!server) return { product: "unknown" };

  const s = server.toLowerCase();

  if (s.includes("apache")) {
    const match = s.match(/apache\/([\d.]+)/);
    return { product: "apache", version: match?.[1] };
  }

  if (s.includes("nginx")) {
    const match = s.match(/nginx\/([\d.]+)/);
    return { product: "nginx", version: match?.[1] };
  }

  if (s.includes("iis")) {
    const match = s.match(/iis\/([\d.]+)/);
    return { product: "iis", version: match?.[1] };
  }

  return { product: "unknown" };
}


function isOutdated(fp: Fingerprint): boolean {
  if (!fp.version) return false;

  const v = fp.version.split(".").map(Number);

  switch (fp.product) {
    case "apache":
      return v[0] === 2 && v[1] === 4 && v[2] < 50;

    case "nginx":
      return v[0] === 1 && v[1] < 20;

    case "iis":
      return v[0] < 10;

    default:
      return false;
  }
}

export function scoreWeakness(item:AnalyzedTarget) {
  let score = 0;

  const sec = item.http_intel?.security || {};

  if (!sec.hsts) score += 5;
  if (!sec.csp) score += 5;
  if (!sec.xfo) score += 3;
  if (!sec.nosniff) score += 3;

  const fp = fingerprintServer(item.webserver);

  if (isOutdated(fp)) score += 15;

  if (item.cdn === "none") score += 10;

  return score;
}
