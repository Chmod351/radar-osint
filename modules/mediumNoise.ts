
export function classifyTarget(domainData: any) {
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
