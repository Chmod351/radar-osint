import {execa} from "execa"
import { resolveTxt } from "node:dns/promises";

const RESULTS_BASE = process.env.RESULTS_BASE || "./results";
const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
const subfinder="subfinder"
const assetfinder="assetfinder"
const OP_DIR= `${RESULTS_BASE}/${TARGET}` 

interface HttpCheck{
  host:string,
  ip:string
}



if (!TARGET) {
    console.error("[-] Uso: bun src/index.ts <dominio>");
    process.exit(1);
}

console.log("target identificado")

/*  ========================= */
 /* 1. buscamos subdominios */
 /* ========================= */

async function runSubdomainFinderThroughApi(target:string){
  try{
    const {stdout}= await execa(subfinder,["-d",target,"-silent"]);
    console.log(subfinder," completado")
    return stdout.split("\n").filter(Boolean)
  }catch(e){
   console.log(e)
  }
}

async function runSubdomainFinderThroughCertificates(target:string){
   try{
      const {stdout}= await execa(assetfinder,["--subs-only",target])
      console.log(assetfinder," completado")
      return stdout.split("\n").filter(Boolean)
   }catch(e){
    console.log(e)
   }
}

// deduplica y arma la coleccion
async function getAllSubdomains(target:string){
  const res = await Promise.allSettled([
     runSubdomainFinderThroughApi(target),
     runSubdomainFinderThroughCertificates(target)
  ]);

  const allSubdomains= new Set<string>();

  res.forEach((result,index)=>{
     if(result.status === "fulfilled" && result.value){
       result.value.forEach(sub => allSubdomains.add(sub));
       console.log(`[+] Fuente ${index === 0 ? 'Subfinder' : 'Assetfinder'} completada.`)
     }else{

     console.error(`[-] Fuente ${index === 0 ? 'Subfinder' : 'Assetfinder'} falló.`);
     }
  })

  return Array.from(allSubdomains)
}

/*  ========================= */
 /* 2. Resolvemos los subdominios */
 /* ========================= */

// resuelve los subdominios y los filtra
async function domainResolver(subdomains:string[]){
  try{
       const {stdout}= await execa("dnsx",[
       "-json", 
       "-silent", 
       "-nc", 
       "-a", 
       "-resp"
       ],{
        input: subdomains.join("\n") 
       })

       const resolved = stdout.split("\n").filter(Boolean).map((line)=>{
        const data= JSON.parse(line);
        return {
            host:data.host,
            ip:data.a?.[0] || "0.0.0.0", // tomamos la primer ipv4
        }
       })
       console.log(`[✓] ${resolved.length} dominios resolvieron correctamente.`);
       return resolved;
  }catch(e){
    console.log(e)
    return [];
  }
}



async function httpCheck(resolvedDomains:HttpCheck[]){
  console.log(`[+] Lanzando HTTP Check (Fase 3) para ${resolvedDomains.length} dominios...`);

  const hostList = resolvedDomains.map(d=> d.host).join("\n");

  try{
    const {stdout}= await execa('httpx-toolkit',[
       "-silent",
       "-no-color",
       "-threads","50"
    ],{
       input:hostList,
      timeout:300000
    });

    const res=stdout.split("\n").filter(Boolean)

    if(res.length===0 && resolvedDomains.length>0){
       throw new Error("httpx devolvio un output vacio");
    }
    console.log(`[✓] ${res.length} dominios http validados`)
    return res
  }catch(e){
    console.warn("[!]  FALLÓ o dio error. Fallback...");

    return resolvedDomains.map(d=> `http://${d.host}`);
  }
}


/*  ========================= */
 /* 3. obtenemos metadata */
 /* ========================= */

async function getMetadata(httpDomainsValidated:string[]){
  console.log(`[+]  Intentando obtener metada de  ${httpDomainsValidated.length} dominios...`)


try{
const {stdout}=await execa('httpx-toolkit',[
     "-silent", 
    "-no-color",
    "-title",
    "-web-server",
    "-status-code",
    "-json",
    "-threads",
    "50"],{
   input:httpDomainsValidated.join("\n"),
   timeout: 300000
});

console.log(`[✓] Metadata obtenida `)
return stdout.split("\n")
                 .filter(Boolean)
                 .map(line => JSON.parse(line));

}catch(e){
  console.error("[-] Error en getMetadata:", e);
  return []
   }
}


async function getASN(ip: string): Promise<{asn:string,prefix:string,country:string}> {
  const revIp = ip.split('.').reverse().join('.');
  const query = `${revIp}.origin.asn.cymru.com`;

  try {
    const records = await resolveTxt(query); // Función directa
    const firstEntry=records?.[0]?.[0];
  if (firstEntry) {
    const parts = firstEntry.split('|').map(p => p.trim());
 return {
        asn: parts[0] ? `AS${parts[0]}` : "AS_UNKNOWN",
        prefix: parts[1] || "Unknown",
        country: parts[2] || "Unknown"
      };
    }
  } catch(e) {
    console.log(e)
    return {
 asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" 
    }
  }

return { asn: "AS_UNKNOWN", prefix: "Unknown", country: "Unknown" };
}



export async function enrichWithASN(resolvedDomains: {host: string, ip: string}[]) {
  console.log(`[+] Consultando ASN para ${resolvedDomains.length} IPs...`);

  const enriched = await Promise.all(resolvedDomains.map(async (item) => {
    const intel = await getASN(item.ip); 
    // Usamos ...intel para que las propiedades salgan del objeto y entren a 'item'
    return { ...item, ...intel }; 
  }));

  return enriched;
}


/* ========================= */
/* 6. ORQUESTADOR */
/* ========================= */

async function main(target: string) {
  try {
    // 1. Recolección
    const allDomains = await getAllSubdomains(target);
    
    // 2. Resolución DNS (Acá obtenemos las IPs)
    const domainsResolved = await domainResolver(allDomains);
    
    
    // 3. Enriquecimiento con ASN (Usamos las IPs de domainsResolved)
    const domainsWithASN = await enrichWithASN(domainsResolved);

    // 4. Validación HTTP (Filtramos quién responde)
    const httpUrls = await httpCheck(domainsResolved);

    // 5. Metadata Detallada (Títulos, Servers, etc.)
    const metadata = await getMetadata(httpUrls);

    // 6. FUSIÓN FINAL: Armamos el reporte cruzando todo en memoria
    const finalReport = domainsWithASN.map(domain => {
      // Buscamos en el array de metadata si este host tiene datos web
      // httpx-toolkit en JSON devuelve la propiedad 'input' o 'url'
      const webData = metadata.find(m => 
        m.input === domain.host || 
        m.url?.includes(domain.host)
      );

      return {
        host: domain.host,
        ip: domain.ip,
        asn: domain.asn, 
        country: domain.country, 
        prefix: domain.prefix,
        url: webData?.url || `http://${domain.host}`,
        status_code: webData?.status_code || 0,
        title: webData?.title || "N/A",
        webserver: webData?.webserver || "N/A",
        cdn: webData?.webserver?.toLowerCase().includes("cloudflare") ? "cloudflare" : "none"
      };
    });

    // 7. RESULTADO FINAL
    console.log(`\n[🏁] REPORTE FINAL GENERADO: ${finalReport.length} entradas.`);
    console.table(finalReport.slice(0, 10)); // Mostramos los primeros 10 para debuggear
    const lownoisePhaseDone=await Bun.write(`${OP_DIR}/lowNoice.json`, JSON.stringify(finalReport, null, 2));
return lownoisePhaseDone
  } catch (e) {
    console.error("[!] Error crítico en el orquestador de lowNoice", e);
  }
}


main(TARGET)
