
export const subfinder = "subfinder"
export const assetfinder = "assetfinder"



export const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
];

export const RESULTS_BASE = process.env.RESULTS_BASE || "./results";
export const TARGET = Bun.argv[2]; // Esto reemplaza al TARGET="$1"
export const OP_DIR = `${RESULTS_BASE}/${TARGET}`


 export    const criticalKeywords = [
        'svn', 'git', 'api', 'dev', 'stg', 'test', 'mail',
        'vpn', 'admin', 'db', 'ssh', 'backup', 'internal'
      ];







export async function dataSaver(finalReport:any){
  try{
    await Bun.write(`${OP_DIR}/report.json`,JSON.stringify(finalReport,null,2))
  }catch(e){
    console.log(e)
  }
}
