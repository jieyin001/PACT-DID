import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
const out=path.join('results','figure_measurements',new Date().toISOString().replaceAll(':','-'));
fs.mkdirSync(out,{recursive:true});
const health=await fetch('http://127.0.0.1:18081/health',{signal:AbortSignal.timeout(3000)});
if(!health.ok)throw Error('Existing deployment must be ready');
const initial=await health.json();
const rows=[];
for(let rep=-1;rep<10;rep++){
 const run=spawnSync(process.execPath,['e2e.mjs'],{encoding:'utf8',timeout:180000,windowsHide:true});
 fs.writeFileSync(path.join(out,`run_${rep}.log`),run.stdout+'\n'+run.stderr);
 if(run.error||run.status!==0)throw Error(`Run ${rep} failed; see preserved log`);
 const row=JSON.parse(fs.readFileSync('results/latest-e2e.json'));
 if(row.status!=='passed'||row.committee.session!==initial.session)throw Error('Invalid result or session changed');
 row.repeat=rep;row.warmup=rep<0;rows.push(row);
 fs.writeFileSync(path.join(out,'runs.json'),JSON.stringify(rows,null,2));
 fs.copyFileSync('results/latest-certificate.json',path.join(out,`certificate_${rep}.json`));
 console.log(`${rep<0?'warmup':'sample '+rep}: total=${(row.request_to_accept_ms/1000).toFixed(3)} s, cert=${row.certificate_KB.toFixed(3)} KB`);
}
fs.writeFileSync('results/figure-measurements-latest.json',JSON.stringify({directory:path.resolve(out),repeats:10,warmups:1,session:initial.session},null,2));
console.log('OUTPUT='+path.resolve(out));
