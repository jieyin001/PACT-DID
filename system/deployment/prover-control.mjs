import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawn,execFileSync} from 'node:child_process';
const action=process.argv[2]??'status';
if(action==='status'){
 try{console.log(await(await fetch('http://127.0.0.1:18081/health',{signal:AbortSignal.timeout(2000)})).text());}
 catch{console.log('Proof service not ready');process.exitCode=1;}
}else if(action==='start'){
 fs.mkdirSync('results/prover',{recursive:true});
 if(fs.existsSync('results/prover-process.json')){
  const p=JSON.parse(fs.readFileSync('results/prover-process.json'));
  try{
   process.kill(p.pid,0);
   const actual=execFileSync('powershell.exe',['-NoProfile','-Command',`(Get-Process -Id ${Number(p.pid)} -ErrorAction Stop).Path`],{encoding:'utf8',windowsHide:true}).trim();
   if(path.resolve(actual).toLowerCase()===path.resolve(p.executable).toLowerCase())throw Error('Registered proof-service PID is still alive; check status first');
  }catch(e){if(e.message?.includes('Registered proof-service PID'))throw e;}
 }
 const executable=path.resolve(process.env.EQUIDID_PROVER_BINARY || 'equidid-local.exe');
 const parallelism=process.env.EQUIDID_GOMAXPROCS || String(Math.min(16,os.availableParallelism()));
 const child=spawn(executable,['-serve-local','-out','results/prover'],{cwd:process.cwd(),env:{...process.env,GOMAXPROCS:parallelism},detached:true,windowsHide:true,stdio:['ignore',fs.openSync('results/prover-stdout.log','a'),fs.openSync('results/prover-stderr.log','a')]});
 child.on('error',e=>{console.error(e);process.exitCode=1;});
 child.unref();fs.writeFileSync('results/prover-process.json',JSON.stringify({pid:child.pid,executable,gomaxprocs:Number(parallelism)}));
 console.log('Started local proof service PID',child.pid,'GOMAXPROCS',parallelism);
}else throw Error('Use start or status');
