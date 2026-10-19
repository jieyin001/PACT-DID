import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {groth16,wtns} from 'snarkjs';
import {spawnSync} from 'node:child_process';
const out='results_remeasured';fs.mkdirSync(out,{recursive:true});
const specs=[['registration','reg'],['issuance','issuer_auth'],['revocation','cred_status']];
const reps=10,warmups=2,raw=[],summary=[],tests=[];
function countConstraints(path){
 const b=fs.readFileSync(path);let p=12;
 if(b.toString('ascii',0,4)!=='r1cs')throw Error('Bad R1CS');
 for(let i=0;i<b.readUInt32LE(8);i++){
  const type=b.readUInt32LE(p),len=Number(b.readBigUInt64LE(p+4));p+=12;
  if(type===1)return b.readUInt32LE(p+4+b.readUInt32LE(p)+24);p+=len;
 }throw Error('No R1CS header');
}
function med(x){x=[...x].sort((a,b)=>a-b);return (x[4]+x[5])/2;}
function p95(x){return [...x].sort((a,b)=>a-b)[Math.ceil(.95*x.length)-1];}
const json=(path,obj)=>fs.writeFileSync(path,JSON.stringify(obj,null,2));
for(const [name,label] of specs){
 const dir=`build/${name}`,wasm=`${dir}/${name}_js/${name}.wasm`,zk=`${dir}/${name}_final.zkey`;
 const input=JSON.parse(fs.readFileSync(`inputs/${name}.json`)),vk=JSON.parse(fs.readFileSync(`${dir}/verification_key.json`));
 const constraints=countConstraints(`${dir}/${name}.r1cs`);
 for(let i=-warmups;i<reps;i++){
  let start=performance.now();const {proof,publicSignals}=await groth16.fullProve(input,wasm,zk);
  const prove=performance.now()-start;start=performance.now();
  const ok=await groth16.verify(vk,publicSignals,proof);const verify=performance.now()-start;
  if(!ok)throw Error('Positive proof verification failed');
  const calldata=JSON.parse('['+await groth16.exportSolidityCallData(proof,publicSignals)+']');
  const proofBytes=calldata.slice(0,3).flat(Infinity).length*32;
  if(proofBytes!==256)throw Error('Unexpected proof encoding');
  if(i>=0)raw.push({relation:label,rep:i,constraints,prove_ms:prove,verify_ms:verify,proof_bytes:proofBytes,public_inputs:publicSignals.length});
  console.log(`${name} rep=${i} prove=${prove.toFixed(2)} ms verify=${verify.toFixed(2)} ms`);
  json(`${out}/${name}_proof.json`,proof);json(`${out}/${name}_public.json`,publicSignals);
 }
 // Each tampered input must fail a circuit assertion, not merely crash tooling.
 const mutations=[['signature',x=>x.sigS=(BigInt(x.sigS)+1n).toString()],
  ['context',x=>x.contextDigest=(BigInt(x.contextDigest)+1n).toString()],
  ['path',x=>{const key=name==='issuance'?'credentialSiblings':'siblings';x[key][0]=(BigInt(x[key][0])+1n).toString();}]];
 if(name==='revocation')mutations.push(['sequence',x=>x.newSequence=x.oldSequence]);
 for(const [id,fn] of mutations){
  const x=structuredClone(input);fn(x);const path=`${out}/${name}_${id}.json`;json(path,x);
  const run=spawnSync(process.execPath,[`${dir}/${name}_js/generate_witness.js`,wasm,path,`${out}/negative.wtns`],{encoding:'utf8',timeout:60000});
  const ok=run.status!==0&&!run.error&&/Assert Failed|Assertion failed|Error in template/i.test(run.stderr+run.stdout);
  tests.push({relation:label,test:id,passed:ok,diagnostic:run.stderr});
  if(!ok)throw Error(`Negative test failed ${name}/${id}`);
 }
 const rows=raw.filter(r=>r.relation===label);
 summary.push({relation:label,constraints,prove_median_s:med(rows.map(r=>r.prove_ms))/1000,
 verify_median_ms:med(rows.map(r=>r.verify_ms)),proof_bytes:256,
 prove_p95_s:p95(rows.map(r=>r.prove_ms))/1000,verify_p95_ms:p95(rows.map(r=>r.verify_ms)),reps,warmups});
 json(`${out}/summary.json`,summary);json(`${out}/raw.json`,raw);json(`${out}/tests.json`,tests);
}
function csv(path,rows){const keys=Object.keys(rows[0]);fs.writeFileSync(path,[keys.join(','),...rows.map(r=>keys.map(k=>r[k]).join(','))].join('\n')+'\n');}
csv(`${out}/summary.csv`,summary);csv(`${out}/raw.csv`,raw);
json(`${out}/environment.json`,{date:new Date().toISOString(),node:process.version,cpu:os.cpus()[0].model,
 cores:os.cpus().length,memory_bytes:os.totalmem(),os:os.release(),platform:os.platform(),snarkjs:'0.7.6',
 prove_includes_witness:true,setup_included:false,includes_rsel:false,
 circuit_sha256:Object.fromEntries(specs.map(([n])=>[n,crypto.createHash('sha256').update(fs.readFileSync(`circuits/${n}.circom`)).digest('hex')]))});
const tex=String.raw`\begin{table}[!t]
\centering
\caption{Costs of Groth16 predicate circuits.}
\label{tab:predicate-cost}
\small
\setlength{\tabcolsep}{3pt}
\renewcommand{\arraystretch}{1.08}
\begin{tabular}{@{}lrrrr@{}}
\toprule
Predicate & Constraints & Prove (s) & Verify (ms) & Proof (B) \\
\midrule
`+summary.map(r=>`$\\mathcal R_{\\mathsf{${r.relation.replace('_','\\_')}}}$ & ${r.constraints.toLocaleString('en-US')} & ${r.prove_median_s.toFixed(3)} & ${r.verify_median_ms.toFixed(3)} & ${r.proof_bytes} \\\\`).join('\n')+String.raw`
\bottomrule
\end{tabular}
\end{table}
`;
fs.writeFileSync(`${out}/predicate_cost.tex`,tex);
console.log(JSON.stringify(summary,null,2));process.exit(0);
