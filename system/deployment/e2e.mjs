import fs from 'node:fs';
import crypto from 'node:crypto';
import {performance} from 'node:perf_hooks';
import solc from 'solc';
import {createAgent} from '@veramo/core';
import {Wallet,JsonRpcProvider,ContractFactory,Contract,Interface,encodeRlp,keccak256,toBeHex,randomBytes,verifyMessage} from 'ethers';

const results='results';fs.mkdirSync(results,{recursive:true});
const secrets=JSON.parse(fs.readFileSync('.secrets/client.json'));
const sourceWallet=new Wallet(secrets.privateKey);
const provider=new JsonRpcProvider('http://127.0.0.1:19545',13371,{staticNetwork:true});
const targetWallet=sourceWallet.connect(provider);
const PROVER='http://127.0.0.1:18081';
const json=(p,x)=>fs.writeFileSync(p,JSON.stringify(x,null,2));
async function rpc(port,method,params=[]){
 const r=await fetch(`http://127.0.0.1:${port}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(30000)});
 const j=await r.json();if(j.error)throw Error(JSON.stringify(j.error));return j.result;
}
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const minimal=n=>BigInt(n)===0n?'0x':toBeHex(BigInt(n));
async function fiscoSend(to,data){
 const height=BigInt(await rpc(18545,'getBlockNumber',[1]));
 const fields=[minimal(BigInt('0x'+Buffer.from(randomBytes(16)).toString('hex'))),minimal(0),minimal(15000000),minimal(height+500n),to||'0x',minimal(0),data,minimal(1),minimal(1),'0x'];
 const signature=sourceWallet.signingKey.sign(keccak256(encodeRlp(fields)));
 const wire=encodeRlp([...fields,minimal(signature.v),minimal(BigInt(signature.r)),minimal(BigInt(signature.s))]);
 const sent=await rpc(18545,'sendRawTransaction',[1,wire]);
 const hash=typeof sent==='string'?sent:sent.transactionHash;
 if(!hash)throw Error('No FISCO transaction hash: '+JSON.stringify(sent));
 for(let i=0;i<120;i++){
  const receipt=await rpc(18545,'getTransactionReceipt',[1,hash]);
  if(receipt){if(BigInt(receipt.status)!==0n)throw Error('FISCO execution failed '+JSON.stringify(receipt));return receipt;}
  await delay(100);
 }
 throw Error('FISCO confirmation timeout');
}
async function sourceQuorum(hash){
 for(let i=0;i<50;i++){
  const all=await Promise.all([18545,18546,18547,18548].map(port=>rpc(port,'getTransactionReceipt',[1,hash])));
  const good=all.filter(r=>r&&BigInt(r.status)===0n);
  if(good.length>=3&&good.every(r=>r.blockHash===good[0].blockHash))return good[0];
  await delay(100);
 }
 throw Error('Source receipt quorum mismatch');
}
async function targetQuorum(hash){
 for(let i=0;i<300;i++) {
  const all=await Promise.all([19545,19546,19547,19548].map(port=>rpc(port,'eth_getTransactionReceipt',[hash])));
  const good=all.filter(r=>r&&BigInt(r.status)===1n);
  if(good.length>=3&&good.every(r=>r.blockHash===good[0].blockHash))return good[0];
  await delay(100);
 }
 throw Error('Target receipt quorum timeout');
}
const input={language:'Solidity',sources:{'Registry.sol':{content:fs.readFileSync('Registry.sol','utf8')}},settings:{optimizer:{enabled:true,runs:200},evmVersion:'byzantium',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}};
const compiled=JSON.parse(solc.compile(JSON.stringify(input)));
if(compiled.errors?.some(e=>e.severity==='error'))throw Error(JSON.stringify(compiled.errors));
const artifacts=compiled.contracts['Registry.sol'];
const s=artifacts.SourceCredentialRegistry,t=artifacts.TargetAcceptanceRegistry;
const sourceAbi=new Interface(s.abi);
let deployment;
if(fs.existsSync('runtime.json'))deployment=JSON.parse(fs.readFileSync('runtime.json'));
else {
 console.log('Deploying source registry on real FISCO PBFT chain...');
 const sr=await fiscoSend(null,'0x'+s.evm.bytecode.object);
 await sourceQuorum(sr.transactionHash);
 console.log('Deploying target registry on real Besu QBFT chain...');
 const tr=await new ContractFactory(t.abi,'0x'+t.evm.bytecode.object,targetWallet).deploy({gasPrice:0,gasLimit:3000000});
 await tr.waitForDeployment();await targetQuorum(tr.deploymentTransaction().hash);
 deployment={sourceRegistry:sr.contractAddress,targetRegistry:await tr.getAddress(),sourceChain:1,sourceGroup:1,targetChain:13371};json('runtime.json',deployment);
}
const targetContract=new Contract(deployment.targetRegistry,t.abi,targetWallet);
const health=await (await fetch(PROVER+'/health')).json();if(!health.ready)throw Error('Prover not ready');
async function prove(payload){const r=await fetch(PROVER+'/prove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload}),signal:AbortSignal.timeout(180000)});const j=await r.json();if(!r.ok)throw Error(JSON.stringify(j));return j;}

// Real Veramo core dispatch, custom source-evidence and EquiDID verifier method.
// Reads trusted local source RPCs, not a trustless source light-client proof.
const agent=createAgent({plugins:[{methods:{equididAccept:async({certificate})=>{
 const start=performance.now();const payload=JSON.parse(certificate.payload);
 if(payload.protocol!=='EquiDID-local-v1'||payload.sourceChain!==1||payload.sourceGroup!==1||payload.targetChain!==13371||payload.epoch!==1||payload.policy!==77||payload.operation!=='VC_ISSUE'||payload.sourceRegistry!==deployment.sourceRegistry||payload.targetRegistry!==deployment.targetRegistry)throw Error('Wrong cross-domain context');
 const digest=keccak256(Buffer.from(certificate.payload));
 if(await targetContract.accepted(digest))throw Error('Replay rejected');
 if(keccak256(Buffer.from(payload.credential))!==payload.credentialHash)throw Error('Credential hash mismatch');
 if(verifyMessage(payload.credential,payload.issuerSignature).toLowerCase()!==sourceWallet.address.toLowerCase())throw Error('Issuer signature invalid');
 const sourceReceipt=await sourceQuorum(payload.sourceTx);
 if(sourceReceipt.to.toLowerCase()!==deployment.sourceRegistry.toLowerCase()||sourceReceipt.blockHash!==payload.sourceBlockHash)throw Error('Wrong source transaction');
 const issuedEvent=sourceReceipt.logs.map(log=>{try{return sourceAbi.parseLog(log)}catch{return null}}).find(e=>e?.name==='Issued'&&e.args.credentialHash===payload.credentialHash&&e.args.issuer.toLowerCase()===sourceWallet.address.toLowerCase());
 if(!issuedEvent)throw Error('Issuance not confirmed in source receipt');
 const v=await fetch(PROVER+'/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(certificate),signal:AbortSignal.timeout(30000)});
 const verified=await v.json();if(!v.ok||!verified.verified)throw Error('EquiDID proof rejected');
 const verifyEnd=performance.now();const certificateHash=keccak256(Buffer.from(JSON.stringify(certificate)));
 const tx=await targetContract.accept(digest,payload.credentialHash,payload.sourceTx,certificateHash,{gasPrice:0,gasLimit:300000});
 const receipt=await targetQuorum(tx.hash);
 return {verified:true,requestHash:digest,targetTx:tx.hash,targetBlockHash:receipt.blockHash,targetBlockNumber:receipt.blockNumber,verification_ms:verifyEnd-start,target_submit_confirm_ms:performance.now()-verifyEnd,crypto_verification_ms:verified.verification_ms};
}}}]});

const begin=performance.now();
const credential=JSON.stringify({type:['VerifiableCredential','MaskIDCompatibleCredential'],id:crypto.randomUUID(),issuer:'did:maskid:'+sourceWallet.address,subject:'did:maskid:test-holder',claim:{membership:'research-test'},issuedAt:new Date().toISOString()});
const credentialHash=keccak256(Buffer.from(credential));const issuerSignature=await sourceWallet.signMessage(credential);
const prepared=performance.now();
const sr=await fiscoSend(deployment.sourceRegistry,sourceAbi.encodeFunctionData('issue',[credentialHash]));
const sourceReceipt=await sourceQuorum(sr.transactionHash);const sourceEnd=performance.now();
const payload=JSON.stringify({protocol:'EquiDID-local-v1',sourceChain:1,sourceGroup:1,targetChain:13371,sourceRegistry:deployment.sourceRegistry,targetRegistry:deployment.targetRegistry,epoch:1,policy:77,operation:'VC_ISSUE',requestId:crypto.randomUUID(),credential,credentialHash,issuerSignature,sourceTx:sr.transactionHash,sourceBlockHash:sourceReceipt.blockHash});
console.log('Source committed; constructing real 4-member Rsel proof...');
const built=await prove(payload);const proofEnd=performance.now();
const proverBreakdown=Object.fromEntries(['construction_ms','precompute_wait_ms','witness_ms','groth16_prove_ms','serialization_audit_store_ms'].filter(k=>built[k]!==undefined).map(k=>[k,built[k]]));
console.log('Veramo checking evidence and proof, then submitting target acceptance...');
const accepted=await agent.execute('equididAccept',{certificate:built.certificate});const end=performance.now();
const checks=[];
try {await agent.execute('equididAccept',{certificate:built.certificate});checks.push({test:'replay',passed:false});}catch(e){checks.push({test:'replay',passed:/Replay/.test(e.message)});}
const tampered=structuredClone(built.certificate);tampered.payload=payload+' ';
const bad=await fetch(PROVER+'/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(tampered)});
checks.push({test:'payload_binding',passed:!bad.ok});
if(checks.some(c=>!c.passed))throw Error('Negative check failed');
const report={status:'passed',time:new Date().toISOString(),environment:'single-host WSL2 PBFT/QBFT testbed; Windows client/prover',source_adapter:'minimal MaskID-compatible contract, not the original Java server',target:'Veramo core 7 custom verifier; contract trusts authorized verifier',committee:{n:4,k:4,logical_members_single_process:true,session:health.session},deployment,sourceTx:sr.transactionHash,sourceBlockHash:sourceReceipt.blockHash,sourceBlockNumber:sourceReceipt.blockNumber,...accepted,source_preparation_ms:prepared-begin,source_submit_confirm_ms:sourceEnd-prepared,committee_request_ms:proofEnd-sourceEnd,request_to_accept_ms:end-begin,certificate_bytes:Buffer.byteLength(JSON.stringify(built.certificate)),certificate_KB:Buffer.byteLength(JSON.stringify(built.certificate))/1000,audit_binary_bytes:built.audit_binary_bytes,audit_json_bytes:built.audit_json_bytes,checks,scope:'one functional smoke sample; not a latency distribution; excludes startup/setup/deployment; RPC receipt polling included; not pure consensus time'};
report.prover_breakdown=proverBreakdown;
json(results+'/latest-e2e.json',report);json(results+'/latest-certificate.json',built.certificate);
console.log(JSON.stringify(report,null,2));
provider.destroy();
