import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const names=['registration','issuance','revocation'];
function run(args){const r=spawnSync(process.execPath,args,{stdio:'inherit'});if(r.status!==0)process.exit(r.status||1);}
for(const name of names){
 fs.mkdirSync(`build/${name}`,{recursive:true});
 run(['compile_local.cjs',`circuits/${name}.circom`,'--r1cs','--wasm','--sym','-o',`build/${name}`]);
 run([`build/${name}/${name}_js/generate_witness.js`,`build/${name}/${name}_js/${name}.wasm`,`inputs/${name}.json`,`build/${name}/${name}.wtns`]);
}
const cli='node_modules/snarkjs/build/cli.cjs';
fs.mkdirSync('build/ptau',{recursive:true});
// Single-machine fixed benchmark entropy: never deployment parameters.
run([cli,'powersoftau','new','bn128','16','build/ptau/start.ptau']);
run([cli,'powersoftau','contribute','build/ptau/start.ptau','build/ptau/contributed.ptau','--name=benchmark','-e=EquiDID typed predicates remeasurement only']);
run([cli,'powersoftau','prepare','phase2','build/ptau/contributed.ptau','build/ptau/final.ptau']);
for(const name of names){
 run([cli,'groth16','setup',`build/${name}/${name}.r1cs`,'build/ptau/final.ptau',`build/${name}/${name}_initial.zkey`]);
 run([cli,'zkey','contribute',`build/${name}/${name}_initial.zkey`,`build/${name}/${name}_final.zkey`,'--name=benchmark',`-e=EquiDID ${name} benchmark only`]);
 run([cli,'zkey','export','verificationkey',`build/${name}/${name}_final.zkey`,`build/${name}/verification_key.json`]);
}
