import fs from 'node:fs';
import {Wallet} from 'ethers';
fs.mkdirSync('.secrets',{recursive:true});
const path='.secrets/client.json';
if(!fs.existsSync(path)) {
 const wallet=Wallet.createRandom();
 fs.writeFileSync(path,JSON.stringify({address:wallet.address,privateKey:wallet.privateKey}),{mode:0o600});
}
const {address}=JSON.parse(fs.readFileSync(path));
fs.writeFileSync('account-public.json',JSON.stringify({address}));
console.log('Created/reused isolated test account:',address);
