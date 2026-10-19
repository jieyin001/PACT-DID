// Keep WASI access within this experiment; upstream CLI preopens every parent.
const fs=require('fs');
const {CircomRunner,bindings}=require('circom2');
const runner=new CircomRunner({args:process.argv.slice(2),env:process.env,
 preopens:{'.':'.'},bindings:{...bindings,fs}});
runner.execute(fs.readFileSync(require.resolve('circom2/circom.wasm')))
 .catch(e=>{console.error(e);process.exit(1)});
