"""Operate only this isolated, loopback-only WSL dual-chain testbed."""
import configparser,json,os,pathlib,shutil,signal,socket,subprocess,sys,urllib.request
ROOT=pathlib.Path.home()/'.local/share/equidid-dualchain'
HERE=pathlib.Path(__file__).resolve().parent
def run(args,**kw):return subprocess.run([str(a) for a in args],check=True,**kw)
def env():
    e=os.environ.copy();e['JAVA_HOME']=str(next(ROOT.glob('jdk-21*-jre')))
    e['JAVA_OPTS']='-Xms128m -Xmx512m -XX:ActiveProcessorCount=2 -Djava.net.preferIPv4Stack=true'
    return e
def rpc(port,method,params):
    req=urllib.request.Request(f'http://127.0.0.1:{port}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
    data=json.load(urllib.request.urlopen(req,timeout=8))
    if 'error' in data:raise RuntimeError(data['error'])
    return data['result']
def init():
    fisco=ROOT/'fisco'
    if not fisco.exists():
        run(['bash',ROOT/'downloads/build_chain.sh','-l','127.0.0.1:4','-p','30380,20280,18545','-e',ROOT/'fisco-bcos','-o','fisco'],cwd=ROOT)
    for p in fisco.glob('127.0.0.1/node*/config.ini'):
        text=p.read_text();text=text.replace('listen_ip=0.0.0.0','listen_ip=127.0.0.1')
        p.write_text(text)
    besu=ROOT/'besu';besu.mkdir(exist_ok=True)
    if not (besu/'generated/genesis.json').exists():
        address=json.loads((HERE/'account-public.json').read_text())['address'][2:]
        config={'genesis':{'config':{'chainId':13371,'berlinBlock':0,'qbft':{'blockperiodseconds':2,'epochlength':30000,'requesttimeoutseconds':4}},'nonce':'0x0','timestamp':'0x0','gasLimit':'0x1c9c380','difficulty':'0x1','mixHash':'0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365','coinbase':'0x'+'00'*20,'alloc':{address:{'balance':'0x3635c9adc5dea00000'}}},'blockchain':{'nodes':{'generate':True,'count':4}}}
        cfg=besu/'qbft-config.json';cfg.write_text(json.dumps(config,indent=2))
        run([ROOT/'besu-24.12.2/bin/besu','operator','generate-blockchain-config',f'--config-file={cfg}',f'--to={besu / "generated"}','--private-key-file-name=key'],env=env())
    keys=sorted((besu/'generated/keys').iterdir())
    if len(keys)!=4:raise RuntimeError('expected four validator keys')
    enodes=[]
    for i,key in enumerate(keys):
        data=besu/f'node{i}';data.mkdir(exist_ok=True)
        for name in ('key','key.pub'):
            dest=data/name
            if not dest.exists():shutil.copy2(key/name,dest);dest.chmod(0o600)
        public=(data/'key.pub').read_text().strip().removeprefix('0x')
        enodes.append(f'enode://{public}@127.0.0.1:{30480+i}')
    for i in range(4):(besu/f'node{i}/static-nodes.json').write_text(json.dumps([e for j,e in enumerate(enodes) if i!=j]))
    print('Initialized 4 PBFT and 4 QBFT nodes; RPC bound to 127.0.0.1.')
def start():
    # Fail before launching anything if an unrelated process owns a port.
    registry=ROOT/'processes.json'
    if registry.exists():
        previous=json.loads(registry.read_text())
        live=[p for p in previous if pathlib.Path(f'/proc/{p["pid"]}').exists()]
        if live:raise RuntimeError('Testbed already has live registered processes; use status/stop')
    for port in [*range(18545,18549),*range(19545,19549),*range(30380,30384),*range(30480,30484),*range(20280,20284)]:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:s.bind(('127.0.0.1',port))
            except OSError as e:raise RuntimeError(f'Port {port} unavailable: {e}') from e
    records=[]
    def launch(name,args,cwd,e=None):
        logs=ROOT/'logs';logs.mkdir(exist_ok=True)
        with (logs/f'{name}.log').open('ab') as log:
            process=subprocess.Popen([str(a) for a in args],cwd=cwd,env=e,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        records.append({'name':name,'pid':process.pid});registry.write_text(json.dumps(records,indent=2))
    for i in range(4):
        node=ROOT/f'fisco/127.0.0.1/node{i}'
        launch(f'fisco{i}',[ROOT/'fisco-bcos','-c',node/'config.ini'],node)
    for i in range(4):
        args=[ROOT/'besu-24.12.2/bin/besu',f'--data-path={ROOT}/besu/node{i}',f'--genesis-file={ROOT}/besu/generated/genesis.json','--network-id=13371','--p2p-host=127.0.0.1','--p2p-interface=127.0.0.1',f'--p2p-port={30480+i}','--discovery-enabled=false','--rpc-http-enabled','--rpc-http-host=127.0.0.1',f'--rpc-http-port={19545+i}','--rpc-http-api=ETH,NET,QBFT','--host-allowlist=localhost,127.0.0.1','--min-gas-price=0','--data-storage-format=FOREST','--logging=INFO']
        launch(f'besu{i}',args,ROOT/'besu',env())
    print(json.dumps(records))
def status():
    rows=[]
    for name,base in [('fisco',18545),('besu',19545)]:
        for i in range(4):
            try:
                if name=='fisco':
                    height=rpc(base+i,'getBlockNumber',[1]);validators=rpc(base+i,'getSealerList',[1]);peers=rpc(base+i,'getPeers',[1])
                else:
                    height=rpc(base+i,'eth_blockNumber',[]);validators=rpc(base+i,'qbft_getValidatorsByBlockNumber',['latest']);peers=rpc(base+i,'net_peerCount',[])
                rows.append({'node':f'{name}{i}','rpc':base+i,'height':height,'validators':len(validators),'peers':len(peers) if isinstance(peers,list) else peers})
            except Exception as e:rows.append({'node':f'{name}{i}','error':str(e)})
    print(json.dumps(rows,indent=2))
    results=HERE/'results';results.mkdir(exist_ok=True);(results/'network-status.json').write_text(json.dumps(rows,indent=2))
def stop():
    p=ROOT/'processes.json'
    if not p.exists():return
    for item in json.loads(p.read_text()):
        proc=pathlib.Path(f'/proc/{item["pid"]}/cmdline')
        if proc.exists() and str(ROOT).encode() in proc.read_bytes():os.kill(item['pid'],signal.SIGTERM)
    print('Sent SIGTERM only to registered testbed processes. Data retained.')
if __name__=='__main__':
    {'init':init,'start':start,'status':status,'stop':stop}[sys.argv[1]]()
