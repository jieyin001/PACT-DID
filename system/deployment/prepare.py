"""Download pinned official node runtimes into an isolated WSL test directory."""
import hashlib,json,os,pathlib,subprocess,tarfile,urllib.request
ROOT=pathlib.Path.home()/'.local/share/equidid-dualchain'
ROOT.mkdir(parents=True,exist_ok=True)
DOWNLOADS=ROOT/'downloads';DOWNLOADS.mkdir(exist_ok=True)
def getjson(url):
    return json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'EquiDID-local-testbed'}),timeout=45))
def download(url,name,checksum=None):
    p=DOWNLOADS/name
    if not p.exists():
        subprocess.run(['curl','--http1.1','--fail','--location','--retry','3','--retry-all-errors','--continue-at','-','--connect-timeout','20','--max-time','600','--silent','--show-error',url,'-o',str(p)+'.part'],check=True)
        pathlib.Path(str(p)+'.part').replace(p)
    sha=hashlib.sha256(p.read_bytes()).hexdigest()
    if checksum and sha!=checksum:raise RuntimeError('SHA256 mismatch: '+name)
    print(json.dumps({'file':name,'bytes':p.stat().st_size,'sha256':sha}),flush=True)
    return p
def release(repo,tag):
    data=getjson(f'https://api.github.com/repos/{repo}/releases/tags/{tag}')
    print(repo,tag,'assets:',len(data['assets']),flush=True)
    return data
if __name__=='__main__':
    import sys
    action=sys.argv[1] if len(sys.argv)>1 else 'list'
    f=release('FISCO-BCOS/FISCO-BCOS','v2.9.1')
    b=release('besu-eth/besu','24.12.2')
    if action=='list':raise SystemExit(0)
    for data,name in [(f,'fisco-bcos.tar.gz'),(b,'besu-24.12.2.tar.gz')]:
        a=next(a for a in data['assets'] if a['name']==name)
        archive=download(a['browser_download_url'],name)
        if name.startswith('besu'):
            digestAsset=next(a for a in data['assets'] if a['name']==name+'.sha256')
            checksum=download(digestAsset['browser_download_url'],name+'.sha256').read_text().split()[0]
            if hashlib.sha256(archive.read_bytes()).hexdigest()!=checksum:raise RuntimeError('Besu checksum mismatch')
        with tarfile.open(archive) as t:t.extractall(ROOT,filter='data')
    j=release('adoptium/temurin21-binaries','jdk-21.0.5%2B11')
    name='OpenJDK21U-jre_x64_linux_hotspot_21.0.5_11.tar.gz'
    a=next(a for a in j['assets'] if a['name']==name)
    c=next(a for a in j['assets'] if a['name']==name+'.sha256.txt')
    checksum=download(c['browser_download_url'],c['name']).read_text().split()[0]
    archive=download(a['browser_download_url'],name,checksum)
    with tarfile.open(archive) as t:t.extractall(ROOT,filter='data')
    a=next(a for a in f['assets'] if a['name']=='build_chain.sh')
    download(a['browser_download_url'],'build_chain.sh')
    print('ROOT='+str(ROOT),flush=True)
