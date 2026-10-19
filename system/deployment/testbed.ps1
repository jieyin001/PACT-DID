param([ValidateSet('Start','Stop','Status','Test')][string]$Action='Status')
$ErrorActionPreference='Stop'
$node=(Get-Command node -ErrorAction Stop).Source
Push-Location $PSScriptRoot
try {
    $windowsPath=$PSScriptRoot.Replace('\','/')
    $linuxPath=(& wsl -d Ubuntu -- wslpath -a $windowsPath).Trim()
    if ($Action -eq 'Start') {
        & wsl -d Ubuntu -- python3 "$linuxPath/network.py" start
        if ($LASTEXITCODE -ne 0) { throw 'Network start failed; inspect Status before retrying' }
        & $node prover-control.mjs start
    } elseif ($Action -eq 'Stop') {
        & wsl -d Ubuntu -- python3 "$linuxPath/network.py" stop
        if (Test-Path 'results/prover-process.json') {
            $r=Get-Content 'results/prover-process.json' -Raw | ConvertFrom-Json
            $p=Get-Process -Id $r.pid -ErrorAction SilentlyContinue
            if ($p -and $p.Path -eq $r.executable) {Stop-Process -Id $p.Id}
        }
    } elseif ($Action -eq 'Status') {
        & wsl -d Ubuntu -- python3 "$linuxPath/network.py" status
        & $node prover-control.mjs status
    } else {
        & $node e2e.mjs
        if ($LASTEXITCODE -ne 0) {throw 'End-to-end smoke test failed'}
    }
} finally {Pop-Location}
