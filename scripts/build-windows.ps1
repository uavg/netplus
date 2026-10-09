param(
    [Parameter(Mandatory = $true)]
    [string]$WinDivertPath,
    [string]$NetchRuntimePath
)

$ErrorActionPreference = "Stop"

$requiredFiles = @("WinDivert.dll", "WinDivert64.sys", "WinDivert.lib")
foreach ($file in $requiredFiles) {
    if (-not (Test-Path (Join-Path $WinDivertPath $file))) {
        throw "Missing $file in $WinDivertPath"
    }
    $winDivertLicense = Join-Path $WinDivertPath "..\LICENSE"
    if (-not (Test-Path $winDivertLicense)) {
        throw "Missing WinDivert LICENSE beside the x64 directory"
    }
}

$env:WINDIVERT_PATH = (Resolve-Path $WinDivertPath).Path
cargo build --release --features gui --bins
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed with exit code $LASTEXITCODE"
}

$dist = Join-Path $PSScriptRoot "..\dist\windows-x64"
if (Test-Path $dist) {
    Remove-Item -Recurse -Force $dist
}
New-Item -ItemType Directory -Force $dist | Out-Null
$netchDist = Join-Path $dist "netch"
Copy-Item "target\release\netplus.exe" $dist
Copy-Item "target\release\netplus-gui.exe" $dist
Copy-Item (Join-Path $WinDivertPath "WinDivert.dll") $dist
Copy-Item (Join-Path $WinDivertPath "WinDivert64.sys") $dist
Copy-Item $winDivertLicense (Join-Path $dist "LICENSE.WinDivert")
Copy-Item "netplus.windows.example.yaml" (Join-Path $dist "config")
Copy-Item "netplus.netch.example.yaml" (Join-Path $dist "config.netch.example")
Copy-Item "scripts\uninstall-netfilter2.bat" $dist
Copy-Item "README.md" $dist
Copy-Item "LICENSE" $dist

if ($NetchRuntimePath) {
    $netchFiles = @("Redirector.bin", "nfapi.dll", "nfdriver.sys")
    foreach ($file in $netchFiles) {
        if (-not (Test-Path (Join-Path $NetchRuntimePath $file))) {
            throw "Missing $file in $NetchRuntimePath"
        }
    }
    New-Item -ItemType Directory -Force $netchDist | Out-Null
    foreach ($file in $netchFiles) {
        Copy-Item (Join-Path $NetchRuntimePath $file) $netchDist
    }
    Copy-Item "netplus.netch.example.yaml" (Join-Path $dist "config")
    Write-Warning "Netch/NetFilter files were copied for local testing only; do not redistribute without permission."
}

Write-Host "Windows package created at $dist"
