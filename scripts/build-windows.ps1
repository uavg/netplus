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

$wintunDll = @(
    "target\release\wintun.dll",
    "target\release\examples\wintun.dll"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $wintunDll) {
    throw "Cargo build did not produce wintun.dll"
}
$metadata = cargo metadata --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "Unable to locate the Wintun license with cargo metadata"
}
$wintunPackage = $metadata.packages | Where-Object { $_.name -eq "wintun-bindings" } | Select-Object -First 1
if (-not $wintunPackage) {
    throw "The wintun-bindings package was not found in cargo metadata"
}
$wintunLicense = Join-Path (Split-Path $wintunPackage.manifest_path) "wintun\LICENSE.txt"
if (-not (Test-Path $wintunLicense)) {
    throw "Missing Wintun license at $wintunLicense"
}

$dist = Join-Path $PSScriptRoot "..\dist\windows-x64"
if (Test-Path $dist) {
    Remove-Item -Recurse -Force $dist
}
New-Item -ItemType Directory -Force $dist | Out-Null
$netchDist = Join-Path $dist "netch"
Copy-Item "target\release\netplus.exe" $dist
Copy-Item "target\release\netplus-gui.exe" $dist
Copy-Item $wintunDll $dist
Copy-Item $wintunLicense (Join-Path $dist "LICENSE.Wintun")
Copy-Item (Join-Path $WinDivertPath "WinDivert.dll") $dist
Copy-Item (Join-Path $WinDivertPath "WinDivert64.sys") $dist
Copy-Item $winDivertLicense (Join-Path $dist "LICENSE.WinDivert")
Copy-Item "netplus.windows.example.yaml" (Join-Path $dist "config")
Copy-Item "netplus.tun.example.yaml" (Join-Path $dist "config.tun.example")
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
