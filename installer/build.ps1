# Builds artifacts\SAMP-Setup-<version>.exe (Inno Setup) on Windows.
# Requires: .NET 8 SDK and Inno Setup 6.4+ (https://jrsoftware.org/isdl.php).
# Usage: .\installer\build.ps1 [-Version 1.0.0] [-Iscc "C:\path\to\ISCC.exe"]
param(
    [string]$Version = "1.0.0",
    [string]$Iscc = ""
)
$ErrorActionPreference = "Stop"
$root    = Resolve-Path (Join-Path $PSScriptRoot "..")
$publish = Join-Path $root "artifacts\publish"

if (-not $Iscc) {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
    )
    $Iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Iscc -or -not (Test-Path $Iscc)) { throw "ISCC.exe not found. Install Inno Setup 6.4+ or pass -Iscc." }

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
New-Item -ItemType Directory -Force $publish | Out-Null
foreach ($p in "SAMP.Service","SAMP.Monitor","SAMP.App","SAMP.UninstallGuard") {
    Write-Host "== publish $p"
    dotnet publish (Join-Path $root "src\$p\$p.csproj") -c Release -r win-x64 --self-contained true `
        -p:DebugType=none -p:DebugSymbols=false -o $publish
    if ($LASTEXITCODE) { throw "publish $p failed" }
}

& $Iscc "/DVersion=$Version" "/DPublishDir=$publish" (Join-Path $root "installer\SAMP.iss")
if ($LASTEXITCODE) { throw "ISCC failed" }
Write-Host "Built $(Join-Path $root "artifacts\SAMP-Setup-$Version.exe")"
