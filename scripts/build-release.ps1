$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$root = (Get-Location).Path
$cargoBin = "$env:USERPROFILE\.cargo\bin"

# Locate MSVC Build Tools via vswhere (no hardcoded VS version/path).
$msvcBin = $null
$msvcLib = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $installPath = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    if ($installPath) {
        $vcTools = Get-ChildItem "$installPath\VC\Tools\MSVC" -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($vcTools) {
            $msvcBin = "$($vcTools.FullName)\bin\Hostx64\x64"
            $msvcLib = "$($vcTools.FullName)\lib\x64"
        }
    }
}
if ($msvcBin -and (Test-Path $msvcBin)) { $env:PATH = "$msvcBin;" + $env:PATH }
if ($msvcLib -and (Test-Path $msvcLib)) { $env:LIB = "$msvcLib;" + $env:LIB }
$env:PATH = "$cargoBin;" + $env:PATH

cargo test
if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }

$candidates = @(
    (Join-Path $root 'target\x86_64-pc-windows-msvc\release\biflow.exe'),
    (Join-Path $root 'target\release\biflow.exe')
)

$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "Release executable not found in target directories" }

try {
    Copy-Item $exe 'BiFlow.exe' -Force -ErrorAction Stop
}
catch {
    $tempOld = "BiFlow.exe.old." + [System.Guid]::NewGuid().ToString("N")
    Rename-Item -Path 'BiFlow.exe' -NewName $tempOld -Force
    Copy-Item $exe 'BiFlow.exe' -Force
}
Get-ChildItem -Path $root -Filter 'BiFlow.exe.old*' | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

Write-Host "BUILD SUCCESS: BiFlow.exe created at root ($exe)" -ForegroundColor Green
