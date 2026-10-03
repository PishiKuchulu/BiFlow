$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$root = (Get-Location).Path
$winlib = Join-Path $root 'winlib'
$msvcBin = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64'
$msvcLib = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\lib\x64'
$cargoBin = "$env:USERPROFILE\.cargo\bin"

if (Test-Path $winlib) {
    $env:LIB = "$winlib;$msvcLib;" + $env:LIB
}
$env:PATH = "$msvcBin;$cargoBin;" + $env:PATH

cargo test
cargo build --release

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

