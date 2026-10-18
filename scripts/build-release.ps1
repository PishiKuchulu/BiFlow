$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

$root = (Get-Location).Path
$cargoBin = "$env:USERPROFILE\.cargo\bin"

# Set up the full MSVC build environment (PATH, INCLUDE, LIB, ...) via
# vcvars64.bat, located through vswhere. No hardcoded VS version/path.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $installPath = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    $vcvars = if ($installPath) { Join-Path $installPath 'VC\Auxiliary\Build\vcvars64.bat' } else { $null }
    if ($vcvars -and (Test-Path $vcvars)) {
        Write-Host "Loading MSVC environment from $vcvars" -ForegroundColor Cyan
        cmd /c "`"$vcvars`" >nul && set" | ForEach-Object {
            if ($_ -match '^(.*?)=(.*)$') {
                [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
            }
        }
    } else {
        Write-Warning "vcvars64.bat not found; hoping cl.exe/link.exe are already on PATH."
    }
} else {
    Write-Warning "vswhere.exe not found; hoping the MSVC toolchain is already on PATH."
}
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
