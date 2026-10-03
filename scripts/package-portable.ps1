$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..

& $PSScriptRoot\build-release.ps1
$portable = Join-Path (Get-Location) 'portable'
Remove-Item $portable -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $portable | Out-Null
Copy-Item 'BiFlow.exe' (Join-Path $portable 'BiFlow.exe')
Copy-Item 'README.md' (Join-Path $portable 'README.txt')
Write-Host "Portable package created successfully at $portable\BiFlow.exe" -ForegroundColor Green
