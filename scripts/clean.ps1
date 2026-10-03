$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot\..
Remove-Item target, portable -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Clean complete.'
