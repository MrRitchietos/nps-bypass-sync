<#
.SYNOPSIS
    Builds dist/NpsBypassSync.exe: one file with the app and its assets inside.
.DESCRIPTION
    Runs on Windows or Linux with PowerShell 7 and the .NET SDK (8 or newer).
.EXAMPLE
    pwsh build/Build.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param
(
    [string]$Version = '1.0.0',
    [string]$Dotnet = $(if ($env:DOTNET) { $env:DOTNET } else { 'dotnet' })
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root 'build/.work'
$payload = Join-Path $work 'payload'
$dist = Join-Path $root 'dist'

New-Item -ItemType Directory -Force -Path $work | Out-Null
if (Test-Path $payload) { Remove-Item $payload -Recurse -Force }

Write-Host 'Staging payload...'
New-Item -ItemType Directory -Force -Path (Join-Path $payload 'assets') | Out-Null
Copy-Item (Join-Path $root 'Start-NpsBypassSync.ps1') $payload
Copy-Item (Join-Path $root 'assets/branding') (Join-Path $payload 'assets/branding') -Recurse

$payloadZip = Join-Path $work 'payload.zip'
if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($payload, $payloadZip, [IO.Compression.CompressionLevel]::Optimal, $false)
Write-Host ("Payload: {0:N1} KB" -f ((Get-Item $payloadZip).Length / 1KB))

Write-Host 'Building launcher...'
$numericVersion = ($Version -replace '[^0-9.].*$', '')
& $Dotnet publish (Join-Path $root 'src/Launcher/NpsBypassSync.csproj') -c Release -o $dist `
    "-p:PayloadZip=$payloadZip" "-p:Version=$numericVersion" "-p:InformationalVersion=$Version" --nologo
if ($LASTEXITCODE) { throw "dotnet publish failed ($LASTEXITCODE)" }

Get-ChildItem $dist | Where-Object { $_.Name -ne 'NpsBypassSync.exe' } | Remove-Item -Recurse -Force
$exe = Get-Item (Join-Path $dist 'NpsBypassSync.exe')
Write-Host ("Built {0} ({1:N1} MB)" -f $exe.FullName, ($exe.Length / 1MB))
