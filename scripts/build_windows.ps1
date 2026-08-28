[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [ValidateSet('x64', 'x86')]
    [string]$Architecture = 'x64',
    [string]$VcpkgRoot = ''
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Require-Command {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw ('Required command not found: ' + $Name + '. Run this script from the VS2022 Developer PowerShell.')
    }
}

Require-Command 'git'
Require-Command 'cmake'
Require-Command 'cl'

if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
    $VcpkgRoot = Join-Path $workspace 'third_party\vcpkg'
}
$VcpkgRoot = [System.IO.Path]::GetFullPath($VcpkgRoot)
$vcpkgExe = Join-Path $VcpkgRoot 'vcpkg.exe'

if (-not (Test-Path -LiteralPath $vcpkgExe)) {
    if (-not (Test-Path -LiteralPath $VcpkgRoot)) {
        Write-Host ('Cloning vcpkg into ' + $VcpkgRoot)
        & git clone https://github.com/microsoft/vcpkg.git $VcpkgRoot
        if ($LASTEXITCODE -ne 0) { throw 'git clone failed.' }
    }
    Push-Location $VcpkgRoot
    try {
        & .\bootstrap-vcpkg.bat -disableMetrics
        if ($LASTEXITCODE -ne 0) { throw 'vcpkg bootstrap failed.' }
    }
    finally { Pop-Location }
}

$triplet = 'x64-windows'
if ($Architecture -eq 'x86') { $triplet = 'x86-windows' }
$ntlPort = Join-Path $VcpkgRoot 'ports\ntl'
if (-not (Test-Path -LiteralPath $ntlPort)) {
    $location = Join-Path $VcpkgRoot ('installed\' + $triplet)
    throw ('The vcpkg checkout has no NTL port. Provide an MSVC-built NTL library under ' + $location)
}

Write-Host ('Installing dependencies for ' + $triplet)
& $vcpkgExe install ('gmp:' + $triplet) ('ntl:' + $triplet)
if ($LASTEXITCODE -ne 0) { throw 'vcpkg dependency installation failed.' }

$depsPrefix = Join-Path $VcpkgRoot ('installed\' + $triplet)
$presetName = 'windows-' + $Architecture.ToLower() + '-' + $Configuration.ToLower()
$buildDir = Join-Path $workspace ('build\' + $presetName)
$toolchainFile = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
$configureArgs = @('-S', $workspace, '-B', $buildDir, '-G', 'Visual Studio 17 2022', '-A', $Architecture, ('-DCMAKE_TOOLCHAIN_FILE=' + $toolchainFile), ('-DUMBRA_DEPS_PREFIX=' + $depsPrefix))

Write-Host 'Configuring CMake'
& cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed.' }

Write-Host 'Building Umbra-Core'
& cmake '--build' $buildDir '--config' $Configuration '--target' 'ALL_BUILD'
if ($LASTEXITCODE -ne 0) { throw 'CMake build failed.' }

Write-Host ('Build completed: ' + $buildDir)
