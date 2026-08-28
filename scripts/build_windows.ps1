[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [ValidateSet('x64', 'x86')]
    [string]$Architecture = 'x64',
    [string]$VcpkgRoot = $env:VCPKG_ROOT
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
    $VcpkgRoot = Join-Path $workspace 'third_party\vcpkg'
}
$VcpkgRoot = [System.IO.Path]::GetFullPath($VcpkgRoot)

if (-not (Test-Path (Join-Path $VcpkgRoot 'vcpkg.exe'))) {
    if (-not (Test-Path $VcpkgRoot)) {
        Write-Host "Cloning vcpkg into $VcpkgRoot ..."
        git clone https://github.com/microsoft/vcpkg.git $VcpkgRoot
    }
    Push-Location $VcpkgRoot
    try { & .\bootstrap-vcpkg.bat } finally { Pop-Location }
}

$triplet = if ($Architecture -eq 'x64') { 'x64-windows' } else { 'x86-windows' }
Write-Host "Installing GMP and NTL for $triplet ..."
& (Join-Path $VcpkgRoot 'vcpkg.exe') install "gmp:$triplet" "ntl:$triplet"
if ($LASTEXITCODE -ne 0) { throw "vcpkg dependency installation failed ($LASTEXITCODE)." }

$depsPrefix = Join-Path $VcpkgRoot "installed\$triplet"
$preset = if ($Architecture -eq 'x64') { "windows-x64-$($Configuration.ToLower())" } else { "windows-x86-$($Configuration.ToLower())" }
$buildDir = Join-Path $workspace "build\$preset"
$toolchain = (Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake').Replace('\', '/')

Write-Host 'Configuring CMake ...'
cmake -S $workspace -B $buildDir -G Ninja `
    -DCMAKE_BUILD_TYPE=$Configuration `
    -DCMAKE_C_COMPILER=cl.exe -DCMAKE_CXX_COMPILER=cl.exe `
    -DCMAKE_TOOLCHAIN_FILE=$toolchain `
    -DUMBRA_DEPS_PREFIX=$depsPrefix
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)." }

Write-Host 'Building Umbra-Core ...'
cmake --build $buildDir --config $Configuration --target all
if ($LASTEXITCODE -ne 0) { throw "CMake build failed ($LASTEXITCODE)." }

Write-Host "Build completed: $buildDir"
