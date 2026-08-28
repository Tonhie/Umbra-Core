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

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "找不到 $Name。请在‘开发者 PowerShell for VS 2022’中运行此脚本。"
    }
}
Require-Command 'git'
Require-Command 'cmake'
Require-Command 'cl'

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
$vcpkg = Join-Path $VcpkgRoot 'vcpkg.exe'
& $vcpkg install "gmp:$triplet"
if ($LASTEXITCODE -ne 0) { throw "GMP 安装失败。请检查网络、VS2022 C++ 工具集和 Windows SDK。" }

# vcpkg 官方仓库目前可能没有 NTL port。提前检查并给出明确提示，
# 避免出现难以理解的“ntl does not exist”错误。
$ntlPort = Join-Path $VcpkgRoot 'ports\ntl'
if (-not (Test-Path $ntlPort)) {
    throw "当前 vcpkg 不包含 NTL port，无法自动生成 ntl.lib。请安装带 NTL port 的自定义 registry，或将已用 MSVC 编译的 NTL 放入 third_party/vcpkg/installed/$triplet（include/NTL、lib/ntl.lib）。"
}
& $vcpkg install "ntl:$triplet"
if ($LASTEXITCODE -ne 0) { throw "NTL 安装失败。" }

$depsPrefix = Join-Path $VcpkgRoot "installed\$triplet"
$preset = if ($Architecture -eq 'x64') { "windows-x64-$($Configuration.ToLower())" } else { "windows-x86-$($Configuration.ToLower())" }
$buildDir = Join-Path $workspace "build\$preset"
$toolchain = (Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake').Replace('\', '/')

Write-Host 'Configuring CMake ...'
cmake -S $workspace -B $buildDir -G 'Visual Studio 17 2022' -A $Architecture `
    -DCMAKE_CONFIGURATION_TYPES='Debug;Release' `
    -DCMAKE_TOOLCHAIN_FILE=$toolchain `
    -DUMBRA_DEPS_PREFIX=$depsPrefix
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)." }

Write-Host 'Building Umbra-Core ...'
cmake --build $buildDir --config $Configuration --target all
if ($LASTEXITCODE -ne 0) { throw "CMake build failed ($LASTEXITCODE)." }

Write-Host "Build completed: $buildDir"
