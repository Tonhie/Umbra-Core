[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$MsysRoot = ''
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Require-Command {
    param([string]$Name)
    if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw ('Required command not found: ' + $Name)
    }
}

Require-Command 'winget'

if ([string]::IsNullOrWhiteSpace($MsysRoot)) {
    $candidates = @('C:\msys64', (Join-Path $env:LOCALAPPDATA 'Programs\msys64'))
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'usr\bin\bash.exe')) {
            $MsysRoot = $candidate
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($MsysRoot)) {
    Write-Host 'MSYS2 was not found. Installing it with winget.'
    & winget install --id MSYS2.MSYS2 --exact --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw 'MSYS2 installation failed.' }
    $candidates = @('C:\msys64', (Join-Path $env:LOCALAPPDATA 'Programs\msys64'))
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'usr\bin\bash.exe')) {
            $MsysRoot = $candidate
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($MsysRoot)) {
    throw 'MSYS2 was installed but bash.exe could not be located. Pass -MsysRoot C:\msys64.'
}

$bash = Join-Path $MsysRoot 'usr\bin\bash.exe'
$shellLauncher = $bash
$rootUnix = (& (Join-Path $MsysRoot 'usr\bin\cygpath.exe') -u $workspace).Trim()
$srcUnix = $rootUnix + '/third_party/src'
$buildUnix = $rootUnix + '/third_party/build/msys2'
$localUnix = $rootUnix + '/third_party/local-msys2'
$buildWindows = Join-Path $workspace 'build\windows-msys2'

# The first MSYS2 runtime update terminates all MSYS2 processes by design.
# Run the update separately and retry it once after the runtime has restarted.
$updated = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Host ('Updating MSYS2 (attempt ' + $attempt + ' of 3).')
    & $shellLauncher '--login' '-lc' 'pacman -Syu --noconfirm'
    if ($LASTEXITCODE -eq 0) {
        $updated = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $updated) {
    throw 'MSYS2 update did not complete after three attempts.'
}

$bashScript = @"
set -e
export MSYS2_ARG_CONV_EXCL='*'
export MSYSTEM=UCRT64
export MINGW_PREFIX=/ucrt64
export PATH=/ucrt64/bin:`$PATH
export CC=gcc
export CXX=g++
export AR=ar
export RANLIB=ranlib
export LD=ld
export CFLAGS='-std=gnu89'
export CXXFLAGS='-std=gnu++17'
pacman -S --needed --noconfirm make diffutils m4 perl autoconf automake libtool mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
mkdir -p '$buildUnix' '$localUnix'

echo 'Building GMP from third_party/src ...'
rm -rf '$buildUnix/gmp-6.3.0'
mkdir -p '$buildUnix/gmp-6.3.0'
cd '$buildUnix/gmp-6.3.0'
ABI=64 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ '$srcUnix/gmp-6.3.0/configure' --build=x86_64-pc-msys --host=x86_64-w64-mingw32 --prefix='$localUnix' --enable-cxx --enable-static --disable-shared --disable-assembly --with-pic
make -j`$(nproc)
make install

echo 'Building NTL from third_party/src ...'
rm -rf '$buildUnix/ntl-11.6.0'
cp -R '$srcUnix/ntl-11.6.0' '$buildUnix/ntl-11.6.0'
cd '$buildUnix/ntl-11.6.0/src'
'$srcUnix/ntl-11.6.0/src/configure' HOST=x86_64-w64-mingw32 PREFIX='$localUnix' GMP_PREFIX='$localUnix' NTL_GMP_LIP=on SHARED=off
make -j`$(nproc)
make install

echo 'Configuring Umbra-Core ...'
cmake -S '$rootUnix' -B '$rootUnix/build/windows-msys2' -G Ninja -DCMAKE_BUILD_TYPE='$Configuration' -DUMBRA_DEPS_PREFIX='$localUnix'
cmake --build '$rootUnix/build/windows-msys2' --target all
"@

Write-Host 'Building GMP, NTL, and Umbra-Core with MSYS2.'
& $shellLauncher '--login' '-lc' $bashScript
if ($LASTEXITCODE -ne 0) { throw 'MSYS2 dependency build failed.' }

Write-Host ('Build completed: ' + $buildWindows)

$gmpLib = Join-Path $workspace 'third_party\local-msys2\lib\libgmp.a'
$ntlLib = Join-Path $workspace 'third_party\local-msys2\lib\libntl.a'
if (-not (Test-Path -LiteralPath $gmpLib) -or -not (Test-Path -LiteralPath $ntlLib)) {
    throw 'Build reported success, but GMP/NTL libraries were not produced.'
}
