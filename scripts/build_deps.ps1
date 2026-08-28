# build_deps.ps1
#
# Windows (MSYS2/MinGW-w64) counterpart of scripts/build_deps.sh.
# Builds GMP and NTL from third_party/src into third_party/local so that
# CMakeLists.txt finds them without extra configuration.
#
# Requirements:
#   - MSYS2 (https://www.msys2.org/), a recent version that provides the
#     UCRT64 toolchain.  Install it with:
#         winget install MSYS2.MSYS2
#     or set the MSYS2_ROOT environment variable to the install directory.
#   - The MinGW-w64 toolchain is required, not MSVC: the project links the
#     static libraries by their .a names (libntl.a, libgmp.a, libgmpxx.a),
#     which is the convention MinGW-w64 produces.
#
# After the dependencies are installed, build the project with the MinGW
# toolchain, e.g. from a PowerShell prompt in the project root:
#     cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
#     cmake --build build
#     ctest --test-dir build --output-on-failure
#
# Usage:
#     powershell -ExecutionPolicy Bypass -File scripts/build_deps.ps1

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$ThirdPartyDir = Join-Path $RootDir "third_party"
$SrcDir = Join-Path $ThirdPartyDir "src"
$BuildDir = Join-Path $ThirdPartyDir "build"
$LocalDir = Join-Path $ThirdPartyDir "local"

$GmpVersion = "6.3.0"
$NtlVersion = "11.6.0"
$GmpFolder = "gmp-$GmpVersion"
$NtlFolder = "ntl-$NtlVersion"

# --- locate MSYS2 ----------------------------------------------------------

$MsysRoot = $env:MSYS2_ROOT
if (-not $MsysRoot) {
    $MsysRoot = "C:\msys64"
}
$MsysBash = Join-Path $MsysRoot "usr\bin\bash.exe"
if (-not (Test-Path $MsysBash)) {
    Write-Error "MSYS2 not found at $MsysRoot. Install MSYS2 (winget install MSYS2.MSYS2) or set the MSYS2_ROOT environment variable."
}

# --- check the bundled sources ---------------------------------------------

if (-not (Test-Path (Join-Path $SrcDir "$GmpFolder\configure"))) {
    Write-Error "GMP source not found: $SrcDir\$GmpFolder"
}
if (-not (Test-Path (Join-Path $SrcDir "$NtlFolder\src\configure"))) {
    Write-Error "NTL source not found: $SrcDir\$NtlFolder"
}

# --- helpers ---------------------------------------------------------------

# Convert a Windows path to an MSYS path, e.g. C:\a\b -> /c/a/b.
function ConvertTo-MsysPath([string]$Path) {
    $p = $Path -replace '\\', '/'
    if ($p -match '^([A-Za-z]):(.*)$') {
        $p = "/" + $matches[1].ToLower() + $matches[2]
    }
    return $p
}

function Invoke-InMsys([string]$BashScript) {
    & $MsysBash -lc $BashScript
    if ($LASTEXITCODE -ne 0) {
        Write-Error "MSYS2 command failed with exit code $LASTEXITCODE"
    }
}

# --- bootstrap the MinGW toolchain -----------------------------------------

Write-Host "Updating MSYS2 and installing base-devel and the UCRT64 MinGW-w64 toolchain..."
Invoke-InMsys @'
set -euo pipefail
# The first upgrade updates the MSYS2 runtime itself and may restart the
# shell; a second run finishes any remaining updates.  Rerunning this
# script is always safe because the package installs use --needed.
pacman -Syu --noconfirm
pacman -Syu --noconfirm
pacman -S --needed --noconfirm base-devel mingw-w64-ucrt-x86_64-gcc
'@

# --- prepare directories ---------------------------------------------------

Write-Host "Cleaning $BuildDir and $LocalDir ..."
Remove-Item -Recurse -Force $BuildDir, $LocalDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $BuildDir, $LocalDir | Out-Null

# Export the MSYS paths; the UCRT64 profile makes gcc/g++/make resolve to
# the MinGW-w64 toolchain inside bash.
$env:MSYSTEM = "UCRT64"
$env:UMBRA_GMP_SRC = ConvertTo-MsysPath (Join-Path $SrcDir $GmpFolder)
$env:UMBRA_NTL_SRC = ConvertTo-MsysPath (Join-Path $SrcDir $NtlFolder)
$env:UMBRA_GMP_BUILD = ConvertTo-MsysPath (Join-Path $BuildDir $GmpFolder)
$env:UMBRA_NTL_BUILD = ConvertTo-MsysPath (Join-Path $BuildDir $NtlFolder)
$env:UMBRA_LOCAL = ConvertTo-MsysPath $LocalDir

# --- build GMP -------------------------------------------------------------

Write-Host "Building GMP $GmpVersion ..."
Invoke-InMsys @'
set -euo pipefail
mkdir -p "$UMBRA_GMP_BUILD"
cd "$UMBRA_GMP_BUILD"
"$UMBRA_GMP_SRC/configure" \
    --prefix="$UMBRA_LOCAL" \
    --enable-cxx \
    --enable-static \
    --disable-shared \
    --with-pic
make -j"$(nproc)"
make install
'@
Write-Host "GMP built and installed to $LocalDir"

# --- build NTL -------------------------------------------------------------

Write-Host "Building NTL $NtlVersion ..."
Invoke-InMsys @'
set -euo pipefail
cp -R "$UMBRA_NTL_SRC" "$UMBRA_NTL_BUILD"
cd "$UMBRA_NTL_BUILD/src"
./configure \
    PREFIX="$UMBRA_LOCAL" \
    GMP_PREFIX="$UMBRA_LOCAL" \
    NTL_GMP_LIP=on \
    SHARED=off
make -j"$(nproc)"
make install
'@
Write-Host "NTL built and installed to $LocalDir"

# --- verify the installed layout -------------------------------------------

$RequiredFiles = @(
    (Join-Path $LocalDir "lib\libntl.a"),
    (Join-Path $LocalDir "lib\libgmp.a"),
    (Join-Path $LocalDir "lib\libgmpxx.a"),
    (Join-Path $LocalDir "include\NTL\ZZ.h"),
    (Join-Path $LocalDir "include\gmp.h")
)
foreach ($file in $RequiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "missing $file"
    }
}

Write-Host "Dependencies built and installed to $LocalDir"
Write-Host "Next: cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++"
