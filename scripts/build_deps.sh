#!/usr/bin/env bash
set -euo pipefail

GMP_VERSION="6.3.0"
NTL_VERSION="11.6.0"

GMP_FOLDER="gmp-${GMP_VERSION}"
NTL_FOLDER="ntl-${NTL_VERSION}"

WORKSPACE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${WORKSPACE_DIR}/third_party/src"
BUILD_DIR="${WORKSPACE_DIR}/third_party/build"
LOCAL_DIR="${WORKSPACE_DIR}/third_party/local"

JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)}"

rm -rf "${BUILD_DIR}" "${LOCAL_DIR}"
mkdir -p "${BUILD_DIR}" "${LOCAL_DIR}"

echo "Building GMP in ${BUILD_DIR}/${GMP_FOLDER} with ${JOBS} jobs..."

mkdir -p "${BUILD_DIR}/${GMP_FOLDER}"
cd "${BUILD_DIR}/${GMP_FOLDER}"

"${SRC_DIR}/${GMP_FOLDER}/configure" \
    --prefix="${LOCAL_DIR}" \
    --enable-cxx \
    --enable-static \
    --disable-shared \
    --with-pic

make -j"${JOBS}"
make install

echo "GMP built and installed to ${LOCAL_DIR}"

echo "Building NTL in ${BUILD_DIR}/${NTL_FOLDER} with ${JOBS} jobs..."

cp -R "${SRC_DIR}/${NTL_FOLDER}" "${BUILD_DIR}/${NTL_FOLDER}"
cd "${BUILD_DIR}/${NTL_FOLDER}/src"

./configure \
    PREFIX="${LOCAL_DIR}" \
    GMP_PREFIX="${LOCAL_DIR}" \
    NTL_GMP_LIP=on \
    SHARED=off

make -j"${JOBS}"
make install

echo "NTL built and installed to ${LOCAL_DIR}"