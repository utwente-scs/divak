#! /bin/bash

set -e


if [[ -z "${WORKDIR}" ]]; then
  WORKDIR=${PWD}
  echo "WARNING: WORKDIR is not set, using ${WORKDIR}"
fi


sudo apt-get install git gcc python3 python3-dev python3-venv

# Install dependency of our S2E plugins
wget https://github.com/nlohmann/json/releases/download/v3.10.5/json.hpp
sudo mkdir /usr/include/nlohmann && sudo mv json.hpp /usr/include/nlohmann/

# Fetch s2e-env and set it up
cd ${WORKDIR}
git clone https://github.com/s2e/s2e-env.git
/bin/bash -c "cd ${WORKDIR}/s2e-env && python3 -m venv venv && . venv/bin/activate && pip install --upgrade pip && pip install ."

# Fetch S2E and set up environment
/bin/bash -c "cd ${WORKDIR}/s2e-env && source ${WORKDIR}/s2e-env/venv/bin/activate && s2e init ../s2e"

# Patch the files we modified in S2E
cd ${WORKDIR}/s2e/source/s2e/libs2ecore/src
patch -b < ${WORKDIR}/s2e-patches/CorePluginInterface.cpp.patch
patch -b < ${WORKDIR}/s2e-patches/S2EExecutionStateRegisters.cpp.patch
cd ${WORKDIR}/s2e/source/s2e/libs2ecore/include/s2e
patch -b < ${WORKDIR}/s2e-patches/CorePlugin.h.patch
patch -b < ${WORKDIR}/s2e-patches/S2EExecutionStateRegisters.h.patch

# Copy the custom plugins and make sure they're also built
cp -a ${WORKDIR}/s2e-plugins/. ${WORKDIR}/s2e/source/s2e/libs2eplugins/src/s2e/Plugins/
cd ${WORKDIR}/s2e/source/s2e/libs2eplugins/src
patch -b < ${WORKDIR}/s2e-patches/CMakeLists.txt.patch

# Build S2E
cd ${WORKDIR}/s2e
/bin/bash -c "source ${WORKDIR}/s2e-env/venv/bin/activate && source ${WORKDIR}/s2e/s2e_activate && s2e build"
/bin/bash -c "source ${WORKDIR}/s2e-env/venv/bin/activate && source ${WORKDIR}/s2e/s2e_activate && s2e image_build -d debian-9.2.1-x86_64"

# Fetch Clang
cd ${WORKDIR}
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
mkdir clang-13.0.1
tar -xvf clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz -C clang-13.0.1 --strip-components 1
rm clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
LLVM_DIR=${WORKDIR}/clang-13.0.1

# Build the LLVM pass
cd ${WORKDIR}/llvmPass
mkdir -p build  && cd build
CXX=${LLVM_DIR}/bin/clang cmake -DLLVM_DIR=${LLVM_DIR}/lib/cmake/llvm/ ..
make

# Install dependencies of static analysis
cd ${WORKDIR}/staticAnalysis
/bin/bash -c "python3 -m venv venv && . venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt"

