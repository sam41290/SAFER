#!/bin/bash

TOOL_PATH=`pwd`

INSTALL_DIR=$1

# Install system dependencies (skip sudo if already root)
if [ "$(id -u)" -eq 0 ]; then
  apt-get -y install ocaml camlp4-extra camlp4 exuberant-ctags
else
  sudo apt-get -y install ocaml camlp4-extra camlp4 exuberant-ctags
fi

tar -xf auto.tgz
mkdir -p run/tmp

# Install capstone
tar -xf capstone-4.0.2.tar.gz
cd capstone-4.0.2/
if [ "$(id -u)" -eq 0 ]; then
  ./make.sh install
else
  sudo ./make.sh install
fi
cd ..

path=`echo "${TOOL_PATH}" | sed 's/\//\\\\\/\/g'`

sed -i "/#define TOOL_PATH/c #define TOOL_PATH \"${path}\/\"" run/config.h

rand_configs=($(ls -1 ${TOOL_PATH}/run/randmodes/*.h))
for f in "${rand_configs[@]}"
do
  sed -i "/#define TOOL_PATH/c #define TOOL_PATH \"${path}\/\"" ${f}
done

export LD_LIBRARY_PATH=/usr/lib/ocaml

cd ${TOOL_PATH}/src/SBD/lift/lift-code
make clean
make all

cd ${TOOL_PATH}/src/SBD/analysis/
make clean
make all

cd ${TOOL_PATH}/jtable_cache/
make clean
make all

# Build all apps
for app_dir in ${TOOL_PATH}/apps/*/; do
  if [ -f "${app_dir}/Makefile" ]; then
    echo "Building app: $(basename $app_dir)"
    cd "${app_dir}"
    make clean
    make -j$(nproc)
    cd ${TOOL_PATH}
  fi
done

cd ${TOOL_PATH}

ln -sf ${TOOL_PATH}/instrument.sh ${INSTALL_DIR}/instrument.sh 2>/dev/null || true
ln -sf ${TOOL_PATH}/testsuite/instrument-coreutils.sh ${INSTALL_DIR}/instrument-coreutils.sh 2>/dev/null || true
ln -sf ${TOOL_PATH}/testsuite/instrument-suite.sh ${INSTALL_DIR}/instrument-suite.sh 2>/dev/null || true
ln -sf ${TOOL_PATH}/testsuite/instrument_prog.sh ${INSTALL_DIR}/instrument_prog.sh 2>/dev/null || true

mkdir -p ${HOME}/instrumented_libs

sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/apps/run.sh 2>/dev/null || true
sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/scripts/instrument_prog.sh 2>/dev/null || true
sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/scripts/instrument_batch.sh 2>/dev/null || true
sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/scripts/instrument.sh 2>/dev/null || true
sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/scripts/instrument_binary.sh 2>/dev/null || true
sed -i "s|^TOOL_PATH=.*|TOOL_PATH=\"${TOOL_PATH}\"|" ${TOOL_PATH}/scripts/find_libs.sh 2>/dev/null || true
