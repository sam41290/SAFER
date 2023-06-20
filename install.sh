
#!/bin/bash

TOOL_PATH=`pwd`

sudo apt-get -y install ocaml
sudo apt-get -y install camlp4-extra
sudo apt-get -y install camlp4
sudo apt-get -y install ctags

tar -xf auto.tgz
mkdir run/tmp

#installing capstone

tar -xf capstone-4.0.2.tar.gz
cd capstone-4.0.2/
sudo ./make.sh install
cd ..

path=`echo "${TOOL_PATH}" | sed 's/\//\\\\\//g'`

sed -i "/#define TOOL_PATH/c #define TOOL_PATH \"${path}\/\"" run/config.h

rand_configs=($(ls -1 ${TOOL_PATH}/run/randmodes/*.h))
for f in "${rand_configs[@]}"
do
  sed -i "/#define TOOL_PATH/c #define TOOL_PATH \"${path}\/\"" ${f}
done

export LD_LIBRARY_PATH=/usr/lib/ocaml
cp ${TOOL_PATH}/run/randmodes/NoRand.h ${TOOL_PATH}/run/config.h


cd ${TOOL_PATH}/src/lift/lift-code
make clean
make all


cd ${TOOL_PATH}/src/rtl-analysis/
make clean
make libanalysis.so

cd ${TOOL_PATH}

#cd jmp-table-analysis
#cd lift/lift-code/
#make clean
#make all
#cd ../../
#make clean
#make


ln -sf ${TOOL_PATH}/instrument.sh ${HOME}/instrument.sh

ln -sf ${TOOL_PATH}/testsuite/instrument-coreutils.sh ${HOME}/instrument-coreutils.sh
ln -sf ${TOOL_PATH}/testsuite/instrument-suite.sh ${HOME}/instrument-suite.sh

ln -sf ${TOOL_PATH}/testsuite/instrument_prog.sh ${HOME}/instrument_prog.sh

#ln -sf ${TOOL_PATH}/testsuite/replace_libs.sh ${HOME}/replace_libs.sh

ln -sf ${TOOL_PATH}/jmp-table-analysis/asm_format.sh ${HOME}/asm_format.sh

mkdir ${HOME}/instrumented_libs

#sudo mkdir /inst_libs

