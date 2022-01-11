#!/bin/sh

if [ $# -lt 1 ]
then
  echo "Please provide a program path"
  exit
fi

TOOL_PATH="${HOME}/SBR"

create_lib_list() {

  local prog=$1
  
  local progname=`basename $prog`
  
  ldd $prog | awk '{print $3}' | sed '/^$/d' > /tmp/${progname}_libs.dat
  
  local outfile="${TOOL_PATH}/testsuite/deps/${progname}_file_list.dat"
  echo "${prog}" > ${outfile}

  while read line
  do
    local lib=`basename $line`
    local computed=`grep "${lib}$" ${outfile} | wc -w`
    if [ $computed -gt 0 ]
    then
      continue
    fi
    create_lib_list $line
    cat ${TOOL_PATH}/testsuite/deps/${lib}_file_list.dat >> ${outfile}
  done < /tmp/${progname}_libs.dat

  sort -u ${outfile} > /tmp/${progname}_file_list.dat
  cp /tmp/${progname}_file_list.dat ${outfile}
}


create_lib_list $1
