#!/bin/sh

max=40

i=0

prog=$1

while [ $i -lt $max ]
do

  echo "---------------------------------"
  echo "execution number: $i"
  echo "---------------------------------"

  ./run.sh ${prog} > ${prog}.log
  cmd="${prog}_2 --help"
  echo "cmd: $cmd"
  $cmd
  if [ $? -ne 0 ]
  then
    echo "Failure encountered!! exiting"
    exit
  fi
  i=`expr $i + 1`
done
