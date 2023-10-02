#!/bin/bash

miss_jump=$1
dlist=$2

for i in {0..9}
do
   $miss_jump $dlist $i &
done
