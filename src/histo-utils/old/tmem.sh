#!/bin/bash
( for h in 1000 2000 4000 8000 16000 32000 64000 128000 160000 175000; do
        time ./testmem $h || exit 
  done ) > tmemres 2>&1
