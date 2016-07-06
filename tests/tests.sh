#!/bin/bash

for SCRIPT in ./run_*sh
do
  if [ -f $SCRIPT -a -x $SCRIPT ]
  then
    $SCRIPT
  fi
done