#!/bin/bash

for SCRIPT in ./run_*sh
do
  if [ -f $SCRIPT -a -x $SCRIPT ]
  then
    echo -e "\n## Running $SCRIPT"
    $SCRIPT --test
  fi
done