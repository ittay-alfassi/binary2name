#!/bin/bash

limit=0
for i in {0..100} ; do
    echo "${i}";
    timeout 1000m python3 paths_constraints_main.py --binary_idx=${i} --output=$1 --dataset $2  &
    let limit=limit+1;
    if (( limit == 10 )); then
        echo "wating";
        wait;
        let limit=0;
    fi;
done;

wait
python3 generate_output.py --output_dir=$1

