#!/bin/bash

EXPECTED_ARGS=3;
ARGC=$#;

if [ $ARGC -ne $EXPECTED_ARGS ]; then
    echo "RUN_PPROC PARAMETERS: ./run_pproc.sh <output_dir> <dataset_dir> <parallel_lim>";
    echo "exiting";
    exit;
fi

echo "starting run"
date
BIN_COUNT=`ls "our_dataset/${2}" | wc -l`;
limit=0;
for ((i=1; i<=$BIN_COUNT; i++)); do
    echo "Starting binary ${i}";
    timeout 1000m python3 paths_constraints_main.py --binary_idx=${i} --output=$1 --dataset=$2 2> /dev/null > /dev/null &
    let limit=limit+1;
    if [ $limit == $3 ]; then
        echo "wating";
        wait;
        let limit=0;
        echo 'starting next batch';
        date;
    fi;
done;

wait
echo 'finished run'
date
python3 generate_output.py --output_dir=$1

