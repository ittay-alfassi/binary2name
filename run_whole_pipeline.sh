#!/bin/bash

echo "Welcome! This is an execution bash script for Ittay and Itamar's results."
echo "Remember - If you're running on Lambda, usr srun!"
echo "Also remember to have all your modules installed - angr and TensorFlow 1 included."

# Extract data
chmod +x extract_data.sh
./extract_data.sh

echo "Running symbolic analysis"
python3 run_pproc.py --output_dir nero --dataset_dir nero_ds --log_dir nero_logs --cpu_no 30 --mem_limit 45 --no_usables_file

echo "Running output processing and conversion"
python3 output_converter.py --dataset_name nero

echo "Copying to nero's internal data directory"
cp ready_data/ready_nero/train.json nero/procedure_representations/raw/bin2name/train.json
cp ready_data/ready_nero/validation.json nero/procedure_representations/raw/bin2name/validation.json
cp ready_data/ready_nero/test.json nero/procedure_representations/raw/bin2name/test.json

echo "Running Nero's preprocessing"
cd nero
python3 preprocess.py -trd procedure_representations/raw/bin2name/train.json -ted procedure_representations/raw/bin2name/test.json -vd procedure_representations/raw/bin2name/validation.json -o data

echo "Running Nero"
python3 -u gnn.py  --data procedure_representations/preprocessed/data --test procedure_representations/preprocessed/data.val --save new_model/model --gnn_layers 4 > nero_out_log.txt 2> nero_error_log.txt

echo "That's All, Folks!"
