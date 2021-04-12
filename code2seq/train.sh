#!/bin/bash
###########################################################
# Change the following values to train a new model.
# type: the name of the new model, only affects the saved file name.
# dataset: the name of the dataset, as was preprocessed using preprocess.sh
# test_data: by default, points to the validation set, since this is the set that
#   will be evaluated after each training iteration. If you wish to test
#   on the final (held-out) test set, change 'val' to 'test'.
type=$1
dataset_name=$1
data_dir=data/$1
data=${data_dir}/${dataset_name}
data_train=${data_dir}/${dataset_name}.train.c2s
date_test="${data_dir}/${dataset_name}.test.c2s"
test_data=${data_dir}/${dataset_name}.val.c2s
model_dir=models/${type}
vocab_size=$(./preprocess.sh ${dataset_name} | grep "target vocab size" | cut -d " " -f5)
## calculate max_path_length
len1=$(python get_max_length.py -path ${data_train} ) 
len2=$(python get_max_length.py -path ${date_test} )
len3=$(python get_max_length.py -path ${test_data} )
max=len1 
max=$(( len2 > max ? len2 : max ))
max_len=$(( len3 > max ? len3 : max ))
echo ${max_len}
vocab_Size=vocab_size/2
#vocab_size=$(./preprocess.sh ${dataset_name} | grep "target vocab size" | cut -d " " -f5)
echo ${vocab_size}
mkdir -p ${model_dir}
python -u code2seq.py --max_path_len ${max_len} --vocab_max ${vocab_size} --data ${data} --test ${test_data} --save_prefix ${model_dir}/model &

#type=final
#dataset_name=final
#data_dir=data/final
#data=${data_dir}/${dataset_name}
#test_data=${data_dir}/${dataset_name}.val.c2s
#model_dir=models/${type}
#
#mkdir -p ${model_dir}
#python code2seq.py --data ${data} --test ${test_data} --save_prefix ${model_dir}/model  &
#
#
#type=constantless_overfitting
#dataset_name=constantless_overfitting
#data_dir=data/constantless_overfitting
#data=${data_dir}/${dataset_name}
#test_data=${data_dir}/${dataset_name}.val.c2s
#model_dir=models/${type}
#
#mkdir -p ${model_dir}
#python code2seq.py --data ${data} --test ${test_data} --save_prefix ${model_dir}/model &
#

wait
