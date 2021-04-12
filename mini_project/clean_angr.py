from typing import Dict, Any

import angr
import os
import pickle
import re
import time
import logging
import json
import argparse
import itertools
from glob import glob

def generate_dataset(train_binaries, dataset_name):
    dataset_dir = f"datasets/{dataset_name}"
    os.makedirs(dataset_dir, exist_ok=True)
    for binary in train_binaries:
        analyse_binary(binary, dataset_dir)

def analyse_binary(binary_name, dataset_dir):
    proj = angr.Project(binary_name, auto_load_libs=False)
    cfg = proj.analyses.CFGEmulated()
    funcs = proj.kb.functions.values()
    binary_name = os.path.basename(binary_name)
    binary_dir = os.path.join(dataset_dir, f"{binary_name}")
    os.makedirs(binary_dir, exist_ok=True)
    for funcInfo in funcs:
        open(os.path.join(binary_dir, f"{funcInfo.name}"), "w")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary_idx", type=int, required=True)
    args = parser.parse_args()
    binaries = os.listdir("our_dataset/nero_dataset")
    binaries.sort()
    binaries = [f"our_dataset/nero_dataset/{binary}" for binary in binaries]
    generate_dataset([binaries[args.binary_idx]], "cfg_overfitting_test_clean_emulated_all")
    print("successfully exited")



if __name__ == '__main__':
    main()
