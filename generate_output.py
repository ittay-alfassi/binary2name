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


def num_in_sets(set_counts):
    return set_counts['train'] + set_counts['val'] + set_counts['test']


def update_hist(func_hist, name_parts, set):
    for func in name_parts:
        func_counts = func_hist[func]
        func_counts['free'] -= 1
        func_counts[set] += 1
    return func_hist


def set_decide(func_hist, name_parts, global_counters): #keep
    """
    here we tried to devide the inputs between the train/val/test sets such that there is more shared names between the
    sets
    :param func_hist: counters for each name, how many times it appeared in each set
    :param name_parts: names that consist the function name ( '_' seperated function name)
    :return: set to place this function in
    """
    min_func = name_parts[0]
    min_in_set = num_in_sets(func_hist[min_func])
    for func in name_parts:
        if func not in func_hist:
            continue
        curr_in_set = num_in_sets(func_hist[func])
        if curr_in_set < min_in_set:
            if curr_in_set != min_in_set or func_hist[func]['free'] > func_hist[min_func]['free']:
                continue
            min_func = func
            min_in_set = curr_in_set

    min_counts = func_hist[min_func]
    if min_counts['train'] == 0:
        return update_hist(func_hist, name_parts, 'train'), 'train'
    if min_counts['val'] == 0:
        return update_hist(func_hist, name_parts, 'val'), 'val'
    if min_counts['test'] == 0:
        return update_hist(func_hist, name_parts, 'test'), 'test'

    total_samples = sum(global_counters.values())
    if global_counters['train'] / total_samples < 0.7:
        return update_hist(func_hist, name_parts, 'train'), 'train'
    elif global_counters['val'] / total_samples < 0.2:
        return update_hist(func_hist, name_parts, 'val'), 'val'
    else:
        return update_hist(func_hist, name_parts, 'test'), 'test'


def gen_shared_name(func_hist, funcs):
    shared_funcs = []
    for func in funcs:
        if func in func_hist:
            shared_funcs.append(func)
    return shared_funcs

def generate_output(dataset_path, dataset_name): #keep
    """
    this is the experimentation code at the last experiments, we tried to add to the test/val sets only functions that
    have a name part the appeared at least 3 times in the dataset, later we tried to remove from the label the name parts
    that didn't appear more than 3 times, and wrote a function that divides the training functions in a way that
    promotes sharing names across train/val/test sets
    """
    def func_name_extractor(x):
        x = os.path.basename(x)
        return x

    binaries = list(os.scandir(dataset_path))
    import numpy as np
    np.random.seed(42)
    np.random.shuffle(binaries)
    train_output = open(os.path.join(dataset_path, dataset_name + "_train_output.txt"), "w")
    test_output = open(os.path.join(dataset_path, dataset_name + "_test_output.txt"), "w")
    val_output = open(os.path.join(dataset_path, dataset_name + "_val_output.txt"), "w")
    mapper = dict()
    all_funcs = set()
    for i, entry in enumerate(binaries):
        funcs = list(glob(f"{entry.path}/*"))
        all_funcs.update(funcs)
        for func in funcs:
            func_name = func_name_extractor(func)
            func_name = func_name.split("_")
            for label in func_name:
                if label not in mapper:
                    mapper[label] = []
                mapper[label].append(func)

    well_named_funcs = set()
    popular_names = filter(lambda x: len(x[1]) >= 3, mapper.items())

    count_func_names = open(os.path.join(dataset_path, "count_func_names.txt"), "w")
    for name, name_funcs in mapper.items():
        line= name + " " + str(len(name_funcs)) + "\n"
        count_func_names.write(line)


    names_hists = {name: {'free': len(name_funcs), 'train': 0, 'val': 0, 'test': 0} for name, name_funcs in popular_names}
    for partial in map(lambda x: x[1], filter(lambda x: len(x[1]) >= 3, mapper.items())):
        well_named_funcs.update(partial)
    well_named_funcs = list(well_named_funcs)

    # generate output
    np.random.shuffle(well_named_funcs)
    print(f"{len(all_funcs)} functions, {len(well_named_funcs)} functions with a name that contains a common word")
    # print("choosing 250 functions for test/validation")

    global_counters = {'train': 0, 'val': 0, 'test': 0}
    for i, func in enumerate(well_named_funcs):
        func_name_parts = func_name_extractor(func).split("_")
        print_name = gen_shared_name(names_hists, func_name_parts)
        names_hists, dest = set_decide(names_hists, print_name, global_counters)
        global_counters[dest] += 1
        print_name = "|".join(print_name)
        if dest == 'train':
            output = train_output
        elif dest == 'test':
            output = test_output
        else:
            output = val_output

        print(f"shared name: {print_name}")
        all_funcs.remove(func)
        with open(func, "r") as f:
            for line in f:
                line = line.split(" ")
                line[0] = print_name
                line = " ".join(line)
                output.write(line)
    train_output.close()
    test_output.close()
    val_output.close()

def main():
    parser = argparse.ArgumentParser()
    # we did this in order to parallelize the analysis process
    parser.add_argument("--output_dir", type=str, required=True)
    args = parser.parse_args()
    generate_output("datasets/" + args.output_dir, args.output_dir)

if __name__ == '__main__':
    main()
