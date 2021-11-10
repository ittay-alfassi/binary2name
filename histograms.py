import json
from typing import Dict, List
import argparse
import os
from metadata import *

BBL_HISTOGRAM = {}
CONSTRAINT_HISTOGRAM = {}
TOTAL_STATS_HISTOGRAM = []
TOTAL_NODE_NUMBER = 0
TOTAL_CONSTRAINT_NUM = 0
TOTAL_CONSTRAINT_LEN = 0


def add_to_hist(histogram: Dict[str, int], entry: str):
    if entry in histogram:
        histogram[entry] += 1
    else:
        histogram[entry] = 1


def is_entry_junk(entry: str):
    return entry == 'no_instructions'


def filter_constraint(constraint: str) -> List[str]:
    return list(map(lambda x: x.strip(), constraint.split('    |')))


def register_tokens(graph_json: dict, file_name: str):
    # Add the node data
    nodes = graph_json['GNN_DATA']['nodes']
    for node in nodes:
        if not is_entry_junk(node['instructions']):
            add_to_hist(BBL_HISTOGRAM, node['instructions'])

        for constraint in node['constraints']:
            filtered_cons = filter_constraint(constraint)
            for con in filtered_cons:
                add_to_hist(CONSTRAINT_HISTOGRAM, con)


def get_all_filenames(base_path: str):
    res = []
    dirs = map(lambda x: os.path.join(base_path, x), os.listdir(base_path))
    dirs = filter(os.path.isdir, dirs)

    for d in dirs:
        res += list(map(lambda x: os.path.join(d, x), os.listdir(d)))

    return res


def calc_total_stats(file_dict: dict, filename: str) -> None:
    global TOTAL_NODE_NUMBER
    global TOTAL_CONSTRAINT_NUM
    global TOTAL_CONSTRAINT_LEN
    file_stats_dict = calc_constraint_stats(file_dict, filename)
    TOTAL_STATS_HISTOGRAM.append(file_stats_dict)
    TOTAL_NODE_NUMBER += file_stats_dict['total_node_num']
    TOTAL_CONSTRAINT_NUM += file_stats_dict['constraint_total_count']
    TOTAL_CONSTRAINT_LEN += file_stats_dict['constraint_len_total']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base_dir', type=str, required=True)
    parser.add_argument('--hist_dir', type=str, required=True)
    args = parser.parse_args()
    filenames = get_all_filenames('preprocessed_data/' + args.base_dir)
    for filename in filenames:
        if os.stat(filename).st_size == 0:
            continue
        with open(filename) as f:
            file_dict = json.load(f)
            register_tokens(file_dict, filename)
            calc_total_stats(file_dict['GNN_DATA'], filename)

    real_hist_dir = 'preprocessed_histograms/' + args.hist_dir
    if not os.path.exists(real_hist_dir):
        os.mkdir(real_hist_dir)

    with open(os.path.join(real_hist_dir, 'bbl_hist.json'), 'w') as f:
        json.dump(BBL_HISTOGRAM, f, indent=4, sort_keys=True)

    with open(os.path.join(real_hist_dir, 'constraint_hist.json'), 'w') as f:
        json.dump(CONSTRAINT_HISTOGRAM, f, indent=4, sort_keys=True)

    with open(os.path.join(real_hist_dir, 'dataset_hist.json'), 'w') as f:
        data_dict = {'total_node_number': TOTAL_NODE_NUMBER, 'total_constraint_number': TOTAL_CONSTRAINT_NUM,
                     'total_constraint_len': TOTAL_CONSTRAINT_LEN, 'constraint_num_per_node': TOTAL_CONSTRAINT_NUM / TOTAL_NODE_NUMBER,
                     'constraint_len_per_node': TOTAL_CONSTRAINT_LEN / TOTAL_NODE_NUMBER}
        json.dump(data_dict, f, indent=4, sort_keys=True)

    with open(os.path.join(real_hist_dir, 'per_file_hist.json'), 'w') as f:
        json.dump(TOTAL_STATS_HISTOGRAM, f, indent=4, sort_keys=True)
'''  
TODO: need to separate constraints. the way to parse it is <cons1> <cons2>...
need to be careful of < and | switching places, for example |<BOOL...
the right way is < |BOOL
also remove spaces, its inconsistent
lastly check why some constraints contain the token <...>
its uninformative and harmful
'''

if __name__ == '__main__':
    main()
