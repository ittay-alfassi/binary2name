import json
from typing import Dict, List
import argparse
import os

BBL_HISTOGRAM = {}
CONSTRAINT_HISTOGRAM = {}


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
        if 'constraints' in node:
            for constraint in node['constraints']:
                filtered_cons = filter_constraint(constraint)
                for con in filtered_cons:
                    add_to_hist(CONSTRAINT_HISTOGRAM, con)
                    if len(con) > 1000:
                        print('look out, really big constraint in:', file_name)


def get_all_filenames(base_path: str):
    res = []
    dirs = map(lambda x: os.path.join(base_path, x), os.listdir(base_path))
    dirs = filter(os.path.isdir, dirs)

    for d in dirs:
        res += list(map(lambda x: os.path.join(d, x), os.listdir(d)))

    return res


if __name__ == '__main__':
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

    real_hist_dir = 'preprocessed_histograms/' + args.hist_dir
    if not os.path.exists(real_hist_dir):
        os.mkdir(real_hist_dir)
    with open(os.path.join(real_hist_dir, 'bbl_hist.json'), 'w') as f:
        json.dump(BBL_HISTOGRAM, f, indent=4, sort_keys=True)

    with open(os.path.join(real_hist_dir, 'constraint_hist.json'), 'w') as f:
        json.dump(CONSTRAINT_HISTOGRAM, f, indent=4, sort_keys=True)
'''  
TODO: need to separate constraints. the way to parse it is <cons1> <cons2>...
need to be careful of < and | switching places, for example |<BOOL...
the right way is < |BOOL
also remove spaces, its inconsistent
lastly check why some constraints contain the token <...>
its uninformative and harmful
'''
