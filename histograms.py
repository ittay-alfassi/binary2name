import json
from typing import Dict

BBL_HISTOGRAM = {}
CONSTRAINT_HISTOGRAM = {}

def add_to_hist(histogram: Dict[str, int], entry: str):
    if entry in histogram:
        histogram[entry] += 1
    else:
        histogram[entry] = 1
        
def is_entry_junk(entry: str):
    return entry == ''


def register_tokens(graph_json: dict):
    
    # Add the node data
    nodes = graph_json['GNN_DATA']['nodes']
    for bbl in nodes.values():
        if not is_entry_junk(bbl):
            add_to_hist(BBL_HISTOGRAM, bbl)
    
    # Add the edge data
    edges = graph_json['GNN_DATA']['edges']
    for edge in edges:
        constraint = edge['CONSTRAINT']
        if not is_entry_junk(constraint):
            add_to_hist(CONSTRAINT_HISTOGRAM, constraint)



if __name__ == '__main__':
    # load a specific example
    with open('POCs/chosen_example.json') as f:
        example_dict = json.load(f)

    register_tokens(example_dict)
    print(CONSTRAINT_HISTOGRAM)