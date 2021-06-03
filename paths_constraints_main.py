from sym_graph import *
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

bases_dict = dict()
replacement_dict = dict()
start_time = 0


# REPR = representation
        
def time_limit_check(simulation_manager):
    global start_time
    minutes_limit = 10
    should_stop = time.time() - start_time > (60 * minutes_limit)
    if should_stop:
        print("stopped exploration")
    return should_stop

# Analyze a specific function with angr
# proj is the project object, cfg IS THE ACTUAL CONTROL-FLOW GRAPH
def analyze_func(proj, bin_func, cfg):
    print(f"started running {bin_func.name}")
    call_state = proj.factory.call_state(bin_func.addr, add_options={
        'CALLLESS': True, 'NO_SYMBOLIC_SYSCALL_RESOLUTION': True
    })
    sm = proj.factory.simulation_manager(call_state)  # Creates a simulation manager, ready to start from the specific function
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=2))
    global start_time
    start_time = time.time()
    sm.run(until=time_limit_check)
    print(f"finished {bin_func.name}")
    return sm


def get_cfg_funcs(proj, binary, excluded):
    """
    get functions that are suitable for analysis, (funcs that are defined in the binary and not libc funcs...)
    """
    return list(filter(None, [f if f.binary_name == binary and (not f.is_plt) and not f.name.startswith(
        "sub_") and not f.name.startswith("_") and f.name not in excluded else None for f in
                              proj.kb.functions.values()]))


def block_to_ins(block: angr.block.Block):
    result = []
    for ins in block.capstone.insns:
        op_str = ins.op_str
        operands = op_str.strip(" ").split(",")
        operands = [i.strip().replace("[","").replace("]", "") for i in operands if i != ""]
        parsed_ins = [ins.mnemonic] + list(filter(None, operands))
        result.append("|".join(parsed_ins).replace(" ", "|") + "|\t")
    return "|".join(result)



def remove_consecutive_pipes(s1):
    s1 = re.sub("(\|(\s)+\|)", "|", s1)
    return re.sub("(\|)+", "|", s1)


# TODO: CONSTANT OR CONSTRAINT?
def constraint_to_str(con, replace_strs=[', ', ' ', '(', ')'], max_depth=8):
    repr = con.shallow_repr(max_depth=max_depth, details=con.MID_REPR).replace('{UNINITIALIZED}', '')
    repr=re.sub("Extract\([0-9]+\, [0-9]+\,","",repr)
    for r_str in replace_strs:
        repr = repr.replace(r_str, '|')

    return remove_consecutive_pipes(repr) + "\t"


def gen_new_name(old_name):
    if re.match(r"mem", old_name):
        return 'mem_%s' % old_name.split('_')[2]
    if re.match(r"fake_ret_value", old_name):
        return 'ret'
    if re.match(r"reg", old_name):
        return re.sub("(_[0-9]+)+", '', old_name)
    if re.match(r"unconstrained_ret", old_name):
        return re.sub("(_[0-9]+)+", '', old_name[len("unconstrained_ret_") : ])
    return old_name


# TODO: CONSTANT OR CONSTRAINT?
# OH GOD.
def varify_constraints(constraints, variable_map=None, counters=None, max_depth=8):
    """
    abstract away constants from the constraints
    """
    #counters = {'mem': itertools.count(), 'ret': itertools.count()} if counters is None else counters
    variable_map = {} if variable_map is None else variable_map
    new_constraints = []
    variable_map['Extract'] = ""

    m = None
    for constraint in constraints:
        if constraint.concrete:
            continue
        for variable in constraint.leaf_asts():
            if variable.op in { 'BVS', 'BoolS', 'FPS' }:
                new_name = gen_new_name(variable.args[0])
                if re.match(r"mem", new_name):
                    if m is None :
                        m = int(new_name.split('_')[1])
                    else:
                        m = min(m,int(new_name.split('_')[1]))
                variable_map[variable.cache_key] = variable._rename(new_name)
        new_constraints.append(constraint_to_str(constraint.replace_dict(variable_map), max_depth=max_depth))
    final_constraints = []
    if m is not None:
        for constraint in new_constraints :
            split = constraint.split("|")
            for i,s in enumerate(split):
                if re.match(r"mem", s):
                    new_s = 'mem_%d' % (int(s.split('_')[1]) -m)
                    constraint = constraint.replace(s,new_s)
            final_constraints.append(constraint)
    else:
        final_constraints = new_constraints
    return variable_map, final_constraints



#remove the Numbers from the function names + tokenize the function name.
def tokenize_function_name(function_name):
    name = "".join([i for i in function_name if not i.isdigit()])
    return "|".join(name.split("_"))



def generate_dataset(train_binaries, output_name, dataset_name): #keep
    
    usable_functions_file = open("our_dataset/"+ dataset_name + "/usable_functions_names.txt", "r")
    usable_functions = [name.strip() for name in usable_functions_file]
    output_dir = f"datasets/{output_name}"
    os.makedirs(output_dir, exist_ok=True)
    analyzed_funcs = get_analyzed_funcs(output_dir)
    for binary in train_binaries:
        analyzed_funcs = analyze_binary(analyzed_funcs, binary, output_dir, usable_functions)


def analyze_binary(analyzed_funcs, binary_name, dataset_dir, usable_functions): #keep
    excluded = {'main', 'usage', 'exit'}.union(analyzed_funcs)
    proj = angr.Project(binary_name, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()  # cfg is the ACTUAL control-flow graph

    #REMOVE THIS
    print(cfg.graph.nodes())
    print(cfg.graph.edges())
    #REMOVE THIS


    binary_name = os.path.basename(binary_name)
    binary_dir = os.path.join(dataset_dir, f"{binary_name}")
    os.makedirs(binary_dir, exist_ok=True)
    funcs = get_cfg_funcs(proj, binary_name, excluded)
    print(f"{binary_name} have {len(funcs)} funcs")
    for test_func in funcs:
        if (test_func.name in analyzed_funcs) or (tokenize_function_name(test_func.name) not in usable_functions):
            print(f"skipping {tokenize_function_name(test_func.name)}")
            continue
        print(f"analyzing {binary_name}/{test_func.name}")
        output = open(os.path.join(binary_dir, f"{test_func.name}"), "w")
        analyzed_funcs.add(test_func.name)
        try:
            sm: angr.sim_manager.SimulationManager = analyze_func(proj, test_func, cfg)
            sm_to_output(sm, output, test_func.name)
        except Exception as e:
            logging.error(str(e))
            logging.error(f"got an error while analyzing {test_func.name}")
        output.close()
    return analyzed_funcs



def get_analyzed_funcs(dataset_path): #keep
    binaries = os.scandir(dataset_path)
    analyzed_funcs = set()
    for entry in binaries:
        funcs = glob(f"{entry.path}/*")
        analyzed_funcs.update(map(lambda x: x[:-len(".pkl")] if x.endswith(".pkl") else x, map(os.path.basename, funcs)))

    return analyzed_funcs

def find_target_constants(line):
    targets_mapper = dict()
    targets_counter = itertools.count()
    
    found_targets = set(re.findall(r"jmp\|0[xX][0-9a-fA-F]+|jnb\|0[xX][0-9a-fA-F]+|jnbe\|0[xX][0-9a-fA-F]+|jnc\|0[xX][0-9a-fA-F]+|jne\|0[xX][0-9a-fA-F]+|jng\|0[xX][0-9a-fA-F]+|jnge\|0[xX][0-9a-fA-F]+|jnl\|0[xX][0-9a-fA-F]+|jnle\|0[xX][0-9a-fA-F]+|jno\|0[xX][0-9a-fA-F]+|jnp\|0[xX][0-9a-fA-F]+|jns\|0[xX][0-9a-fA-F]+|jnz\|0[xX][0-9a-fA-F]+|jo\|0[xX][0-9a-fA-F]+|jp\|0[xX][0-9a-fA-F]+|jpe\|0[xX][0-9a-fA-F]+|jpo\|0[xX][0-9a-fA-F]+|js\|0[xX][0-9a-fA-F]+|jz\|0[xX][0-9a-fA-F]+|ja\|0[xX][0-9a-fA-F]+|jae\|0[xX][0-9a-fA-F]+|jb\|0[xX][0-9a-fA-F]+|jbe\|0[xX][0-9a-fA-F]+|jc\|0[xX][0-9a-fA-F]+|je\|0[xX][0-9a-fA-F]+|jz\|0[xX][0-9a-fA-F]+|jg\|0[xX][0-9a-fA-F]+|jge\|0[xX][0-9a-fA-F]+|jl\|0[xX][0-9a-fA-F]+|jle\|0[xX][0-9a-fA-F]+|jna\|0[xX][0-9a-fA-F]+|jnae\|0[xX][0-9a-fA-F]+|jnb\|0[xX][0-9a-fA-F]+|jnbe\|0[xX][0-9a-fA-F]+|jnc\|0[xX][0-9a-fA-F]+|jne\|0[xX][0-9a-fA-F]+|jng\|0[xX][0-9a-fA-F]+|jnge\|0[xX][0-9a-fA-F]+|jnl\|0[xX][0-9a-fA-F]+|jnle\|0[xX][0-9a-fA-F]+|jno\|0[xX][0-9a-fA-F]+|jnp\|0[xX][0-9a-fA-F]+|jns\|0[xX][0-9a-fA-F]+|jnz\|0[xX][0-9a-fA-F]+|jo\|0[xX][0-9a-fA-F]+|jp\|0[xX][0-9a-fA-F]+|jpe\|0[xX][0-9a-fA-F]+|jpo\|0[xX][0-9a-fA-F]+|js\|0[xX][0-9a-fA-F]+|jz\|0[xX][0-9a-fA-F]+ ", line))
    for target in found_targets:
        print("removing targets")
        target = re.sub("[a-z]+\|", "" , target)
        if target not in targets_mapper:
            targets_mapper[target] = f"target_{next(targets_counter)}"
    for target, replacement in sorted(targets_mapper.items(), key=lambda x: len(x[0]), reverse=True):
                line = line.replace(target, replacement)
    return line

def sm_to_output(sm: angr.sim_manager.SimulationManager, output_file, func_name):
    #TESTING! calling our graph generation

    res = sm_to_graph(sm, output_file, func_name)
    print(res)

    #TESTING! ending call


    counters = {'mem': itertools.count(), 'ret': itertools.count()}
    variable_map = {}
    skipped_lines = 0
    #constants_mapper = dict()
    #constants_counter = itertools.count()
    #pos_constants_mapper = dict()
    #neg_constants_mapper = dict()
    
    proj = sm._project
    for exec_paths in sm.stashes.values():
        for exec_path in exec_paths:
            blocks = [proj.factory.block(baddr) for baddr in exec_path.history.bbl_addrs]


            if len(exec_path.history.parent.recent_constraints) > 0:
                print('AHAHAHAHHAHAHAHAHAHHAHAHHAHAH')


            processsed_code = "|".join(list(filter(None, map(block_to_ins, blocks))))
            variable_map, relified_constraints = varify_constraints(exec_path.solver.constraints, variable_map=variable_map, counters=counters)
            relified_constraints = "|".join(relified_constraints)
            line = f"{tokenize_function_name(func_name)} DUM,{processsed_code}" 
            line = re.sub("r[0-9]+", "reg", line)
            line = re.sub("xmm[0-9]+", "xmm", line)
            line = find_target_constants(line)
            line += f"|CONS|{relified_constraints},DUM\n"
            
            line = re.sub(r"0[xX][0-9a-fA-F]+", "|const|", line)
            line = re.sub(r"\|[0-9]+\|", "|const|", line)     
            
            line = remove_consecutive_pipes(line)
            if len(line) <= 3000:
                output_file.write(line)
            else:
                skipped_lines += 1
    print(f"skipped {skipped_lines} lines")




#--------------------- ITTAY AND ITAMAR'S CODE---------------------#

def address_to_content(proj: angr.project.Project, baddr: int):
    full_block = proj.factory.block(baddr)
    raw_instructions = block_to_ins(full_block)
    instructions = re.sub("r[0-9]+", "reg", raw_instructions)
    instructions = re.sub("r[0-9]+", "reg", instructions)
    instructions = re.sub("xmm[0-9]+", "xmm", instructions)
    instructions = find_target_constants(instructions)
    return instructions



def sm_to_graph(sm: angr.sim_manager.SimulationManager, output_file, func_name):
    proj = sm._project
    final_states_lists = filter(None, sm.stashes.values())

    #TODO: make sure you want to treat the "deadended" and "spinning" states the same way
    final_states = [item for sublist in final_states_lists for item in sublist]
    assert(final_states != [])

    all_paths = []
    for state in final_states:
        state_path = []
        current_node = state.history
        while current_node.addr != None:
            state_path.insert(0,(current_node.addr, current_node.recent_constraints))
            current_node = current_node.parent
        all_paths.append(state_path)

    # find the root and assert it is equal for all
    initial_node = all_paths[0][0]
    for path in all_paths:
        assert(path[0][0] == initial_node[0]) # WARNING: make sure this works type-wise!

    sym_graph = SymGraph(Vertex(initial_node[0], address_to_content(proj, initial_node[0])))
    #TODO: unite into graph

    variable_map = {} #semi-global structure, used by varify_constraints
    for path in all_paths:
        for i in range(len(path)-1):
            src = Vertex(path[i][0], address_to_content(proj, path[i][0]))
            dst = Vertex(path[i+1][0], address_to_content(proj, path[i+1][0]))
            variable_map, constraint_list = varify_constraints(path[i+1][1], variable_map)
            edge = Edge(src, dst, "|".join(constraint_list)) # TODO: make sure where to take the constraint from!!!!
            sym_graph.addEdge(edge)

    return sym_graph #TODO: return the json!
    
#--------------------- ITTAY AND ITAMAR'S CODE---------------------#


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary_idx", type=int, required=True)
    parser.add_argument("--dataset", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)
    args = parser.parse_args()
    binaries = os.listdir("our_dataset/"+ args.dataset)
    binaries.sort()
    binaries = [f"our_dataset/" + args.dataset+ f"/{binary}" for binary in binaries]
    generate_dataset([binaries[args.binary_idx]], args.output, args.dataset)


if __name__ == '__main__':
    main()
