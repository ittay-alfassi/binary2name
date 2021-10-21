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
from sim_tree import SimTreeNode

def build_exec_tree(project: angr.Project,
                        bin_func: angr.knowledge_plugins.Function,
                        cfg: angr.analyses.CFGFast):

    print(f"building sym-exec tree for {bin_func.name}")

    # Build initial state and SM
    call_state = project.factory.call_state(bin_func.addr, add_options={
        'CALLLESS': True, 'NO_SYMBOLIC_SYSCALL_RESOLUTION': True
    })
    sm = project.factory.simulation_manager(call_state)
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=2))

    root = SimTreeNode(call_state)
    
