import os
import time
from random import randint
from datetime import datetime
from multiprocessing import Process
import argparse
from select import select
from typing import Dict, Tuple


def run_single_bin(output_dir: str, dataset_dir: str, bin_timeout: str, bin_idx:int):
    cmd_line = f"timeout {bin_timeout} python3 paths_constraints_main.py --binary_idx={bin_idx} --output={output_dir} --dataset={dataset_dir} 2> /dev/null > /dev/null"
    os.system(cmd_line)


def dispatch_process(output_dir: str, dataset_dir: str, bin_timeout: str, bin_idx:int, processes: Dict[int, Process]) -> Dict[int, Tuple[int, Process]]:
    print(f'dispatching idx {bin_idx} at {datetime.today()}')
    proc = Process(target=run_single_bin, args=(output_dir, dataset_dir, bin_timeout, bin_idx))
    proc.start()
    processes[proc.sentinel] = (bin_idx, proc)
    return processes


def run_preprocess(output_dir: str, dataset_dir: str, cpu_no: int, bin_timeout: str, base_dataset_dir:str = "our_dataset"):
    processes = {}

    # Calculate number of binaries
    full_dataset_dir = os.path.join(base_dataset_dir, dataset_dir)
    bin_count = len(os.listdir(full_dataset_dir))

    # Fill CPUs with jobs
    curr_bin = 0
    for _ in range(min(cpu_no, bin_count)):
        processes = dispatch_process(output_dir, dataset_dir, bin_timeout, curr_bin, processes)
        curr_bin += 1

    while curr_bin < bin_count:
        # Wait for tick from finished sentinel
        finished_procs, _, _ = select(processes.keys(), [], [])

        # Remove it from the processes and sentinels lists
        for sentinel in finished_procs:
            print(f'idx {processes[sentinel][0]} completed at {datetime.today()}')
            del processes[sentinel]

        # Build and run a new process
        processes = dispatch_process(output_dir, dataset_dir, bin_timeout, curr_bin, processes)
        curr_bin += 1

    # Wait for all remaining processes
    for sentinel, (idx, proc) in processes.items():
        print(f'idx {idx} completed at {datetime.today()}')
        proc.join()



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', type=str, required=True)
    parser.add_argument('--dataset_dir', type=str, required=True)
    parser.add_argument('--cpu_no', type=int, default=64)
    parser.add_argument('--bin_timeout', type=str, default='1000m')
    args = parser.parse_args()
    run_preprocess(args.output_dir, args.dataset_dir, args.cpu_no, args.bin_timeout)
    print('DONEDONEDONE!!!!!!!')


if __name__ == "__main__":
    main()

# python3 run_pproc.py --output_dir dyn_test --dataset_dir coreutils_ds > dyn_pproc_log.txt &