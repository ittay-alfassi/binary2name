import os
from datetime import datetime
from multiprocessing import Process
import argparse
from select import select
from typing import Dict, Tuple
# from random import randint


# def run_single_bin_test(output_dir: str, dataset_dir: str, bin_timeout: str, bin_idx:int):
#     res = 0
#     for _ in range(randint(2**26, 2**27)):
#         res += 1

def run_single_bin(output_dir: str, dataset_dir: str, bin_timeout: str, bin_idx: int, no_usables_file: bool):
    """Run an instance of the preprocessing script on a single binary."""

    usables_flag = "--no_usables_file " if no_usables_file else ""
    cmd_line = f"timeout {bin_timeout} python3 paths_constraints_main.py --binary_idx={bin_idx} --output={output_dir} --dataset={dataset_dir} {usables_flag} 2> /dev/null > /dev/null"
    os.system(cmd_line)


def dispatch_process(output_dir: str, dataset_dir: str, bin_timeout: str, bin_idx:int, processes: Dict[int, Tuple[int, Process]], \
                        no_usables_file: bool) -> Dict[int, Tuple[int, Process]]:
    """Dispatch a process to analyze a single binary."""

    print(f'dispatching idx {bin_idx} at {datetime.today()}')
    proc = Process(target=run_single_bin, args=(output_dir, dataset_dir, bin_timeout, bin_idx, no_usables_file))
    proc.start()
    processes[proc.sentinel] = (bin_idx, proc)
    return processes


def collect_process(processes: Dict[int, Tuple[int, Process]]):
    # Wait for tick from finished sentinel
    finished_procs, _, _ = select(processes.keys(), [], [])

    # Remove it from the processes and sentinels lists
    for sentinel in finished_procs:
        print(f'idx {processes[sentinel][0]} completed at {datetime.today()}')
        del processes[sentinel]


def run_preprocess(output_dir: str, dataset_dir: str, cpu_no: int, bin_timeout: str, no_usables_file: bool, base_dataset_dir:str = "our_dataset"):
    """Run the preprocessing on all files in the dataset_dir."""

    processes: Dict[int, Tuple[int, Process]] = {}

    # Calculate number of binaries
    full_dataset_dir = os.path.join(base_dataset_dir, dataset_dir)
    bin_count = len(os.listdir(full_dataset_dir))

    # Fill CPUs with jobs
    curr_bin = 0
    for _ in range(min(cpu_no, bin_count)):
        processes = dispatch_process(output_dir, dataset_dir, bin_timeout, curr_bin, processes, no_usables_file)
        curr_bin += 1

    while curr_bin < bin_count:
        collect_process(processes)

        # Build and run a new process
        processes = dispatch_process(output_dir, dataset_dir, bin_timeout, curr_bin, processes, no_usables_file)
        curr_bin += 1

    # Wait for all remaining processes
    while processes:
        collect_process(processes)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', type=str, required=True)
    parser.add_argument('--dataset_dir', type=str, required=True)
    parser.add_argument('--cpu_no', type=int, default=64)
    parser.add_argument('--bin_timeout', type=str, default='1000m')
    parser.add_argument("--no_usables_file", dest="no_usables_file", action="store_true")
    args = parser.parse_args()
    run_preprocess(args.output_dir, args.dataset_dir, args.cpu_no, args.bin_timeout, args.no_usables_file)
    print('DONEDONEDONE!!!!!!!')


if __name__ == "__main__":
    main()

# python3 run_pproc.py --output_dir nero_train_out --dataset_dir nero_ds/TRAIN --cpu_no 55 --no_usables_file > nero_pproc_log.txt 2> nero_pproc_error.txt &