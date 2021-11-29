from angr import Project
from typing import Set

def is_ELF(file_path: str) -> bool:
    with open(file_path, "rb") as f:
        magic = f.read(4)
    return magic == b"\x7fELF"


def get_func_names(binary_name: str, dataset_dir: str, analyzed_functions: Set[str]):
    """
    get functions that are suitable for analysis, (funcs that are defined in the binary and not libc funcs...)
    """
    proj = Project(binary_name, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    return list(filter(None, [f if f.binary_name == binary and (not f.is_plt) and not f.name.startswith(
        "sub_") and not f.name.startswith("_") and f.name not in excluded else None for f in
                              proj.kb.functions.values()]))