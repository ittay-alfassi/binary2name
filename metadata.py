


def get_instruction_count(block_dict: dict, delim="    ") -> int:
    assert "instructions" in block_dict
    return len(list(filter(None, block_dict["instructions"].split(delim))))


def get_constraint_count(block_dict: dict, delim="    ") -> int:
    assert "constraints" in block_dict
    constraints = block_dict["constraints"]

    if constraints == []:
        return 0

    if type(constraints[0]) == str:  # Support old version, in which every path is represented at as a string.
        constraints = [list(filter(None, con.split(delim))) for con in constraints]
    
    lengths = [len(con_list) for con_list in constraints]
    return sum(lengths)


def get_constraint_len(block_dict: dict, delim="   ") -> int:
    assert "constraints" in block_dict
    constraints = block_dict["constraints"]

    if constraints == []:
        return 0

    if type(constraints[0]) == str:  # Support old version, in which every path is represented at as a string.
        constraints = [list(filter(None, con.split(delim))) for con in constraints]
    
    lengths = [[len(con) for con in con_list] for con_list in constraints]
    lengths = [sum(con_list) for con_list in constraints]
    return sum(lengths)