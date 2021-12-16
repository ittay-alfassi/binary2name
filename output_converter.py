import os
import shutil
import json
from typing import List, Dict, Tuple
from jsonpickle import encode
import argparse
from tqdm import tqdm
import random
import re

CONSTRAINT_DELIM = '|'
OUR_API_TYPE = 'F'  # Meaningless - simply here to notify this is not a NORMAL_PROC or INDIRECT_PROC in the Nero Preprocessing.


def prettify_constraint(block_constraints: List[str]) -> List[str]:
    """
    goals: take out garbage from the constraint like EXTRACT(X,X,X) and BOOL __X__
    strip ' ' and '<' and '>'
    reduce very big chunks of a constraints to single generalized constraint.

    structure of block_constraints:
    It is a list of strings.
    Each string represents the constraints of a single path through the CFG.
    The constraints of each single path are delimited with a '|' character.
    """
    converted_block_constraints = []
    for path_constraints in block_constraints:
        converted_path_constraints = []
        for constraint in path_constraints.split('|'):
            # Remove the <Bool ... > prefix and suffix of each constraint.
            converted_constraint = constraint.replace('Bool', '').replace('<', '').replace('>', '').strip()
            # Clean the representation of boolean ops: remove the '__' prefix and suffix.
            converted_constraint = re.sub(r'__(?P<op>[a-zA-Z]+)__',
                                          r'\g<op>',
                                          converted_constraint)
            converted_path_constraints.append(converted_constraint)
        # Style back to the original format
        converted_block_constraints.append('|'.join(converted_path_constraints))
    return converted_block_constraints


def style_json(filename: str) -> None:
    with open(filename, 'r') as function_file:
        data_dict = json.load(function_file)

    styled_dict = data_dict
    graph_nodes = data_dict['GNN_DATA']['nodes']
    prettify_constraint.variable_dict = {}
    for node in graph_nodes:
        node['constraints'] = prettify_constraint(node['constraints'])

    with open(filename, 'w') as function_file:
        json.dump(styled_dict, function_file, indent=4)


def collect_to_file(file_list: List[str], filename: str) -> None:
    collective_files = ''
    for function_file in file_list:
        with open(function_file, 'r') as file:
            collective_files += file.read() + '\n'

    with open(os.path.join('../ready_data', filename), 'w') as file:
        file.write(collective_files)


def separate_arguments(args):
    arguments = []
    delimiter_count = 0
    begin_index = 0
    end_index = 0

    while end_index < len(args):
        letter = args[end_index]
        if letter == '(':
            delimiter_count += 1
        if letter == ')':
            delimiter_count -= 1
        if letter == ',' and delimiter_count == 0:
            arguments.append(args[begin_index:end_index])
            begin_index = end_index + 2  # (, )
            end_index = begin_index
        end_index += 1

    arguments.append(args[begin_index:])
    if delimiter_count != 0:
        print('Warning! delimiters are not equal on both sides, check for inconsistencies')
        print('arguments', arguments)
        exit(1)
    return arguments


def dissolve_function_call(str_call):
    delimiter_open = str_call.find('(')
    delimiter_close = str_call.rfind(')')
    arguments = separate_arguments(str_call[delimiter_open + 1:delimiter_close])
    call_name = str_call[:delimiter_open]
    return call_name, arguments


def convert_argument(argument: str) -> tuple:
    if 'mem' in argument:
        argument_type = 'MEMORY'
    elif 'reg' in argument:
        argument_type = 'REGISTER'
    elif '0x' in argument:
        argument_type = 'CONSTANT'
    elif argument.startswith(OUR_API_TYPE):
        argument_type = 'FUNCTION_CALL'
    else:
        argument_type = 'UNKNOWN'
    return argument_type, argument


class ConstraintAst:
    def __init__(self, value='dummy_name', children=None):
        self.value = value
        self.children = children

    def remove_filler_nodes(self, bad_name: str, argnum: int) -> None:
        if self.value == bad_name:
            assert len(self.children) >= argnum
            self.value = self.children[argnum - 1].value
            self.children = self.children[argnum - 1].children

        if self.children is None:  # if the grandchild is none, meaning the son which replaced the father is a leaf
            return

        for child in self.children:
            child.remove_filler_nodes(bad_name, argnum)

    def __export_ast_to_list(self) -> List:
        list_repr = []
        if self.children is None:
            return []

        for child in self.children:
            list_repr += child.__export_ast_to_list()

        my_call = (self.value, [child.value for child in self.children])
        list_repr.append(my_call)
        return list_repr

    def convert_list_to_nero_format(self) -> List:
        """
        convert all function calls existing in the list into the nero format.
        we roll the list, popping from the start, converting then appending to the end
        because we do that len(list) times, there !should! be no problems...
        """
        constraints_as_calls = self.__export_ast_to_list()
        for i in range(len(constraints_as_calls)):
            func_name, arguments = constraints_as_calls.pop(0)
            function_call = [func_name]
            for arg in arguments:
                function_call.append(convert_argument(arg))
            converted_function_call = tuple(function_call)
            constraints_as_calls.append(converted_function_call)
        return constraints_as_calls


def get_constraint_ast(constraint: str) -> ConstraintAst:
    constraint_ast = ConstraintAst(children=[])
    function_name, arguments = dissolve_function_call(constraint)
    function_name = OUR_API_TYPE + function_name
    constraint_ast.value = function_name
    for arg in arguments:
        if '(' in arg or ')' in arg:
            constraint_ast.children.append(get_constraint_ast(arg))
        else:
            constraint_ast.children.append(ConstraintAst(value=arg))
    return constraint_ast


class OutputConvertor:
    def __init__(self):
        self.filenames = []

    def backup_all_files(self, dataset_name):
        """
        update the self.filename list to contain all the files in the given dataset
        we presume the given dataset is a folder in the same directory as the script
        we copy the dataset first to a different name directory so working on it will not harm
        the previous model.
        """
        src = dataset_name
        dest = 'Converted_' + dataset_name
        if os.path.isdir(dest):
            print('converted dir already exists, removing')
            shutil.rmtree(dest)

        print('Started copying dataset for backup')
        shutil.copytree(src, dest)
        print('Finished backup, starting to scan files')

    def load_all_files(self, dataset_name: str):
        dataset_name = 'Converted_' + dataset_name
        bin_folders = list(
            map(lambda x: os.path.join(dataset_name, x) if x[-4:] != '.txt' else None, os.listdir(dataset_name)))
        bin_folders = list(filter(None, bin_folders))

        for path in bin_folders:
            self.filenames += list(map(lambda x: os.path.join(path, x), os.listdir(path)))

        for file in self.filenames:
            if not file.endswith('.json'):
                self.filenames.remove(file)
        print('Finished scanning and adding all files\n', 'added {} files'.format(len(self.filenames)))

    def convert_dataset(self, only_style: bool):
        print('Starting to convert json files')
        for filename in tqdm(self.filenames):
            print(f'converting {filename}')
            style_json(filename)
            if not only_style:
                self.__convert_json(filename)
            print(f'{filename} converted')
        print('Done converting, data should be ready')

    def __convert_edges(self, edges: List) -> List:
        converted_edges = []
        for edge in edges:
            new_edge = (edge['src'], edge['dst'])
            converted_edges.append(new_edge)
        return converted_edges

    def __convert_constraints_to_reprs(self, block_constraints: List[str]) -> List:
        with open('conversion_config.json', 'r') as config_file:
            data = json.load(config_file)
            MAX_TOKENS_PER_CONSTRAINT = data['MAX_TOKENS_PER_CONSTRAINT']

        nero_formatted_constraints = []
        for path_constraints_string in block_constraints:
            constraints = path_constraints_string.split(CONSTRAINT_DELIM)
            for constraint in constraints:
                # get the constraint AST
                constraint_ast = get_constraint_ast(constraint)
                # filter all unwanted functions
                constraint_ast.remove_filler_nodes(OUR_API_TYPE + 'Extract', 3)
                # convert to nero format and save
                nero_formatted_constraints += constraint_ast.convert_list_to_nero_format()

        return nero_formatted_constraints  # TODO: use the MAX_TOKENS parameter to cut the list according the the rules...

    def __convert_nodes(self, nodes: List) -> Dict:
        converted_nodes = {}
        for node in nodes:
            converted_constraint = self.__convert_constraints_to_reprs(node['constraints'])
            if not converted_constraint:
                converted_nodes[node['block_addr']] = []
            else:
                converted_nodes[node['block_addr']] = converted_constraint

        return converted_nodes

    def __convert_json(self, filename: str):
        if os.path.getsize(filename) == 0:
            print(f'Warning! file {filename} is empty. Skipping.')
            return

        with open(filename, 'r') as function_file:
            initial_data = json.load(function_file)

        # convert operation - according to the Nero format
        exe_name = filename.split(os.sep)[-2]
        package_name = 'unknown'
        function_name = filename.split(os.sep)[-1][:-5]

        exe_name_split = list(filter(None, exe_name.split('_')))
        if len(exe_name_split) > 1:
            exe_name = exe_name_split[-1]
            package_name = exe_name_split[-2]

        converted_data = {'func_name': OUR_API_TYPE + function_name, 'GNN_data': {}, 'exe_name': exe_name,
                          'package': package_name}
        converted_data['GNN_data']['edges'] = self.__convert_edges(initial_data['GNN_DATA']['edges'])
        converted_data['GNN_data']['nodes'] = self.__convert_nodes(initial_data['GNN_DATA']['nodes'])

        with open(filename, 'w') as function_file:
            jp_obj = encode(converted_data)
            function_file.write(jp_obj)


class OrganizeOutput:
    def __init__(self, file_locations, train_percentage, test_percentage, validate_percentage):
        self.train_percentage = train_percentage
        self.validate_percentage = validate_percentage
        self.test_percentage = test_percentage
        self.file_locations = file_locations

    def print_information_and_fix(self):
        if self.train_percentage + self.test_percentage + self.validate_percentage != 100:
            print('CRITICAL! : all percentages don\'t add to 100')
        if self.train_percentage < self.validate_percentage + self.test_percentage:
            print('Warning! : not enough training')
        # TODO: add more warning and errors if needed

        self.test_percentage /= 100
        self.train_percentage /= 100
        self.validate_percentage /= 100

    def collect_files(self):
        """
        Aggregate all training, testing and validation files into single files.
        """
        train_length = int(len(self.file_locations) * self.train_percentage)
        test_length = int(len(self.file_locations) * self.test_percentage)
        validate_length = len(self.file_locations) - train_length - test_length

        print('num of train files: {}'.format(train_length))
        print('num of test files: {}'.format(test_length))
        print('num of validate files: {}'.format(validate_length))

        random.shuffle(self.file_locations)

        training_files = self.file_locations[:train_length]
        testing_files = self.file_locations[train_length:train_length + test_length]
        validating_files = self.file_locations[train_length + test_length:]
        collect_to_file(training_files, 'train.json')
        collect_to_file(testing_files, 'test.json')
        collect_to_file(validating_files, 'validate.json')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset_name', type=str, required=True,
                        help='enter dataset directory name (the one that is in preprocessed_data')
    parser.add_argument('--train', type=int, required=True, help='percent of functions in the train file')
    parser.add_argument('--test', type=int, required=True, help='percent of functions in the test file')
    parser.add_argument('--val', type=int, required=True, help='percent of functions in the validate file')
    parser.add_argument('--only_collect', dest='only_collect', action='store_true')
    parser.add_argument('--only_style', dest='only_style', action='store_true')
    args = parser.parse_args()

    out_convertor = OutputConvertor()
    os.chdir('preprocessed_data')
    if not args.only_collect:
        out_convertor.backup_all_files(args.dataset_name)
        out_convertor.load_all_files(args.dataset_name)
        out_convertor.convert_dataset(args.only_style)
    else:
        out_convertor.load_all_files(args.dataset_name)

    collector = OrganizeOutput(out_convertor.filenames, args.train, args.test, args.val)
    collector.print_information_and_fix()
    buff = input('continue? [y/n]\n')
    if 'y' in buff or 'Y' in buff:
        collector.collect_files()


if __name__ == '__main__':
    main()
