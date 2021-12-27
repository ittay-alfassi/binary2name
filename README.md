# Binary2Name
## Automatic Detection for Binary Code Functionality

This project was developed by [Ittay Alfassi](https://github.com/ittay-alfassi) and [Itamar Juwiler](https://github.com/itamar1208) as a part of the [Project in Computer Security](https://webcourse.cs.technion.ac.il/236349/Spring2021/) course at Technion - Israel Institute of Technology. 
Project Advisors: Dr. Gabi Nakibly and Dr. Yaniv David. 

## Introduction:
The main motivation for this project is to be a helpful tool for researchers of binary code.
We started with binary datasets as input and used [angr](https://angr.io), a symbolic analysis tool to get an intermediate representation of the code.
From there, came the most extensive step in the project which was to preprocess the intermediate code in preparation to be used as input to a neural network. We used a deep neural network adopted from [Nero](https://github.com/tech-srl/nero), which is intended for the same problem but used a different approach.

We suggest reading our report about this project (final_report.pdf) before running the code.

Getting started:
=====================
## Requirements:
    -   Python 3.6 and up
    -   all packages shown in requirements.txt 

## Full preprocessing and training:

The bash script `run_whole_pipeline.sh` runs the project pipeline as a whole, and should achieve the results presented in the report.

If you're running on the Lambda server, make sure to use srun!

### Extract our datasets: 
The bash script `extract_data.sh` extracts all the zipped data that we used and generated.

## Source code file description:
  * `paths_constraints_main.py` is the python script that performs the basic symbolic execution. It reads its datasets from the `our_dataset` directory and saves its results to the `preprocessed_data` directory.

  * `output_converter.py` is the file that applies constraint styling.  It reads its input from `preprocessed_data/<dir_name>`. The converted output will be saved under `ready_data/Converted_<dir_name>`.
    The aggregated output will be saved under `ready_data/ready_<dir_name>`.

  * `nero/preprocess.py` is the file that processes the files from `ready_data` and prepares them for execution by Nero. It reads its input from the any specified file, but usually uses `nero/procedure_representations/raw`.

  * `nero/gnn.py` is the file that activates Nero's model. It reads its input from any specified file, but usually uses `nero/procedure_representations/preprocessed`.

For more information on the Nero source code, reading the README of [Nero](https://github.com/tech-srl/nero) is recommended.