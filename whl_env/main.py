#!/usr/bin/env python

# Copyright 2025 WheelOS All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from whl_env.collector import collect_system_info
from whl_env.utils import save_json


import argparse
import sys

import whl_env
from whl_env.collector import collect_system_info
from whl_env.utils import save_json


def main():
    """
    Main function to parse command-line arguments, collect system
    information, and save it to the specified JSON file.

    Follows best practices for command-line script structure.
    """
    # 1. Create an ArgumentParser object
    # The description will be shown in the help message (when running with -h or --help)
    parser = argparse.ArgumentParser(
        description="Collects system information and saves it to a JSON file."
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default="system_info.json",
        help="Path to the output JSON file (default: system_info.json)"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {whl_env.__version__}",
        help="Display the script's version and exit."
    )
    # 3. Parse the command-line arguments
    # parse_args() reads arguments from sys.argv (the command line)
    # and returns them as an object with attributes corresponding to the argument names
    args = parser.parse_args()

    # Get the value of the parsed argument
    output_filepath = args.output
    # Access other arguments like this: args.verbose

    try:
        # 4. Add user feedback/progress messages
        print(f"Collecting system information...")

        # 5. Call the core logic function
        system_info = collect_system_info()
        print("System information collected.")

        # 6. Use the parsed argument to perform the save operation
        print(f"Saving information to {output_filepath}...")
        save_json(system_info, output_filepath)
        print(f"Information successfully saved to {output_filepath}")

    except Exception as e:
        # 7. Implement basic error handling
        # Catch any exceptions that occur during collection or saving
        # Print the error message to standard error (sys.stderr)
        # It's best practice to output errors/warnings to stderr, not stdout
        print(f"An error occurred: {e}", file=sys.stderr)
        # 8. Exit with a non-zero status code to indicate failure
        # A zero status code (default exit) indicates success
        sys.exit(1)
