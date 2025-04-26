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

from typing import Dict, Any
from whl_env.utils import run_command


def get_wheelos_version() -> Dict[str, Any]:
    """
    Gets the current Git commit hash (HEAD) for the repository in the current
    working directory. This hash serves as a unique identifier for the
    software version's state.

    Uses run_command to execute the git command.

    Returns:
        Dict[str, Any]: A dictionary containing git information.
                        On success: {'wheelos_version': {'commit_hash': '...', 'status': 'success'}}
                        On failure: {'wheelos_version': {'commit_hash': None, 'status': 'error', 'message': '...'}}
    """
    # Use run_command to execute 'git rev-parse HEAD'
    # This command outputs the full hash of the current commit
    commit_hash = run_command(["git", "rev-parse", "HEAD"])

    if commit_hash:
        # Command succeeded, return the hash
        return {
            "wheelos_version": {
                "commit_hash": commit_hash,
                "status": "success"
            }
        }
    else:
        # Command failed (not a git repo, git not installed, etc.)
        # run_command already printed a warning to stderr
        return {
            "wheelos_version": {
                "commit_hash": None,
                "status": "error",
                "message": "Could not retrieve Git commit hash. Ensure 'git' is installed and the script is run from within a Git repository."
            }
        }


if __name__ == "__main__":
    # Example usage
    version_info = get_wheelos_version()
    print(version_info)
