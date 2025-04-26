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
    Gets detailed Git information for the repository in the current working directory,
    including commit hash, current branch or tag, and commit details.

    Uses run_command to execute git commands.

    Returns:
        Dict[str, Any]: A dictionary containing git information.
                        On success: {'wheelos_version': {
                                        'commit_hash': '...',
                                        'ref': 'branch_name_or_tag', # Current branch or tag
                                        'commit_details': '...',   # e.g., commit subject line
                                        'status': 'success'
                                    }}
                        On failure: {'wheelos_version': {
                                        'commit_hash': None,
                                        'ref': None,
                                        'commit_details': None,
                                        'status': 'error',
                                        'message': '...'
                                    }}
    """
    version_info: Dict[str, Any] = {
        "commit_hash": None,
        "ref": None,
        "commit_details": None,
        "status": "error",
        "message": "Could not retrieve Git information. Ensure 'git' is installed and the script is run from within a Git repository."
    }

    # 1. Get the current commit hash
    # This command outputs the full hash of the current commit
    commit_hash = run_command(["git", "rev-parse", "HEAD"])
    if not commit_hash:
        # If getting hash fails, likely not a git repo or git not found.
        # run_command already printed a warning.
        return {"wheelos_version": version_info}

    version_info["commit_hash"] = commit_hash
    # Assume success unless subsequent commands fail critically
    version_info["status"] = "success"

    # 2. Get current tag or branch
    # Try to get an exact tag match first
    tag = run_command(["git", "describe", "--tags",
                      "--exact-match", commit_hash])
    if tag:
        version_info["ref"] = tag
    else:
        # If no exact tag match, get the current branch name
        branch = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        if branch and branch != "HEAD":  # "HEAD" means detached HEAD, prefer commit hash alone in this case unless tagged
            version_info["ref"] = branch
        # If branch is None or "HEAD" and no tag, ref remains None.

    # 3. Get commit details (e.g., subject line)
    # Using git log with pretty format to get the subject line of the latest commit
    # %s: subject
    # %an: author name
    # %ad: author date (format: ISO 8601 strict)
    commit_detail_format = "%s (%an, %ad)"
    commit_details = run_command(
        ["git", "log", "-1", f"--pretty=format:{commit_detail_format}", commit_hash])
    if commit_details:
        version_info["commit_details"] = commit_details
        # Clean up potential multi-line output from subject (though %s usually is just first line)
        version_info["commit_details"] = version_info["commit_details"].splitlines()[
            0]

    # Check if at least commit_hash was successful to determine overall success status
    if version_info["commit_hash"]:
        version_info["status"] = "success"
        # Remove the generic error message if successful
        if "message" in version_info:
            del version_info["message"]
    else:
        # This case should ideally be caught by the initial check, but as a fallback:
        version_info["status"] = "error"
        version_info["message"] = "Failed to retrieve essential Git information (commit hash)."

    return {"wheelos_version": version_info}


# Example usage (assuming you are in a git repository)
if __name__ == "__main__":
    version = get_wheelos_version()
    import json
    print(json.dumps(version, indent=2))
