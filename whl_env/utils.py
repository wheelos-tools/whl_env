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

import subprocess
import hashlib
import os
import glob
import sys
import json
from typing import Dict, List, Optional, Any


def get_file_hash(filepath: str, hash_algorithm: str = 'sha256') -> str:
    """
    Calculates the hash of a given file.

    Args:
        filepath (str): The path to the file.
        hash_algorithm (str): The name of the hash algorithm to use (e.g., 'sha256').
                              Defaults to 'sha256'.

    Returns:
        str: The hexadecimal hash digest of the file if successful.
        str: An error message string if the file cannot be read (e.g., not found, permission denied).
    """
    if not os.path.isfile(filepath):
        return "Error: File not found"
    try:
        hasher = hashlib.new(hash_algorithm)
        # Read file in binary mode to avoid encoding issues and hash correctly
        with open(filepath, 'rb') as f:
            # Read in chunks to handle large files efficiently (4KB chunks)
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except PermissionError:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error reading file: {e}"


def collect_files_and_hashes(directories: List[str], patterns: List[str] = None) -> List[Dict[str, str]]:
    """
    Scans specified directories for files matching patterns and collects
    their paths and SHA256 hashes. Handles non-existent directories and
    permission errors during listing or reading.

    Args:
        directories (List[str]): A list of directories to scan.
        patterns (List[str], optional): A list of glob patterns to match file names
                                        (e.g., ['*.rules', '*.service']).
                                        If None, all files in the directories are considered.
                                        Defaults to None.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary
                              contains 'path' and 'hash_sha256' for a file.
                              The hash_sha256 value will be an error string
                              if hashing failed for that specific file.
    """
    collected_files = []
    for directory in directories:
        # Check if the directory exists and is a directory
        if not os.path.isdir(directory):
            # print(f"Warning: Directory not found or not a directory: {directory}", file=sys.stderr) # Optional warning
            continue

        # Define search patterns, default to all files if none provided
        search_patterns = patterns if patterns is not None else ['*']

        for pattern in search_patterns:
            # Construct the full pattern for glob
            full_pattern = os.path.join(directory, pattern)
            try:
                # Use glob to find paths matching the pattern
                # Filter results to ensure they are files, not directories found by glob
                files_in_dir = [f for f in glob.glob(
                    full_pattern) if os.path.isfile(f)]
            except PermissionError:
                print(
                    f"Warning: Permission denied to list directory: {directory}", file=sys.stderr)
                continue  # Skip if directory listing is denied
            except Exception as e:
                print(
                    f"Warning: Error listing directory {directory}: {e}", file=sys.stderr)
                continue  # Skip on other errors

            # Process each file found
            for filepath in files_in_dir:
                # Use the helper function to get hash or error
                file_hash = get_file_hash(filepath)
                collected_files.append(
                    {'path': filepath, 'hash_sha256': file_hash})

    return collected_files


def run_command(command: List[str], timeout: int = 10) -> Optional[str]:
    """
    Helper function to run a command and return its stdout if successful on Linux.
    The command is run without a shell.

    Args:
        command (List[str]): The command and its arguments as a list of strings.
                             e.g., ['ls', '-l', '/tmp']
        timeout (int): Maximum time in seconds to wait for the command to complete.
                       Defaults to 10 seconds.

    Returns:
        Optional[str]: The stripped standard output of the command if it runs successfully
                       and exits with code 0 within the timeout.
                       Returns None if the command fails (non-zero exit code), is not found,
                       times out, or encounters any other execution error.
    """
    try:
        # Use shell=False is the default and safer
        # capture_output=True to capture stdout/stderr
        # text=True to decode output as text
        # check=True will raise CalledProcessError if the command returns a non-zero exit code
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        # Return stripped stdout if command was successful (check=True implies returncode is 0)
        return result.stdout.strip()
    except FileNotFoundError:
        # Command not found in PATH
        print(f"Warning: Command not found: {command[0]}", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        # Command returned a non-zero exit code
        print(
            f"Warning: Command failed: {' '.join(e.cmd)} with exit code {e.returncode}", file=sys.stderr)
        # Optionally print stderr for debugging: print(f"Stderr: {e.stderr.strip()}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired as e:
        # Command timed out
        print(
            f"Warning: Command timed out: {' '.join(e.cmd)} after {e.timeout} seconds", file=sys.stderr)
        # Optionally print stdout/stderr up to timeout: print(f"Stdout: {e.stdout.strip()}\nStderr: {e.stderr.strip()}", file=sys.stderr)
        return None
    except Exception as e:
        # Catch any other unexpected errors during command execution
        print(
            f"Warning: An unexpected error occurred while running command {' '.join(command)}: {e}", file=sys.stderr)
        return None


def read_sys_file(filepath: str) -> Optional[str]:
    """Helper to safely read a sysfs file and return stripped content or None on error."""
    if not os.path.isfile(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except (PermissionError, OSError) as e:
        # print(f"Warning: Could not read sysfs file {filepath}: {e}", file=sys.stderr) # Optional warning
        return None


def save_json(data: Dict[str, Any], filename: str = "system_info.json") -> None:
    """
    Saves a dictionary containing system information to a JSON file.

    Args:
        data (Dict[str, Any]): The dictionary containing the system information.
        filename (str): The name of the file to save the JSON data to.
                        Defaults to "system_info.json".
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"System information successfully saved to {filename}")
    except IOError as e:
        print(f"Error saving system information to {filename}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while saving the file: {e}")
