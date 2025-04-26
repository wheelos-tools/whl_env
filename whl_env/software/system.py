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

import os
import sys
import platform
from typing import Dict, List, Any

from whl_env.utils import get_file_hash, collect_files_and_hashes, run_command


def get_system_info() -> Dict[str, Any]:
    """
    Collects basic system information including OS, Python version, and GCC version.

    Returns:
        Dict[str, Any]: A dictionary containing basic system information.
    """
    # Use the new run_command helper to get GCC version
    # run_command returns None if the command fails or is not found
    gcc_version_output = run_command(["gcc", "--version"])
    if gcc_version_output:
        # Extract the first line from the command output
        gcc_version = gcc_version_output.split("\n")[0]
    else:
        # run_command returned None, meaning gcc command failed or wasn't found
        gcc_version = "Not Found or Error"

    return {"system_info": {
        "os": platform.platform(),  # e.g., 'Linux-5.15.0-91-generic-x86_64-with-glibc2.35'
        "python": platform.python_version(),  # e.g., '3.10.12'
        "gcc": gcc_version}
    }


def get_environment_variables() -> Dict[str, Dict[str, str]]:
    """
    Retrieves all environment variables currently set for the process.

    Returns:
        Dict[str, Dict[str, str]]: A dictionary containing a single key 'environment_variables'
                                  whose value is a dictionary of all environment variables.
    """
    # os.environ is a dictionary-like object containing environment variables.
    # This does not involve running external commands via subprocess.
    # Note: Environment variables can be sensitive. Consider filtering in a real app.
    return {"environment_variables": dict(os.environ)}


def get_udev_rules() -> List[Dict[str, str]]:
    """
    Collects udev rules files and their SHA256 hashes from standard directories.
    Does not involve running external commands via subprocess.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, each with 'path' and 'hash_sha256'.
    """
    udev_directories = [
        '/etc/udev/rules.d/',
        '/usr/lib/udev/rules.d/',
        '/run/udev/rules.d/'  # Less common for static rules, but good to check
    ]
    # Uses collect_files_and_hashes which does file I/O, not subprocess
    return collect_files_and_hashes(
        udev_directories, patterns=['*.rules'])


def get_systemd_units() -> List[Dict[str, str]]:
    """
    Collects systemd unit files and main configuration files from standard directories
    and calculates their SHA256 hashes. Does not involve running external commands
    via subprocess.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, each with 'path' and 'hash_sha256'.
    """
    systemd_directories = [
        # System-specific unit files (highest priority)
        '/etc/systemd/system/',
        '/run/systemd/system/',       # Runtime-generated system unit files
        # Distribution-provided system unit files (lowest priority)
        '/usr/lib/systemd/system/',
        # User-specific unit files (system-wide, higher priority)
        '/etc/systemd/user/',
        '/run/systemd/user/',         # Runtime-generated user unit files
        # Distribution-provided user unit files (lower priority)
        '/usr/lib/systemd/user/',
        # Main systemd configuration files (e.g., journald.conf)
        '/etc/systemd/',
        '/usr/lib/systemd/',          # Distribution-provided systemd config files
        # Note: ~/.config/systemd/user/ is user-specific and harder to collect generically
        # Note: Systemd drop-in directories (*.d) are not explicitly listed but covered if patterns include them
    ]
    # Common systemd unit file extensions and some general config files
    # Using glob patterns like '*.service' will capture files in drop-in directories like *.service.d/*.conf
    systemd_patterns = [
        '*.service', '*.socket', '*.device', '*.mount', '*.automount', '*.swap',
        '*.target', '*.path', '*.timer', '*.slice', '*.scope',
        # Explicitly list some main config files if patterns like '*' in /etc/systemd/ are not desired
        'systemd.conf', 'journald.conf', 'logind.conf', 'resolved.conf', 'networkd.conf',
        'user.conf'
    ]
    # Uses collect_files_and_hashes which does file I/O, not subprocess
    return collect_files_and_hashes(systemd_directories, patterns=systemd_patterns)


def get_user_groups() -> Dict[str, List[Dict[str, Any]]]:
    """
    Collects user and group information from /etc/passwd and /etc/group by reading files.
    Note: This does NOT collect password hashes from /etc/shadow for security reasons
          and typically requires root privileges for shadow/gshadow. Reading passwd/group
          might also require elevated privileges depending on system configuration.
          This function does NOT use subprocess. Alternatively, 'getent passwd' and
          'getent group' could be used with run_command, but file reading is shown here.

    Returns:
        Dict[str, List[Dict[str, Any]]]: A dictionary containing lists for 'users'
                                         and 'groups' with their details.
    """
    users = []
    groups = []

    # Read /etc/passwd
    passwd_file = '/etc/passwd'
    if os.path.exists(passwd_file):
        try:
            with open(passwd_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    fields = line.split(':')
                    if len(fields) >= 6:  # passwd typically has 7 fields, check for at least 6
                        try:
                            users.append({
                                'name': fields[0],
                                'uid': int(fields[2]),
                                'gid': int(fields[3]),
                                # fields[4] is GECOS field (comment)
                                'home': fields[5],
                                'shell': fields[6] if len(fields) > 6 else ''
                            })
                        except ValueError:
                            print(
                                f"Warning: Skipping malformed line in {passwd_file}: {line}", file=sys.stderr)
                            continue  # Skip lines with non-integer uid/gid
        except PermissionError:
            print(
                f"Warning: Permission denied to read {passwd_file}", file=sys.stderr)
        except Exception as e:
            print(f"Error reading {passwd_file}: {e}", file=sys.stderr)

    # Read /etc/group
    group_file = '/etc/group'
    if os.path.exists(group_file):
        try:
            with open(group_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    fields = line.split(':')
                    if len(fields) >= 3:  # group typically has 4 fields, check for at least 3
                        try:
                            groups.append({
                                'name': fields[0],
                                'gid': int(fields[2]),
                                'members': fields[3].split(',') if len(fields) > 3 and fields[3] else []
                            })
                        except ValueError:
                            print(
                                f"Warning: Skipping malformed line in {group_file}: {line}", file=sys.stderr)
                            continue  # Skip lines with non-integer gid
        except PermissionError:
            print(
                f"Warning: Permission denied to read {group_file}", file=sys.stderr)
        except Exception as e:
            print(f"Error reading {group_file}: {e}", file=sys.stderr)

    return {"user_groups": {"users": users, "groups": groups}}


def get_kernel_param_config() -> Dict[str, List[Dict[str, str]]]:
    """
    Collects kernel parameter configuration files (/etc/sysctl.conf and *.conf in /etc/sysctl.d/)
    and their SHA256 hashes. Does NOT read live kernel parameters from /proc/sys/.
    Does not involve running external commands via subprocess.

    Returns:
        Dict[str, List[Dict[str, str]]]: A dictionary containing a list of dictionaries
                                         for 'kernel_parameter_config_files'.
    """
    sysctl_directories = [
        '/etc/sysctl.d/',
        '/usr/lib/sysctl.d/',  # Lower priority config directory
        '/run/sysctl.d/'      # Runtime config directory
    ]
    # Collect files with *.conf extension from directories
    sysctl_files = collect_files_and_hashes(
        sysctl_directories, patterns=['*.conf'])

    # Add /etc/sysctl.conf explicitly if it exists and wasn't already collected
    main_sysctl_conf = '/etc/sysctl.conf'
    if os.path.isfile(main_sysctl_conf):
        # Check if already in the list (unlikely with current patterns, but safe)
        if not any(f['path'] == main_sysctl_conf for f in sysctl_files):
            file_hash = get_file_hash(main_sysctl_conf)
            sysctl_files.append(
                {'path': main_sysctl_conf, 'hash_sha256': file_hash})

    # Sort for consistent output
    sysctl_files.sort(key=lambda x: x['path'])

    return {"kernel_parameter_config_files": sysctl_files}


def get_ssh_config_files() -> Dict[str, List[Dict[str, str]]]:
    """
    Collects main SSH server and client configuration files and their SHA256 hashes.
    Does not involve running external commands via subprocess.

    Returns:
        Dict[str, List[Dict[str, str]]]: A dictionary containing a list of dictionaries
                                         for 'ssh_config_files'.
    """
    ssh_directories = [
        '/etc/ssh/',
        # /run/ssh usually contains runtime keys/sockets, not config files
        # '/run/ssh/'
    ]
    # Explicitly list main config files by name
    ssh_patterns = [
        'sshd_config',  # SSH server configuration
        'ssh_config'   # SSH client configuration
        # Note: Does not include files in sshd_config.d/ or ssh_config.d/
        # or host-specific config files in user homes (~/.ssh/config)
    ]
    return {"ssh_config_files": collect_files_and_hashes(ssh_directories, patterns=ssh_patterns)}


def get_crontab_files() -> Dict[str, List[Dict[str, str]]]:
    """
    Collects system-wide crontab files (/etc/crontab, /etc/cron.d/) and
    attempts to collect user crontab files from /var/spool/cron/crontabs/.
    Calculates their SHA256 hashes. Does not involve running external commands
    via subprocess directly, relies on file reading.

    Note: Accessing user crontabs in /var/spool/cron/crontabs/ typically
          requires root privileges. Files that cannot be read will show an error in hash.

    Returns:
        Dict[str, List[Dict[str, str]]]: A dictionary containing a list of dictionaries
                                         for 'crontab_files'.
    """
    crontab_directories = [
        '/etc/',                  # For /etc/crontab
        '/etc/cron.d/',           # System-wide cron tasks defined in separate files
        # User crontabs (requires root to read others)
        '/var/spool/cron/crontabs/'
    ]
    # Specify patterns: the main crontab file and files in cron.d/, user crontabs
    crontab_patterns = [
        'crontab',       # The main /etc/crontab file
        '*.cron',        # Common extension for files in /etc/cron.d/
        # Catch user crontabs in /var/spool/cron/crontabs/ (named after user)
        '*'
    ]

    collected = collect_files_and_hashes(
        crontab_directories, patterns=crontab_patterns)

    # Optional: Filter out /etc/crontab if collected by '*' pattern in /etc/
    # This ensures consistent output and avoids potential duplicates if pattern handling changes
    # filtered_collected = [f for f in collected if f['path'] == '/etc/crontab' or '/etc/cron.d/' in f['path'] or '/var/spool/cron/crontabs/' in f['path']]

    # Sort for consistent output
    collected.sort(key=lambda x: x['path'])

    return {"crontab_files": collected}


# --- Main Execution ---
def main():
    """
    Main function to collect and print all specified system configuration details.
    """
    print("--- Linux System Configuration Collection ---")
    print("Note: Accessing some files or running certain commands may require root privileges.")
    print("Files/commands requiring elevated privileges might show 'Permission denied' or 'Not Found/Error'.")

    all_config_data: Dict[str, Any] = {}

    # Collect System Info
    print("\n--- System Information ---")
    sys_info = get_system_info()
    all_config_data.update(sys_info)
    # Print preview
    for key, value in sys_info['system_info'].items():
        print(f"{key.replace('_', ' ').capitalize()}: {value}")

    # Collect Environment Variables
    # Note: Printing all env vars can expose sensitive information.
    # The function returns them, decide whether to print fully or just keys.
    print("\n--- Environment Variables ---")
    env_vars_data = get_environment_variables()
    all_config_data.update(env_vars_data)
    print(
        f"Total environment variables found: {len(env_vars_data['environment_variables'])}")
    # Optional: Print env var keys for overview
    # print("Keys:", sorted(env_vars_data['environment_variables'].keys()))

    # Collect udev Rules
    print("\n--- udev Rules Files and Hashes (SHA256) ---")
    udev_data = {"udev_rules": get_udev_rules()}
    all_config_data.update(udev_data)
    if udev_data['udev_rules']:
        # Sort by path for consistent output
        udev_data['udev_rules'].sort(key=lambda x: x['path'])
        for file_info in udev_data['udev_rules']:
            print(f"Path: {file_info['path']}")
            print(f"Hash: {file_info['hash_sha256']}")
            # print("-" * 10) # Optional separator
        print(f"Total udev rules files found: {len(udev_data['udev_rules'])}")
    else:
        print("No udev rules files found in common directories.")

    # Collect systemd Units
    print("\n--- systemd Configuration Files and Hashes (SHA256) ---")
    systemd_data = {"systemd_config_files": get_systemd_units()}
    all_config_data.update(systemd_data)
    if systemd_data['systemd_config_files']:
        # Sort by path for consistent output
        systemd_data['systemd_config_files'].sort(key=lambda x: x['path'])
        for file_info in systemd_data['systemd_config_files']:
            print(f"Path: {file_info['path']}")
            print(f"Hash: {file_info['hash_sha256']}")
            # print("-" * 10) # Optional separator
        print(
            f"Total systemd config files found: {len(systemd_data['systemd_config_files'])}")
    else:
        print("No systemd configuration files found in common directories.")

    # Collect User and Group Info
    print("\n--- User and Group Information ---")
    user_group_data = get_user_groups()
    all_config_data.update(user_group_data)
    # Optional: Sort users/groups by name for consistent output
    user_group_data['user_groups']['users'].sort(
        key=lambda x: x.get('name', ''))
    user_group_data['user_groups']['groups'].sort(
        key=lambda x: x.get('name', ''))

    print(f"Total users found: {len(user_group_data['user_groups']['users'])}")
    print(
        f"Total groups found: {len(user_group_data['user_groups']['groups'])}")
    # Optional: Print a summary of users/groups
    # print("Sample Users:", user_group_data['user_groups']['users'][:5]) # Print first 5
    # print("Sample Groups:", user_group_data['user_groups']['groups'][:5]) # Print first 5

    # Collect Kernel Parameter Config Files
    print("\n--- Kernel Parameter Configuration Files and Hashes (SHA256) ---")
    kernel_param_data = get_kernel_param_config()
    all_config_data.update(kernel_param_data)
    if kernel_param_data['kernel_parameter_config_files']:
        # Already sorted in the function, but sort again just in case or if merging later
        # kernel_param_data['kernel_parameter_config_files'].sort(key=lambda x: x['path'])
        for file_info in kernel_param_data['kernel_parameter_config_files']:
            print(f"Path: {file_info['path']}")
            print(f"Hash: {file_info['hash_sha256']}")
        print(
            f"Total kernel parameter config files found: {len(kernel_param_data['kernel_parameter_config_files'])}")
    else:
        print("No kernel parameter config files found in common directories.")

    # Collect SSH Config Files
    print("\n--- SSH Configuration Files and Hashes (SHA256) ---")
    ssh_config_data = get_ssh_config_files()
    all_config_data.update(ssh_config_data)
    if ssh_config_data['ssh_config_files']:
        # Sort by path for consistent output
        ssh_config_data['ssh_config_files'].sort(key=lambda x: x['path'])
        for file_info in ssh_config_data['ssh_config_files']:
            print(f"Path: {file_info['path']}")
            print(f"Hash: {file_info['hash_sha256']}")
        print(
            f"Total SSH config files found: {len(ssh_config_data['ssh_config_files'])}")
    else:
        print("No SSH config files found in common directories.")

    # Collect Crontab Files
    print("\n--- Crontab Files and Hashes (SHA256) ---")
    crontab_data = get_crontab_files()
    all_config_data.update(crontab_data)
    if crontab_data['crontab_files']:
        # Already sorted in the function, but sort again just in case or if merging later
        # crontab_data['crontab_files'].sort(key=lambda x: x['path'])
        for file_info in crontab_data['crontab_files']:
            print(f"Path: {file_info['path']}")
            print(f"Hash: {file_info['hash_sha256']}")
        print(
            f"Total crontab files found: {len(crontab_data['crontab_files'])}")
    else:
        print("No crontab files found in common directories.")

    print("\n--- All Configuration Data Collected ---")
    # Optional: Print the full collected data structure (e.g., as JSON)
    # This is useful for programmatic use or saving the data.
    import json
    print("\n--- Full Data (JSON) ---")
    print(json.dumps(all_config_data, indent=2))


if __name__ == "__main__":
    main()
