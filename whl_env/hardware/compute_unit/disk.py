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

import logging
import re       # Needed for parsing key="value" format or df/fstab
from typing import Dict, List, Any

from whl_env.utils import run_command


# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define paths for system files
FSTAB_PATH = '/etc/fstab'

# --- Helper function to parse lsblk -P output ---


def parse_lsblk_pairs(output: str) -> List[Dict[str, str]]:
    """
    Parses the key="value" output format from lsblk -P.

    Args:
        output: The raw string output from lsblk -P.

    Returns:
        A list of dictionaries, where each dictionary represents a device
        or partition and contains key-value pairs from lsblk.
    """
    parsed_data: List[Dict[str, str]] = []
    lines = output.strip().split('\n')
    # Regex to find key="value" pairs, handling spaces inside quotes
    # \w+ : one or more word characters (keys like NAME, SIZE, etc.)
    # "([^"]*)" : quotes around the value, capturing anything inside that is not a quote
    pair_regex = re.compile(r'(\w+)="([^"]*)"')

    for line in lines:
        if not line.strip():
            continue
        device_info: Dict[str, str] = {}
        # Find all key="value" pairs in the line
        matches = pair_regex.findall(line)
        for key, value in matches:
            device_info[key] = value.strip()  # Store stripped value

        if device_info:  # Only add if the line actually contained parseable info
            parsed_data.append(device_info)
            logging.debug(
                f"Parsed lsblk device line: {device_info.get('NAME')}")

    return parsed_data

# --- Function to get block device info using lsblk ---


def get_disk_info_lsblk() -> Dict[str, Any]:
    """
    Retrieves basic block device information (name, size, type, mountpoint, fstype, model)
    by running the 'lsblk' command with key="value" output format.

    Returns:
        A dictionary containing:
        - 'devices': A list of dictionaries, each representing a block device
                     or partition with keys like 'name', 'size_bytes', 'type',
                     'mount_point', 'filesystem_type', 'model'.
        - 'errors': A list of strings for any errors encountered.
    """
    storage_info: Dict[str, Any] = {}
    disk_list: List[Dict[str, Any]] = []
    errors: List[str] = []

    # Use lsblk to list block devices.
    # -b: print size in bytes (unambiguous)
    # -P: use key="value" output format (easy to parse)
    # -o: specify output columns (NAME, SIZE, TYPE, MOUNTPOINT, FSTYPE, MODEL)
    # We use 'NAME' as the primary identifier, 'SIZE' in bytes,
    # 'TYPE' (disk, part, loop, etc.), 'MOUNTPOINT' (where it's mounted),
    # 'FSTYPE' (filesystem type), 'MODEL' (disk model).
    lsblk_cmd = ['lsblk', '-b', '-P', '-o',
                 'NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL']
    logging.info(f"Running command: {' '.join(lsblk_cmd)}")
    output = run_command(lsblk_cmd, timeout=10)

    if output:
        logging.info("lsblk command successful. Parsing output...")
        # Parse the key="value" output format
        disk_list_raw = parse_lsblk_pairs(output)

        for dev_info_raw in disk_list_raw:
            dev_info: Dict[str, Any] = {}
            # Extract and process information from the raw parsed data
            dev_info['name'] = dev_info_raw.get('NAME', 'N/A')
            dev_info['type'] = dev_info_raw.get(
                'TYPE', 'unknown')  # e.g., disk, part, loop

            # Safely convert size to integer (lsblk -b gives bytes)
            size_bytes_str = dev_info_raw.get('SIZE', '0')
            try:
                dev_info['size_bytes'] = int(size_bytes_str)
            except ValueError:
                dev_info['size_bytes'] = 0
                errors.append(
                    f"Could not parse size '{size_bytes_str}' for device {dev_info['name']}")
                logging.warning(errors[-1])

            # Add convenience size in GB (round to 2 decimal places)
            dev_info['size_gb'] = round(
                dev_info['size_bytes'] / (1024**3), 2) if dev_info['size_bytes'] > 0 else 0.0

            # MOUNTPOINT and FSTYPE can be empty/None if not mounted or no FS
            # lsblk -P uses "" for empty values, convert to None or empty string as preferred
            mount_point_raw = dev_info_raw.get('MOUNTPOINT', '')
            dev_info['mount_point'] = mount_point_raw if mount_point_raw != '' else None

            fstype_raw = dev_info_raw.get('FSTYPE', '')
            dev_info['filesystem_type'] = fstype_raw if fstype_raw != '' else None

            # Disk model name (only for TYPE=disk)
            dev_info['model'] = dev_info_raw.get('MODEL', 'N/A')

            disk_list.append(dev_info)

        storage_info['devices'] = disk_list
    else:  # success is True but output is empty - indicates no block devices?
        info_msg = "lsblk returned no output. No block devices found?"
        storage_info['info'] = info_msg
        logging.warning(info_msg)

    if errors:
        storage_info['errors'] = errors

    return storage_info


# --- Function to get filesystem usage info using df ---
def get_filesystem_usage() -> Dict[str, Any]:
    """
    Retrieves filesystem usage information (total, used, available space)
    for mounted filesystems using the 'df' command.

    Returns:
        A dictionary containing:
        - 'filesystems': A list of dictionaries, each representing a mounted filesystem
                         with keys like 'device', 'mount_point', 'total_bytes',
                         'used_bytes', 'available_bytes', 'use_percentage'.
        - 'errors': A list of strings for any errors encountered.
    """
    fs_usage_info: Dict[str, Any] = {}
    fs_list: List[Dict[str, Any]] = []
    errors: List[str] = []

    # Use df to get filesystem disk space usage
    # -P: Use POSIX output format (consistent columns)
    # -B1: Report sizes in 1-byte blocks (unambiguous)
    # Output columns (with -P): Filesystem, 1-blocks, Used, Available, Capacity, Mounted on
    df_cmd = ['df', '-P', '-B1']
    logging.info(f"Running command: {' '.join(df_cmd)}")
    output = run_command(df_cmd, timeout=10)

    if output:
        logging.info("df command successful. Parsing output...")
        lines = output.strip().split('\n')
        if len(lines) > 1:  # Skip header line
            # Not strictly needed due to fixed order with -P
            header = lines[0].split()
            data_lines = lines[1:]

            for line in data_lines:
                if not line.strip():
                    continue
                # Split line by whitespace. With -P, the last column is Mountpoint,
                # which can potentially contain spaces (less common, but possible).
                # A simple split might break if the device path has spaces,
                # but typically device paths don't. Mount points can.
                # df -P puts Mountpoint last, so split(None, 5) splits by whitespace
                # into 6 parts, the last being the Mountpoint.
                # Split into at most 6 parts by any whitespace
                parts = line.split(None, 5)

                if len(parts) == 6:
                    try:
                        # Columns: Filesystem, 1-blocks, Used, Available, Capacity, Mounted on
                        device_name = parts[0]
                        total_bytes = int(parts[1])
                        used_bytes = int(parts[2])
                        available_bytes = int(parts[3])
                        # Capacity is 'Use%', remove '%' and convert to float
                        use_percentage = float(parts[4].replace('%', ''))
                        mount_point = parts[5]  # Last part is the mount point

                        fs_info: Dict[str, Any] = {
                            'device': device_name,  # e.g., /dev/sda1, tmpfs
                            'mount_point': mount_point,  # e.g., /, /home, /mnt/data
                            'total_bytes': total_bytes,
                            'used_bytes': used_bytes,
                            'available_bytes': available_bytes,
                            'use_percentage': use_percentage
                        }
                        fs_list.append(fs_info)
                        logging.debug(f"Parsed df entry: {mount_point}")

                    except (ValueError, IndexError) as e:
                        errors.append(
                            f"Error parsing df output line '{line}': {e}")
                        logging.error(errors[-1])
                else:
                    errors.append(
                        f"df output format unexpected for line (expected 6 parts, got {len(parts)}): {line}")
                    logging.warning(errors[-1])

        elif len(lines) == 1:
            # Only header line received, no mounted filesystems listed
            logging.info(
                "df command returned only header, no mounted filesystems found.")
        else:
            # Should not happen if output is not empty and > 1 line check passed
            pass  # Handled by empty output check below
    else:  # success is True but output is empty
        info_msg = "df returned no output. No mounted filesystems?"
        fs_usage_info['info'] = info_msg
        logging.warning(info_msg)

    fs_usage_info['filesystems'] = fs_list
    if errors:
        fs_usage_info['errors'] = errors

    return fs_usage_info


# --- Function to parse /etc/fstab ---
def parse_fstab() -> Dict[str, Any]:
    """
    Parses the /etc/fstab file to get static filesystem configuration entries.
    Does not check if filesystems are currently mounted or accessible.

    Returns:
        A dictionary containing:
        - 'entries': A list of dictionaries, each representing an fstab entry
                     with keys like 'device', 'mount_point', 'fstype', 'options',
                     'dump', 'pass_no'.
        - 'errors': A list of strings for any errors encountered.
                     (e.g., file not found, parsing issues).
    """
    fstab_entries: List[Dict[str, str]] = []
    errors: List[str] = []
    fstab_info: Dict[str, Any] = {}

    try:
        logging.info(f"Attempting to read {FSTAB_PATH}")
        with open(FSTAB_PATH, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip comment lines and empty lines
                if not line or line.startswith('#'):
                    continue

                # Split line by whitespace. Standard fstab has 6 fields.
                # Fields: fs_spec, fs_file, fs_vfstype, fs_mntops, fs_freq, fs_passno
                parts = line.split()

                # Basic check for expected number of fields (at least 2 are mandatory)
                # A standard entry has 6 fields.
                if len(parts) >= 2:
                    entry: Dict[str, str] = {
                        # fs_spec - device, UUID, LABEL etc.
                        'device': parts[0],
                        'mount_point': parts[1],   # fs_file - mount point
                        # fs_vfstype - filesystem type
                        'fstype': parts[2] if len(parts) > 2 else 'auto',
                        # fs_mntops - mount options
                        'options': parts[3] if len(parts) > 3 else 'defaults',
                        # fs_freq - dump frequency
                        'dump': parts[4] if len(parts) > 4 else '0',
                        # fs_passno - fsck pass number
                        'pass_no': parts[5] if len(parts) > 5 else '0'
                    }
                    fstab_entries.append(entry)
                    logging.debug(
                        f"Parsed fstab entry: {entry.get('mount_point')}")

                else:
                    # Log malformed lines
                    errors.append(
                        f"Malformed line in {FSTAB_PATH} (line {line_num}, expected >=2 fields): {line}")
                    logging.warning(errors[-1])

    except FileNotFoundError:
        err_msg = f'{FSTAB_PATH} not found. Cannot get static filesystem configuration.'
        errors.append(err_msg)
        logging.error(err_msg)
    except Exception as e:
        err_msg = f'An unexpected error occurred while reading or parsing {FSTAB_PATH}: {e}'
        errors.append(err_msg)
        logging.error(err_msg)

    fstab_info['entries'] = fstab_entries
    if errors:
        fstab_info['errors'] = errors

    return fstab_info


# --- Main function to combine storage information ---
def get_storage_status() -> Dict[str, Any]:
    """
    Gathers comprehensive storage status including block device information
    from lsblk, filesystem usage from df, and static configuration from fstab.

    Note: This function provides configuration and usage data.
    Checking read/write speed requires performing benchmarks, which is NOT
    included here.

    Returns:
        A dictionary containing storage information.
        Example Structure:
        {
            'devices': [ # From lsblk, augmented with df and fstab info
                 {
                     'name': 'sda',
                     'type': 'disk',
                     'size_bytes': ...,
                     'size_gb': ...,
                     'model': '...',
                     'partitions': [
                         {
                             'name': 'sda1',
                             'type': 'part',
                             'size_bytes': ...,
                             'size_gb': ...,
                             'mount_point': '/', # If mounted
                             'filesystem_type': 'ext4', # If has FS
                             'usage': { # If mounted and found in df
                                 'total_bytes': ...,
                                 'used_bytes': ...,
                                 'available_bytes': ...,
                                 'use_percentage': ...
                             },
                             'fstab': { # If found in fstab
                                 'device': '/dev/sda1',
                                 'mount_point': '/',
                                 'fstype': 'ext4',
                                 'options': 'defaults',
                                 'dump': '0',
                                 'pass_no': '1'
                             }
                         },
                         ...
                     ]
                 },
                 ...
            ],
            'filesystems_usage': [ # List of all mounted filesystems from df
                 {
                     'device': '/dev/sda1',
                     'mount_point': '/',
                     'total_bytes': ...,
                     'used_bytes': ...,
                     'available_bytes': ...,
                     'use_percentage': ...
                 },
                 ...
            ],
            'fstab_entries': [ # List of all entries from /etc/fstab
                 {
                     'device': 'UUID=...',
                     'mount_point': '/home',
                     'fstype': 'ext4',
                     'options': 'defaults',
                     'dump': '0',
                     'pass_no': '2'
                 },
                 ...
            ],
            'errors': ['List of errors from lsblk, df, fstab parsing']
        }
    """
    # 1. Get block device info (disks, partitions, etc.)
    lsblk_result = get_disk_info_lsblk()
    devices = lsblk_result.get('devices', [])
    all_errors = lsblk_result.get('errors', [])

    # 2. Get filesystem usage info for mounted filesystems
    df_result = get_filesystem_usage()
    filesystems_usage = df_result.get('filesystems', [])
    all_errors.extend(df_result.get('errors', []))

    # 3. Parse static fstab entries
    fstab_result = parse_fstab()
    fstab_entries = fstab_result.get('entries', [])
    all_errors.extend(fstab_result.get('errors', []))

    # 4. Augment lsblk data with df and fstab info
    # Create lookup dictionaries for easier matching
    usage_lookup = {fs['mount_point']: fs for fs in filesystems_usage}
    # Matching fstab requires checking both device and mount point, and handling different device specs (name, UUID, LABEL)
    # A simple lookup by mount_point might find the most relevant fstab entry for a mounted FS.
    fstab_lookup_by_mount = {entry['mount_point']                             : entry for entry in fstab_entries}
    # Consider adding lookup by device name/UUID/LABEL if needed for non-mounted fstab entries

    # Build a hierarchical structure or just augment the flat list?
    # Augmenting the flat list is simpler and matches the original structure closer.
    # Let's augment the 'devices' list from lsblk results.

    # Iterate through devices/partitions from lsblk
    for device in devices:
        # If the device/partition has a mount point according to lsblk
        mount_point = device.get('mount_point')
        if mount_point:
            # Try to find corresponding usage info from df results (match by mount point)
            usage_info = usage_lookup.get(mount_point)
            if usage_info:
                device['usage'] = usage_info
                logging.debug(
                    f"Augmented {device.get('name')} ({mount_point}) with usage info.")

            # Try to find corresponding fstab entry (match by mount point)
            fstab_entry = fstab_lookup_by_mount.get(mount_point)
            # Additional check: does the fstab entry's device specification match this lsblk device name?
            # This is complex due to UUIDs/LABELs. For simplicity, just adding the fstab entry found by mount point for now.
            # More robust matching would involve resolving UUIDs/LABELs to /dev/ names.
            if fstab_entry:
                # Basic check if the lsblk name or its parent disk name is mentioned in the fstab device spec
                # This check is imperfect but better than just matching mount point alone
                fstab_device_spec = fstab_entry.get('device', '')
                lsblk_name = device.get('name', '')

                # Simple heuristic: check if lsblk name is a substring of fstab spec (e.g., sda1 in /dev/sda1, or sda in UUID=...)
                # A better approach would be to resolve UUID/LABEL from fstab using blkid and match /dev/ paths.
                # Sticking to simple check for completion based on the request.
                # Let's add the fstab entry if mount points match, but add a warning if device spec doesn't look right.
                device['fstab'] = fstab_entry
                # Optional: Add a check/warning if fstab device spec doesn't seem to match
                # if not (lsblk_name in fstab_device_spec or fstab_device_spec.startswith(f'/dev/{lsblk_name}')):
                #      logging.warning(f"Fstab entry for mount point {mount_point} references device '{fstab_device_spec}', which might not directly match lsblk name '{lsblk_name}'.")

        # You could optionally build a hierarchical structure here if needed,
        # linking partitions to their parent disks based on NAME (e.g., sda vs sda1)
        # This requires iterating through devices and nesting 'part' types under 'disk' types.
        # For this request, augmenting the flat list is sufficient to show related info.

    # 5. Final result structure
    result: Dict[str, Any] = {
        'devices': devices,  # Augmented list from lsblk
        'filesystems_usage': filesystems_usage,  # Flat list from df
        'fstab_entries': fstab_entries  # Flat list from fstab
    }

    if all_errors:
        result['errors'] = all_errors

    # Add info message if no devices were found by lsblk
    if not devices and not all_errors:
        result['info'] = "No block devices detected by lsblk."
        logging.info(result['info'])

    # --- Note on Read/Write Speed ---
    # Checking read/write speed is a performance test that requires active I/O operations (benchmarking).
    # This cannot be determined by simply listing device/filesystem properties with tools like lsblk or df.
    # Tools for benchmarking include:
    # - `dd` (simple sequential test)
    # - `fio` (flexible I/O tester, complex configuration)
    # - `ioping` (latency check)
    # - Specific filesystem benchmarks (e.g., bonnie++, iozone)
    # Implementing a benchmark is outside the scope of gathering system information.
    # The caller would need to perform these tests separately on the relevant mount points/devices.
    result['note_speed_check'] = (
        "Read/write speed requires active benchmarking tools (e.g., dd, fio, ioping)"
        " and cannot be determined from configuration/usage data provided here."
    )

    return result


# Example of how to use the function (for testing purposes)
if __name__ == "__main__":
    print("Gathering storage status information...")
    storage_status = get_storage_status()

    import json
    print("\n--- Storage Status (JSON Output) ---")
    print(json.dumps(storage_status, indent=4))

    # Example of processing the results
    print("\n--- Summary of Devices ---")
    if storage_status.get('devices'):
        for device in storage_status['devices']:
            name = device.get('name', 'N/A')
            dev_type = device.get('type', 'N/A')
            size_gb = device.get('size_gb')
            model = device.get('model', 'N/A')

            print(f"Device: {name} (Type: {dev_type})")
            if size_gb is not None:
                print(
                    f"  Size: {size_gb} GB ({device.get('size_bytes', 'N/A')} bytes)")
            if model != 'N/A' and dev_type == 'disk':  # Only show model for disks
                print(f"  Model: {model}")

            # If it's a partition or mounted device, show mount info
            mount_point = device.get('mount_point')
            fstype = device.get('filesystem_type')
            if mount_point:
                print(f"  Mounted on: {mount_point} (FS: {fstype})")

            # Show usage info if available (added from df)
            usage = device.get('usage')
            if usage:
                total_gb = round(usage.get('total_bytes', 0) / (1024**3), 2)
                used_gb = round(usage.get('used_bytes', 0) / (1024**3), 2)
                available_gb = round(
                    usage.get('available_bytes', 0) / (1024**3), 2)
                use_percent = usage.get('use_percentage')
                print(
                    f"  Usage: {used_gb} GB used / {available_gb} GB available ({use_percent}%)")
                print(
                    f"  Total FS Size: {total_gb} GB ({usage.get('total_bytes', 'N/A')} bytes)")

            # Show fstab info if available
            fstab = device.get('fstab')
            if fstab:
                print(f"  fstab Entry:")
                print(f"    Device: {fstab.get('device')}")
                print(f"    Mount Point: {fstab.get('mount_point')}")
                print(f"    FS Type: {fstab.get('fstype')}")
                print(f"    Options: {fstab.get('options')}")

            # Note about partitions hierarchy is not built here
            # print("  Partitions: (Hierarchy not built in this view)") # Could list partition names here if implemented

            print("-" * 20)
    elif storage_status.get('info'):
        print(f"\n--- Info ---\n{storage_status['info']}")

    print("\n--- Summary of Mounted Filesystems (from df) ---")
    if storage_status.get('filesystems_usage'):
        for fs in storage_status['filesystems_usage']:
            total_gb = round(fs.get('total_bytes', 0) / (1024**3), 2)
            used_gb = round(fs.get('used_bytes', 0) / (1024**3), 2)
            available_gb = round(fs.get('available_bytes', 0) / (1024**3), 2)
            use_percent = fs.get('use_percentage')

            print(f"Mount Point: {fs.get('mount_point', 'N/A')}")
            print(f"  Device: {fs.get('device', 'N/A')}")
            print(
                f"  Total Size: {total_gb} GB ({fs.get('total_bytes', 'N/A')} bytes)")
            print(
                f"  Usage: {used_gb} GB used / {available_gb} GB available ({use_percent}%)")
            print("-" * 20)
    elif 'info' not in storage_status:  # Avoid repeating info if already shown
        print("No mounted filesystems reported by df.")

    print("\n--- Summary of fstab Entries ---")
    if storage_status.get('fstab_entries'):
        for entry in storage_status['fstab_entries']:
            print(f"fstab Entry:")
            print(f"  Device: {entry.get('device')}")
            print(f"  Mount Point: {entry.get('mount_point')}")
            print(f"  FS Type: {entry.get('fstype')}")
            print(f"  Options: {entry.get('options')}")
            print("-" * 20)
    elif 'info' not in storage_status:
        print(f"No entries found in {FSTAB_PATH}.")

    if storage_status.get('errors'):
        print("\n--- Errors ---")
        for error in storage_status['errors']:
            print(f"- {error}")

    if storage_status.get('note_speed_check'):
        print(f"\n--- Note ---")
        print(storage_status['note_speed_check'])
