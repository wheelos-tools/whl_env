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
from typing import Dict, Any, List, Optional, Tuple

# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define the path to the CPU information file
CPUINFO_PATH = '/proc/cpuinfo'


def _parse_cpuinfo_block(block_content: str) -> Dict[str, str]:
    """
    Parses a single block of /proc/cpuinfo content into a key-value dictionary.
    A block corresponds to information for one logical processor.

    Args:
        block_content: A string containing the content of a single processor block.

    Returns:
        A dictionary where keys are the /proc/cpuinfo field names (stripped)
        and values are the corresponding field values (stripped).
    """
    block_info: Dict[str, str] = {}
    lines = block_content.strip().split('\n')
    for line in lines:
        if not line.strip():  # Skip empty lines within a block (shouldn't be any normally)
            continue
        # Split each line by the first colon
        parts = line.split(':', 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            block_info[key] = value
        else:
            # Log malformed lines within a block
            logging.warning(
                f"Skipping malformed line in cpuinfo block: {line}")
    return block_info


def get_cpu_info() -> Dict[str, Any]:
    """
    Retrieves detailed CPU information by parsing /proc/cpuinfo.
    Includes model name, vendor, core counts (logical, physical, sockets),
    current frequency, and basic family/model/stepping info.

    Returns:
        A dictionary containing CPU information, or an error message if reading or parsing fails.
        Example Structure:
        {
            'model_name': 'Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz',
            'vendor_id': 'GenuineIntel',
            'cpu_family': '6',
            'model': '158',
            'stepping': '10',
            'logical_cores': 12,      # Total threads (e.g., 6 cores * 2 threads)
            'physical_cores': 6,      # Total physical cores across all sockets
            'sockets': 1,             # Total physical CPU packages
            'physical_cores_per_socket': 6, # Value from 'cpu cores' in cpuinfo
            'current_frequency_mhz': 3700.00, # Current speed (can vary)
            'errors': ['List of any errors encountered during parsing'] # Optional
        }
    """
    cpu_info: Dict[str, Any] = {}
    errors: List[str] = []

    try:
        logging.info(f"Attempting to read {CPUINFO_PATH}")
        with open(CPUINFO_PATH, 'r') as f:
            content = f.read()

        # /proc/cpuinfo contains a block of information for each logical processor (thread).
        # Blocks are typically separated by one or more empty lines.
        processor_blocks = [
            block.strip() for block in content.strip().split('\n\n') if block.strip()]

        if not processor_blocks:
            err_msg = f'Could not parse {CPUINFO_PATH} into processor blocks or file is empty.'
            cpu_info['error'] = err_msg
            errors.append(err_msg)
            logging.error(err_msg)
            # Ensure errors are included even on initial parse failure
            cpu_info['errors'] = errors
            return cpu_info

        # --- Process each processor block to count unique physical cores and sockets ---
        # Stores unique physical IDs (e.g., '0', '1')
        unique_sockets: set[str] = set()
        # Stores unique (physical_id, core_id) tuples
        unique_physical_cores: set[Tuple[str, str]] = set()

        # We'll get representative info from the first block (assuming homogeneity)
        first_processor_block_info: Optional[Dict[str, str]] = None
        # Value from 'cpu cores'
        physical_cores_per_socket: Optional[int] = None

        for i, block_content in enumerate(processor_blocks):
            block_info = _parse_cpuinfo_block(block_content)

            if i == 0:
                first_processor_block_info = block_info
                # Get physical cores per socket from the first block's info
                cores_per_socket_str = block_info.get('cpu cores')
                if cores_per_socket_str is not None:
                    try:
                        physical_cores_per_socket = int(cores_per_socket_str)
                    except ValueError:
                        logging.warning(
                            f"Could not parse 'cpu cores' as int: '{cores_per_socket_str}'")
                        physical_cores_per_socket = None  # Indicate parsing failed

            # Collect physical ID and core ID to count unique entities
            physical_id = block_info.get('physical id')
            core_id = block_info.get('core id')

            if physical_id is not None:
                unique_sockets.add(physical_id)
                if core_id is not None:
                    # Combine physical_id and core_id into a tuple for unique core identification
                    unique_physical_cores.add((physical_id, core_id))
                # Note: If core_id is missing but physical_id is present, we can't count unique physical cores accurately using this method.
                # This is unusual for standard x86 CPUs.

        # --- Populate cpu_info dictionary ---

        # Get representative details from the first processor block
        if first_processor_block_info:
            cpu_info['model_name'] = first_processor_block_info.get(
                'model name', 'Unknown')
            cpu_info['vendor_id'] = first_processor_block_info.get(
                'vendor_id', 'Unknown')
            cpu_info['cpu_family'] = first_processor_block_info.get(
                'cpu family', 'Unknown')
            cpu_info['model'] = first_processor_block_info.get(
                'model', 'Unknown')
            cpu_info['stepping'] = first_processor_block_info.get(
                'stepping', 'Unknown')

            # Get current frequency (can vary per core and over time)
            current_freq_str = first_processor_block_info.get('cpu MHz', '0.0')
            try:
                cpu_info['current_frequency_mhz'] = float(current_freq_str)
            except ValueError:
                logging.warning(
                    f"Could not parse 'cpu MHz' as float: '{current_freq_str}'")
                cpu_info['current_frequency_mhz'] = 0.0
                errors.append(
                    f"Could not parse 'cpu MHz' value: {current_freq_str}")

        # Count total logical processors (threads) - simple count of 'processor' entries
        # More robustly count lines starting with "processor" followed by whitespace and ":"
        logical_cores = 0
        for line in content.splitlines():
            if line.strip().startswith('processor') and ':' in line:
                # Ensure it's the key 'processor' not a value containing it
                key_value_split = line.split(':', 1)
                if key_value_split[0].strip() == 'processor':
                    logical_cores += 1

        cpu_info['logical_cores'] = logical_cores if logical_cores > 0 else len(
            processor_blocks)  # Fallback count

        # Count unique sockets (physical packages)
        # If unique_sockets set is empty (e.g., physical id missing), assume 1 socket.
        cpu_info['sockets'] = len(unique_sockets) if unique_sockets else 1

        # Count unique physical cores
        # If unique_physical_cores set is not empty, use its size.
        # Otherwise, if physical_cores_per_socket was parsed, estimate total physical cores
        # by multiplying sockets by physical_cores_per_socket.
        # If neither works, assume physical cores equals logical cores (simple system).
        if unique_physical_cores:
            cpu_info['physical_cores'] = len(unique_physical_cores)
        elif physical_cores_per_socket is not None:
            cpu_info['physical_cores'] = cpu_info['sockets'] * \
                physical_cores_per_socket
            logging.warning(
                f"'physical id' or 'core id' missing, estimated physical cores: {cpu_info['physical_cores']}")
        else:
            cpu_info['physical_cores'] = cpu_info['logical_cores']
            logging.warning(
                "'physical id' or 'core id' or 'cpu cores' missing, assuming physical cores == logical cores.")

        # Add the parsed physical cores per socket value if available
        if physical_cores_per_socket is not None:
            cpu_info['physical_cores_per_socket'] = physical_cores_per_socket
        elif 'physical_cores' in cpu_info and cpu_info['sockets'] > 0:
            # Estimate physical cores per socket if not directly available but total physical/sockets are
            try:
                cpu_info['physical_cores_per_socket'] = cpu_info['physical_cores'] // cpu_info['sockets']
            except ZeroDivisionError:
                # Should not happen if sockets >= 1
                cpu_info['physical_cores_per_socket'] = cpu_info['physical_cores']

        # Note about max frequency: max/boost frequency is not reliably found in /proc/cpuinfo.
        # It might be in /sys/devices/system/cpu/cpu*/cpufreq/ or require tools like cpupower.

    except FileNotFoundError:
        err_msg = f'{CPUINFO_PATH} not found. Cannot get CPU info on this system.'
        # Keep original error key for backward compatibility
        cpu_info['error'] = err_msg
        errors.append(err_msg)
        logging.error(err_msg)
    except Exception as e:
        err_msg = f'An unexpected error occurred while reading or parsing {CPUINFO_PATH}: {e}'
        cpu_info['error'] = err_msg  # Keep original error key
        errors.append(err_msg)
        logging.error(err_msg)

    if errors:
        cpu_info['errors'] = errors
    # Ensure essential keys exist even if parsing failed for some, with default 'Unknown'/0
    cpu_info.setdefault('model_name', 'Unknown')
    cpu_info.setdefault('vendor_id', 'Unknown')
    cpu_info.setdefault('cpu_family', 'Unknown')
    cpu_info.setdefault('model', 'Unknown')
    cpu_info.setdefault('stepping', 'Unknown')
    cpu_info.setdefault('logical_cores', 0)
    cpu_info.setdefault('physical_cores', 0)
    cpu_info.setdefault('sockets', 0)
    cpu_info.setdefault('physical_cores_per_socket', 0)
    cpu_info.setdefault('current_frequency_mhz', 0.0)

    return cpu_info


# --- Placeholder for getting CPU runtime state ---
def get_cpu_state() -> Dict[str, Any]:
    """
    Placeholder function to get CPU runtime state (usage percentage, load average).
    This requires reading /proc/stat or using other system monitoring tools/libraries.
    This is distinct from getting CPU configuration information from /proc/cpuinfo.

    Returns:
         A dictionary containing CPU state information (currently empty).
    """
    # Implementation would involve:
    # - Reading /proc/stat to calculate per-CPU and total usage.
    # - Reading /proc/loadavg to get system load averages.
    # - Using psutil library (not standard library) for cross-platform compatibility.
    logging.info(
        "get_cpu_state called. This function is a placeholder and not implemented.")
    state_info: Dict[str, Any] = {
        "note": "CPU state (usage, load) retrieval is not implemented in this function."
        # Example keys if implemented:
        # "cpu_percent_total": 15.5,
        # "cpu_percent_per_core": [10.2, 18.0, ...],
        # "load_average_1min": 0.5,
        # "load_average_5min": 0.6,
        # "load_average_15min": 0.7
    }
    # Add implementation here to read /proc/stat and /proc/loadavg or use psutil
    return state_info


# Example of how to use the function (for testing purposes)
if __name__ == "__main__":
    print("Gathering CPU information...")
    cpu_info_result = get_cpu_info()

    import json
    print("\n--- CPU Information (JSON Output) ---")
    print(json.dumps(cpu_info_result, indent=4))

    # Example of processing the results
    print("\n--- Summary ---")
    print(f"Model Name: {cpu_info_result.get('model_name', 'N/A')}")
    print(f"Vendor ID: {cpu_info_result.get('vendor_id', 'N/A')}")
    print(f"CPU Family: {cpu_info_result.get('cpu_family', 'N/A')}")
    print(f"Model: {cpu_info_result.get('model', 'N/A')}")
    print(f"Stepping: {cpu_info_result.get('stepping', 'N/A')}")
    print(
        f"Logical Cores (Threads): {cpu_info_result.get('logical_cores', 'N/A')}")
    print(f"Physical Cores: {cpu_info_result.get('physical_cores', 'N/A')}")
    print(f"Sockets: {cpu_info_result.get('sockets', 'N/A')}")
    print(
        f"Physical Cores per Socket: {cpu_info_result.get('physical_cores_per_socket', 'N/A')}")
    freq = cpu_info_result.get('current_frequency_mhz')
    if freq is not None and freq > 0:
        print(f"Current Frequency: {freq:.2f} MHz")
    else:
        print(f"Current Frequency: N/A or 0.0 MHz")

    if cpu_info_result.get('errors'):
        print("\n--- Errors ---")
        for error in cpu_info_result['errors']:
            print(f"- {error}")

    # Example usage of the placeholder state function
    print("\n--- CPU State (Placeholder) ---")
    cpu_state_result = get_cpu_state()
    print(json.dumps(cpu_state_result, indent=4))
