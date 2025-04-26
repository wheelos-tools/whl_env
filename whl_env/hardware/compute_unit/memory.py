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
from typing import Dict, Any

# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define the path to the memory information file
MEMINFO_PATH = '/proc/meminfo'


def get_memory_info() -> Dict[str, Any]:
    """
    Retrieves detailed memory information by parsing /proc/meminfo.
    Includes total, free, available, swap, etc.
    Getting memory type/speed usually requires tools like dmidecode or parsing BIOS info,
    which is complex and often requires root privileges. This function does not provide that.

    Returns:
        A dictionary containing memory information parsed from /proc/meminfo,
        including values in both kB and bytes (for some key fields),
        and potentially an error message if reading or parsing fails.
        Example structure:
        {
            'MemTotal_kb': 16384000,
            'MemFree_kb': 10000000,
            'MemAvailable_kb': 12000000,
            'SwapTotal_kb': 8192000,
            'SwapFree_kb': 8192000,
            'MemTotal_bytes': 16777216000,
            'total_memory_gb': 15.63, # Convenience field
            'raw_meminfo': { # Optional: Store all parsed values as strings or integers
                'MemTotal': '16384000 kB',
                'MemFree': '10000000 kB',
                ...
            },
            'errors': ['List of any errors encountered'] # Optional
        }
    """
    mem_info: Dict[str, Any] = {}
    # To store all key-value pairs as strings
    raw_mem_stats: Dict[str, str] = {}
    parsed_kb_stats: Dict[str, int] = {}  # To store numerical values in kB

    KB_TO_BYTES = 1024
    KB_TO_GB = 1024**2  # 1024 * 1024

    try:
        logging.info(f"Attempting to read {MEMINFO_PATH}")
        with open(MEMINFO_PATH, 'r') as f:
            content = f.read()

        # Parse /proc/meminfo content
        # Each line is typically in the format "Key: Value Units" (e.g., "MemTotal: 16384000 kB")
        lines = content.strip().split('\n')
        for line in lines:
            if not line:
                continue  # Skip empty lines

            # Split each line by the first colon
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value_str = parts[1].strip()

                # Store the raw string value
                raw_mem_stats[key] = value_str

                # Attempt to parse numerical value (usually the first part before units)
                value_parts = value_str.split()
                if value_parts:
                    try:
                        # The numerical value is typically the first part
                        value_kb = int(value_parts[0])
                        # Store in kB with suffix
                        parsed_kb_stats[f"{key}_kb"] = value_kb

                    except ValueError:
                        logging.warning(
                            f"Could not parse integer value for '{key}': {value_str}")
                        # Optionally store non-parsable values under a different key or log as error
                        # mem_info[f"{key}_raw"] = value_str # Example

            else:
                logging.warning(
                    f"Skipping malformed line in {MEMINFO_PATH}: {line}")

        # Add relevant parsed stats (in kB and bytes) to the main result dictionary
        for key_kb, value_kb in parsed_kb_stats.items():
            mem_info[key_kb] = value_kb
            # Add corresponding value in bytes for common fields
            if key_kb in ['MemTotal_kb', 'MemFree_kb', 'MemAvailable_kb', 'SwapTotal_kb', 'SwapFree_kb']:
                mem_info[key_kb.replace('_kb', '_bytes')
                         ] = value_kb * KB_TO_BYTES

        # Add convenience field for total memory in GB
        total_kb = parsed_kb_stats.get('MemTotal_kb')
        if total_kb is not None:
            mem_info['total_memory_gb'] = round(total_kb / KB_TO_GB, 2)
        else:
            # MemTotal_kb was not found or not parsable
            error_msg = f"Could not find or parse 'MemTotal' from {MEMINFO_PATH}."
            mem_info.setdefault('errors', []).append(error_msg)
            logging.error(error_msg)

        # Optionally include the raw parsed stats dictionary
        # mem_info['raw_meminfo'] = raw_mem_stats # Uncomment if needed

        # As noted previously, memory type/speed cannot be reliably obtained from /proc/meminfo
        mem_info['type'] = 'N/A (Requires dmidecode or specific tools)'
        mem_info['speed'] = 'N/A (Requires dmidecode or specific tools)'

    except FileNotFoundError:
        error_msg = f'{MEMINFO_PATH} not found. Cannot get memory info on this system.'
        # Keep original error key for backward compatibility
        mem_info['error'] = error_msg
        mem_info.setdefault('errors', []).append(error_msg)
        logging.error(error_msg)
    except Exception as e:
        error_msg = f'An unexpected error occurred while reading or parsing {MEMINFO_PATH}: {e}'
        mem_info['error'] = error_msg  # Keep original error key
        mem_info.setdefault('errors', []).append(error_msg)
        logging.error(error_msg)

    # Ensure 'errors' key exists even if empty, for consistent structure
    mem_info.setdefault('errors', [])

    return mem_info


# Example of how to use the function (for testing purposes)
if __name__ == "__main__":
    print("Gathering memory information...")
    mem_info = get_memory_info()

    import json
    print("\n--- Memory Information (JSON Output) ---")
    print(json.dumps(mem_info, indent=4))

    # Example of processing the results
    print("\n--- Summary ---")
    total_gb = mem_info.get('total_memory_gb')
    total_kb = mem_info.get('MemTotal_kb')
    free_kb = mem_info.get('MemFree_kb')
    available_kb = mem_info.get('MemAvailable_kb')
    swap_total_kb = mem_info.get('SwapTotal_kb')
    swap_free_kb = mem_info.get('SwapFree_kb')

    if total_gb is not None:
        print(f"Total Physical Memory: {total_gb} GB ({total_kb} kB)")
    elif total_kb is not None:
        print(f"Total Physical Memory: {total_kb} kB")
    else:
        print("Total Physical Memory: N/A")

    if free_kb is not None:
        print(f"Free Physical Memory: {free_kb} kB")
    if available_kb is not None:
        print(f"Available Physical Memory (est.): {available_kb} kB")
    if swap_total_kb is not None:
        print(f"Total Swap Memory: {swap_total_kb} kB")
    if swap_free_kb is not None:
        print(f"Free Swap Memory: {swap_free_kb} kB")

    if mem_info.get('type'):
        print(f"Memory Type: {mem_info['type']}")
    if mem_info.get('speed'):
        print(f"Memory Speed: {mem_info['speed']}")

    if mem_info.get('errors'):
        print("\n--- Errors ---")
        for error in mem_info['errors']:
            print(f"- {error}")
