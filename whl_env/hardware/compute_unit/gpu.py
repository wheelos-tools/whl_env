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
import platform  # Needed for platform.system()
import re       # Needed for lspci parsing regex
from typing import Dict, List, Any, Tuple  # Added Tuple for run_command hint

from whl_env.utils import run_command  # Using the user's specified import


# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def get_gpu_info() -> Dict[str, Any]:
    """
    Retrieves basic GPU information (model, total memory) by attempting to use
    vendor-specific tools (like nvidia-smi) and generic tools (like lspci).

    Returns:
        A dictionary containing:
        - 'gpu_list': A list of dictionaries, each representing a detected GPU
                      with details like vendor, model, bus_id, and possibly
                      vbios_version, driver_version, total_memory_mib.
                      Information source ('source': 'nvidia-smi' or 'lspci')
                      is included.
        - 'errors': A list of strings for any errors encountered during command execution or parsing.
        - 'info': An informational message if no GPUs are detected.
        Example Structure:
        {
            'gpu_list': [
                {
                    'vendor': 'NVIDIA',
                    'model': 'GeForce RTX 2080',
                    'bus_id': '0000:01:00.0', # PCI bus ID format
                    'vbios_version': '90.04.45.00.01',
                    'driver_version': '535.104',
                    'total_memory_mib': 8192,
                    'source': 'nvidia-smi'
                },
                {
                    'vendor': 'Intel',
                    'model': 'HD Graphics 620',
                    'bus_id': '0000:00:02.0',
                    'source': 'lspci',
                    'details': 'Intel Corporation HD Graphics 620 [8086:5916] (rev 02)'
                }
            ],
            'errors': ["Error parsing lspci output line '...'"],
            'info': '...'
        }
    """
    gpu_list: List[Dict[str, Any]] = []
    errors: List[str] = []
    detected_bus_ids: set[str] = set()  # To avoid duplicates by bus ID

    # --- 1. Attempt NVIDIA GPU info via nvidia-smi ---
    # This is the most reliable tool for detailed NVIDIA information (model, memory, driver).
    logging.info("Attempting to get NVIDIA GPU info via nvidia-smi...")
    nvidia_smi_cmd = [
        'nvidia-smi',
        '--query-gpu=name,gpu_bus_id,vbios_version,driver_version,memory.total',
        '--format=csv,noheader'
    ]
    output = run_command(nvidia_smi_cmd, timeout=10)

    if output:
        # nvidia-smi outputs CSV: name, bus_id, vbios, driver, total_memory [MiB]
        logging.info("nvidia-smi command successful. Parsing output...")
        for line in output.strip().split('\n'):
            if not line.strip():  # Skip empty lines
                continue
            try:
                # Split CSV line, handle potential extra spaces
                parts = [p.strip() for p in line.split(',')]
                # Expecting exactly 5 parts based on the query format
                if len(parts) == 5:
                    # Parse memory value, removing '[MiB]' unit string
                    memory_str = parts[4].split(' ')[0].strip()
                    try:
                        total_memory_mib = int(memory_str)
                    except ValueError:
                        # Handle cases where memory value is not a valid integer
                        logging.warning(
                            f"Could not parse GPU memory value as integer: '{memory_str}' from line '{line}'")
                        total_memory_mib = None  # Indicate parsing failed for memory

                    gpu_info: Dict[str, Any] = {
                        'vendor': 'NVIDIA',
                        'model': parts[0],
                        # Remove 'PCI:' prefix if present
                        'bus_id': parts[1].replace('PCI:', ''),
                        'vbios_version': parts[2],
                        'driver_version': parts[3],
                        'total_memory_mib': total_memory_mib,
                        'source': 'nvidia-smi'
                    }
                    gpu_list.append(gpu_info)
                    # Add bus ID to set
                    detected_bus_ids.add(gpu_info['bus_id'])
                    logging.debug(f"Parsed NVIDIA GPU: {gpu_info['model']}")
                else:
                    # Log lines that don't match the expected CSV format
                    errors.append(
                        f"nvidia-smi output format unexpected for line (expected 5 parts, got {len(parts)}): {line}")
                    logging.warning(errors[-1])

            except Exception as e:  # Catch any other unexpected parsing errors per line
                errors.append(
                    f"Error parsing nvidia-smi output line '{line}': {e}")
                logging.error(errors[-1])
    else:
        # success is True but output is empty - unlikely for nvidia-smi if GPUs are present
        logging.info("nvidia-smi returned no output.")

    # --- 2. Attempt to list graphics cards via lspci ---
    # This is a more generic tool available on most Linux systems.
    # It helps identify graphics devices regardless of vendor/driver status,
    # but provides less detail (no memory, driver, etc.).
    logging.info("Attempting to list graphics cards via lspci...")
    if platform.system().lower() == 'linux':
        # Filter for standard graphics device classes:
        # 0300: Display controller (VGA compatible controller, etc.)
        # 0302: 3D controller
        lspci_cmd = ['lspci', '-nn', '-d', '::0300::,::0302::']
        output_lspci = run_command(lspci_cmd, timeout=5)

        if output_lspci:
            logging.info("lspci command successful. Parsing output...")
            # Output format is typically like:
            # "01:00.0 VGA compatible controller [0300]: NVIDIA Corporation TU104 [GeForce RTX 2080] [10de:1e87] (rev a1)"
            for line in output_lspci.strip().split('\n'):
                if not line.strip():  # Skip empty lines
                    continue
                try:
                    # Basic parsing to get device ID (bus_id) and description
                    # Split by the first colon, the second part contains device/vendor info
                    parts = line.split(':', 2)  # Split into at most 3 parts
                    if len(parts) > 2:
                        # Bus ID is the first part (e.g., "01:00.0")
                        bus_id_full = parts[0].strip()
                        # Normalize bus ID format (remove potential domain if present like '0000:')
                        bus_id = bus_id_full.split(' ')[0].replace('0000:', '')

                        # The rest of the line is the description
                        description = parts[2].strip()

                        # Check if this GPU is already in our list (e.g., from nvidia-smi)
                        # We match based on the normalized bus ID
                        if bus_id not in detected_bus_ids:
                            logging.debug(
                                f"Parsing lspci line for potential new GPU: {line}")
                            # Try to extract vendor and model from description using common patterns
                            # Pattern for Vendor (usually before first '[' after controller type)
                            # Example: "VGA compatible controller [0300]: NVIDIA Corporation [10de:1e87]"
                            # We want "NVIDIA Corporation"
                            vendor_match = re.search(
                                r':\s*([^[]+?)\s*\[', description)

                            # Pattern for Model (usually inside the first '[' and ']')
                            # Example: "NVIDIA Corporation TU104 [GeForce RTX 2080] [10de:1e87]"
                            # We want "GeForce RTX 2080"
                            model_match = re.search(
                                r'\[([^]]+)\]', description)  # Finds text inside first [...]

                            # Use extracted vendor/model or default to Unknown/full description
                            vendor = vendor_match.group(
                                1).strip() if vendor_match else 'Unknown'
                            # Use extracted model or default to the full description if model pattern fails
                            model = model_match.group(
                                1).strip() if model_match else description

                            # Add to list with lspci source
                            lspci_gpu_info: Dict[str, Any] = {
                                'vendor': vendor,
                                'model': model,
                                'bus_id': bus_id,
                                'source': 'lspci',  # Indicate source of info
                                'details': description  # Keep full description for context
                                # Memory/Driver info typically not available from lspci alone
                            }
                            gpu_list.append(lspci_gpu_info)
                            detected_bus_ids.add(bus_id)  # Add bus ID to set
                            logging.debug(f"Added lspci GPU: {model}")
                        else:
                            logging.debug(
                                f"Skipping lspci line for duplicate bus ID ({bus_id}): {line}")

                    else:
                        # Log lines that don't match expected lspci format
                        errors.append(
                            f"lspci output format unexpected for line: {line}")
                        logging.warning(errors[-1])

                except Exception as e:  # Catch any other unexpected parsing errors per line
                    errors.append(
                        f"Error parsing lspci output line '{line}': {e}")
                    logging.error(errors[-1])
        # else: success_lspci is True but output_lspci is empty
        # This is not an error, it means no matching graphics devices were found by lspci.

    else:
        # Not a Linux system, lspci command is not applicable
        logging.info(
            f"lspci command is Linux-specific. Current system is {platform.system()}. Skipping lspci check.")
        errors.append(
            f"lspci command is Linux-specific. Cannot run on {platform.system()}.")

    # --- 3. Combine results and finalize output ---
    # Note: Other methods like parsing /sys/class/graphics or lshw exist
    # but are more complex and often require root or have less standard formats.
    # This implementation focuses on the common and useful nvidia-smi/lspci combo.

    result: Dict[str, Any] = {'gpu_list': gpu_list}

    # Add errors if any occurred
    if errors:
        result['errors'] = errors

    # Add an informational message if no GPUs were found and there were no critical errors
    # Critical errors (like command not found) are already in 'errors'.
    # If errors exist but gpu_list is empty, the errors explain why.
    if not gpu_list and 'errors' not in result:
        result['info'] = 'No graphics devices detected via standard methods (nvidia-smi, lspci).'
        logging.info(result['info'])
    elif gpu_list:
        logging.info(f"Detected {len(gpu_list)} graphics device(s).")

    return result


# Example of how to use the function (for testing purposes)
if __name__ == "__main__":
    print("Gathering GPU information...")
    gpu_info_result = get_gpu_info()

    import json
    print("\n--- GPU Information (JSON Output) ---")
    print(json.dumps(gpu_info_result, indent=4))

    # Example of processing the results
    if gpu_info_result.get('gpu_list'):
        print("\n--- Summary ---")
        for gpu in gpu_info_result['gpu_list']:
            print(f"GPU:")
            print(f"  Vendor: {gpu.get('vendor', 'N/A')}")
            print(f"  Model: {gpu.get('model', 'N/A')}")
            print(f"  Bus ID: {gpu.get('bus_id', 'N/A')}")
            print(f"  Source: {gpu.get('source', 'N/A')}")

            if gpu.get('source') == 'nvidia-smi':
                memory_mib = gpu.get('total_memory_mib')
                if memory_mib is not None:
                    print(f"  Total Memory: {memory_mib} MiB")
                else:
                    print("  Total Memory: N/A (Parsing failed)")
                print(f"  Driver Version: {gpu.get('driver_version', 'N/A')}")
                print(f"  VBIOS Version: {gpu.get('vbios_version', 'N/A')}")
            elif gpu.get('source') == 'lspci':
                print(f"  Details: {gpu.get('details', 'N/A')}")

            print("-" * 10)

    if gpu_info_result.get('errors'):
        print("\n--- Errors ---")
        for error in gpu_info_result['errors']:
            print(f"- {error}")

    if gpu_info_result.get('info'):
        print(f"\n--- Info ---\n{gpu_info_result['info']}")
