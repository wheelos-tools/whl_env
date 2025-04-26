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
from typing import Dict, List, Any, Tuple, Optional
from whl_env.utils import run_command

def get_network_info() -> Dict[str, Any]:
    """
    Retrieves basic network interface information (name, MAC address, IP addresses, state).
    Uses the 'ip address show' command on Linux systems.

    Returns:
        A dictionary containing network interface list and potentially errors.
        Example structure:
        {
            'interfaces': [
                {
                    'name': 'lo',
                    'state': 'UNKNOWN',
                    'flags': ['LOOPBACK', 'UP', 'LOWER_UP'],
                    'link_type': 'loopback',
                    'mac_address': '00:00:00:00:00:00',
                    'addresses': [
                        {'family': 'inet', 'address': '127.0.0.1', 'cidr': '127.0.0.1/8'},
                        {'family': 'inet6', 'address': '::1', 'cidr': '::1/128'}
                    ]
                },
                {
                    'name': 'eth0',
                    'state': 'UP',
                    'flags': ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'],
                    'link_type': 'ether',
                    'mac_address': '00:1a:7f:xx:xx:xx',
                    'addresses': [
                        {'family': 'inet', 'address': '192.168.1.100', 'cidr': '192.168.1.100/24'},
                        {'family': 'inet6', 'address': 'fe80::xxxx:xxxx:xxxx:xxxx', 'cidr': 'fe80::xxxx:xxxx:xxxx:xxxx/64'}
                    ]
                },
                ...
            ],
            'errors': ['List of any errors encountered']
        }
    """
    network_info: Dict[str, Any] = {}
    interface_list: List[InterfaceInfo] = []
    errors: List[str] = []

    # Use 'ip address show' command on Linux (preferred over ifconfig)
    # This command lists interfaces and their addresses
    ip_command = ['ip', 'address', 'show']
    logging.info(f"Running command: {' '.join(ip_command)}")
    output = run_command(ip_command, timeout=10)

    if output:
        # Parse the output of 'ip address show'
        # The output format is block-based, starting with a number and colon (e.g., "1: lo: ...")
        # Subsequent lines for the same interface are indented.

        interfaces_raw_lines = output.strip().split('\n')
        # Use Optional for clarity
        current_iface: Optional[InterfaceInfo] = None
        addresses: List[AddressInfo] = []

        for line in interfaces_raw_lines:
            line = line.strip()

            # Check if the line starts a new interface block
            # A new block starts with a number followed by a colon, possibly space, then interface name
            # Using a simple check for digit followed by colon at the start
            if line and line[0].isdigit() and ':' in line.split(' ', 1)[0]:
                # If we were processing a previous interface, save it
                if current_iface is not None:
                    current_iface['addresses'] = addresses
                    interface_list.append(current_iface)
                    addresses = []  # Reset addresses for the new interface

                # Start parsing the new interface block
                current_iface = {}
                # Split only by the first two colons
                parts = line.split(':', 2)

                if len(parts) > 1:
                    # Parse interface name, flags, state from the first line
                    name_flags_state_part = parts[1].strip()
                    # Extract name (before '<' or the rest of the string)
                    name_match = name_flags_state_part.split('<', 1)
                    current_iface['name'] = name_match[0].strip()

                    # Extract flags (inside '<...>')
                    if len(name_match) > 1:
                        # Part starting from '<FLAGS> ...'
                        flags_state_part = name_match[1]
                        flags_match = flags_state_part.split('>', 1)
                        if len(flags_match) > 0:
                            current_iface['flags'] = [f.strip() for f in flags_match[0].split(
                                ',') if f.strip()]  # Handle empty strings
                            # Extract state (after 'state ' in the remaining part)
                            if len(flags_match) > 1:
                                state_part = flags_match[1]
                                state_match = state_part.split('state', 1)
                                if len(state_match) > 1:
                                    current_iface['state'] = state_match[1].split(' ')[
                                        0].strip()
                                else:
                                    # Default if 'state' keyword not found
                                    current_iface['state'] = 'Unknown'
                            else:
                                # Default if '>' not found after flags
                                current_iface['state'] = 'Unknown'
                        else:
                            current_iface['flags'] = []  # No flags found
                            # Default if '<...>' structure is malformed
                            current_iface['state'] = 'Unknown'
                    else:
                        current_iface['flags'] = []  # No '<' found
                        # Try to find state even without flags
                        state_match = name_flags_state_part.split('state', 1)
                        if len(state_match) > 1:
                            current_iface['state'] = state_match[1].split(' ')[
                                0].strip()
                        else:
                            # Default if no '<' and no 'state' keyword
                            current_iface['state'] = 'Unknown'

            # Check for link layer address (MAC address, etc.) - usually starts with "link/" and is indented
            # Check for indentation and starts with "link/"
            elif line.startswith('link/'):
                if current_iface is not None:
                    link_parts = line.split(' ', 2)
                    if len(link_parts) > 1:
                        current_iface['link_type'] = link_parts[0].split(
                            '/')[1].strip()
                        current_iface['mac_address'] = link_parts[1].strip()
                else:
                    logging.warning(
                        f"Found link line before interface block: {line}")

            # Check for network layer address (IP addresses) - starts with "inet " or "inet6 " and is indented
            # Check for indentation and starts with "inet " or "inet6 "
            elif line.startswith('inet ') or line.startswith('inet6 '):
                if current_iface is not None:
                    addr_parts = line.split()
                    if len(addr_parts) > 1:
                        addr_info: AddressInfo = {'family': addr_parts[0]}
                        # Address and CIDR are typically the second part (e.g., 192.168.1.100/24)
                        addr_info['cidr'] = addr_parts[1]
                        addr_info['address'] = addr_parts[1].split(
                            '/')[0].strip()  # Address part only
                        # Other details like scope, valid_lft could be parsed if needed
                        addresses.append(addr_info)
                else:
                    logging.warning(
                        f"Found address line before interface block: {line}")

            # Handle other potential lines for an interface (e.g., broadcast, scope, valid_lft)
            # You could add more elif clauses here to parse additional details if required.
            # For this scope, we focus on name, state, mac, and ip addresses.
            # else:
            #    logging.debug(f"Skipping line during parsing: {line}")

        # After the loop, add the last interface if one was being processed
        if current_iface is not None:
            current_iface['addresses'] = addresses
            interface_list.append(current_iface)

        network_info['interfaces'] = interface_list

    elif output is None:
        # Handle command execution errors
        error_message = f"Error executing '{' '.join(ip_command)}': {output}"
        errors.append(error_message)
        logging.error(error_message)

        # Check if the error is "command not found"
        if "command not found" in output.lower():
            errors.append(
                f"'{ip_command[0]}' command not found. Cannot reliably get network info on this system."
                " Attempting 'ifconfig' as a fallback (may provide less detail)."
            )
            logging.warning(errors[-1])

            # Fallback attempt with ifconfig (deprecated, less info, parsing is different)
            # For simplicity in this fallback, we just capture raw output.
            # Full ifconfig parsing would require a different parsing logic.
            ifconfig_command = ['ifconfig']
            logging.info(
                f"Running fallback command: {' '.join(ifconfig_command)}")
            success_ifconfig, output_ifconfig = run_command(
                ifconfig_command, timeout=10)

            if success_ifconfig and output_ifconfig:
                # Store raw output from ifconfig for inspection
                network_info['ifconfig_fallback_raw_output'] = output_ifconfig
                errors.append(
                    "Used ifconfig fallback. Parsing not implemented for ifconfig; raw output available.")
                logging.warning(errors[-1])
            elif not success_ifconfig:
                errors.append(
                    f"Fallback command '{' '.join(ifconfig_command)}' also failed: {output_ifconfig}")
                logging.error(errors[-1])
            # else: ifconfig succeeded but had no output? Unlikely, but handled by initial success check.

    else:  # success is True but output is empty - unusual but possible
        info_msg = f"Command '{' '.join(ip_command)}' returned no output. No network interfaces found or unexpected command behavior."
        network_info['info'] = info_msg
        logging.warning(info_msg)

    if errors:
        network_info['errors'] = errors

    # Note on bandwidth and latency: This function only retrieves configuration.
    # Checking bandwidth and latency requires active measurement (e.g., ping, traceroute, iperf)
    # and cannot be obtained solely from 'ip address show' output.
    if 'interfaces' in network_info and network_info['interfaces']:
        logging.info(
            f"Successfully retrieved info for {len(network_info['interfaces'])} interfaces.")
    elif 'errors' not in network_info:
        logging.info("No network interfaces found.")

    return network_info


# Example of how to use the function (for testing purposes)
if __name__ == "__main__":
    print("Gathering network information...")
    net_info = get_network_info()

    import json
    print("\n--- Network Information (JSON Output) ---")
    print(json.dumps(net_info, indent=4))

    # Example of processing the results
    if 'interfaces' in net_info:
        print("\n--- Summary ---")
        for iface in net_info['interfaces']:
            name = iface.get('name', 'N/A')
            state = iface.get('state', 'N/A')
            mac = iface.get('mac_address', 'N/A')
            print(f"Interface: {name}")
            print(f"  State: {state}")
            print(f"  MAC Address: {mac}")
            addresses = iface.get('addresses', [])
            if addresses:
                print("  IP Addresses:")
                for addr in addresses:
                    print(
                        f"    {addr.get('family', 'N/A')}: {addr.get('cidr', 'N/A')}")
            else:
                print("  No IP Addresses assigned.")
            print("-" * 10)

    if 'errors' in net_info:
        print("\n--- Errors ---")
        for error in net_info['errors']:
            print(f"- {error}")

    if 'info' in net_info:
        print(f"\n--- Info ---\n{net_info['info']}")

    if 'ifconfig_fallback_raw_output' in net_info:
        print("\n--- ifconfig Fallback Raw Output ---")
        print(net_info['ifconfig_fallback_raw_output'])
