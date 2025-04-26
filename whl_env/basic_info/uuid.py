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
import socket
import os
from typing import Dict, Any

# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Host and Vehicle ID Series Functions ---

def get_host_machine_id() -> str:
    """
    Retrieves the host's unique machine ID (usually stored in /etc/machine-id
    or /var/lib/dbus/machine-id on Linux systems). This ID should remain
    constant across reboots for a specific installation.

    Returns:
        str: The machine ID string if found and readable, or an informative
             string like "Not Found" or "Error: ..." on failure.
    """
    # Standard locations for machine ID on Linux (preferred order)
    machine_id_paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
    machine_id_status = "Not Found" # Default status

    for path in machine_id_paths:
        try:
            logging.debug(f"Attempting to read machine ID from {path}")
            with open(path, 'r') as f:
                current_id = f.read().strip()

            # Machine ID is typically a 32-character lowercase hex string.
            # Basic validation: check if it's non-empty. A more stringent check
            # could validate format (e.g., using regex [0-9a-f]{32}).
            if current_id:
                logging.debug(f"Machine ID found: {current_id}")
                machine_id_status = current_id # Found a valid ID
                break # Found the ID, no need to check other paths
            else:
                # File exists but is empty, this is unexpected but not an error, try next path
                logging.warning(f"Machine ID file exists but is empty: {path}")
                machine_id_status = "File Empty" # Indicate this path was empty, continue search

        except FileNotFoundError:
            logging.debug(f"Machine ID file not found at {path}, trying next if available.")
            machine_id_status = "Not Found" # Reset status for the loop if not found at this path
        except Exception as e:
            # An unexpected error occurred while reading the file
            err_msg = f"Error reading {path}: {e}"
            logging.error(err_msg)
            machine_id_status = f"Error: {err_msg}" # Set status to indicate read error
            break # Error reading this path, stop trying others

    # After the loop, machine_id_status will hold either the found ID, "Not Found", "File Empty", or "Error: ..."
    return machine_id_status

def get_host_hostname() -> str:
    """
    Retrieves the hostname of the host system.

    Returns:
        str: The hostname string, or an informative string on failure.
    """
    try:
        hostname = socket.gethostname()
        logging.debug(f"Hostname retrieved: {hostname}")
        return hostname
    except Exception as e:
        err_msg = f"Error getting hostname: {e}"
        logging.error(err_msg)
        return f"Error: {err_msg}"

def get_host_mac_addresses() -> Dict[str, str]:
    """
    Retrieves MAC addresses for network interfaces by reading sysfs.

    Returns:
        Dict[str, str]: A dictionary mapping interface names to MAC addresses.
                        Includes status messages for interfaces where MAC could not be retrieved.
    """
    mac_addresses: Dict[str, str] = {}
    sys_net_path = "/sys/class/net/"

    if not os.path.isdir(sys_net_path):
        logging.warning(f"Network interface info path not found: {sys_net_path}")
        return {"status": f"Path not found: {sys_net_path}"}

    try:
        # List all network interfaces (directories in /sys/class/net)
        interface_names = [d for d in os.listdir(sys_net_path) if os.path.isdir(os.path.join(sys_net_path, d))]

        for iface_name in interface_names:
            # Skip the loopback interface (lo) as it doesn't have a meaningful MAC
            if iface_name == 'lo':
                continue

            mac_file_path = os.path.join(sys_net_path, iface_name, "address")
            try:
                with open(mac_file_path, 'r') as f:
                    mac = f.read().strip()
                if mac and mac != '00:00:00:00:00:00': # Check if MAC is not empty or all zeros
                    mac_addresses[iface_name] = mac
                    logging.debug(f"Read MAC for {iface_name}: {mac}")
                else:
                    # File exists but contains empty or zero MAC (e.g., interface down or virtual)
                    mac_addresses[iface_name] = "N/A or All Zeros"
                    logging.debug(f"MAC N/A or zero for {iface_name}")
            except FileNotFoundError:
                 # 'address' file not found (unlikely for a listed interface but possible)
                 mac_addresses[iface_name] = "Address file not found"
                 logging.warning(f"MAC address file not found for {iface_name}: {mac_file_path}")
            except Exception as e:
                # Any other reading error
                mac_addresses[iface_name] = f"Error reading address: {e}"
                logging.error(f"Error reading MAC for {iface_name}: {e}")

    except Exception as e:
        # Error listing directories in /sys/class/net
        logging.error(f"Error listing network interfaces in {sys_net_path}: {e}")
        return {"status": f"Error listing interfaces: {e}"}

    if not mac_addresses:
         # No interfaces found or all were loopback/skipped
         return {"status": "No non-loopback network interfaces found or MACs N/A"}

    return mac_addresses


# --- Vehicle Specific ID Placeholders ---
# These require specific vehicle interfaces (CAN, Ethernet services, diagnostic protocols)
# and potentially external libraries or manufacturer SDKs, which are not standard Python.

def get_vehicle_vin() -> str:
    """
    Placeholder function to retrieve the Vehicle Identification Number (VIN).

    Note: Actual implementation requires vehicle-specific communication interfaces
    (e.g., reading from CAN bus, querying a specific ECU via diagnostic protocol).
    """
    logging.info("Attempting to get Vehicle VIN (placeholder).")
    # Example of how a real implementation might look (requires external libraries):
    # try:
    #     import can
    #     # Connect to CAN interface, send VIN request message (specific to vehicle/protocol)
    #     # Listen for response message containing VIN
    #     # Parse VIN from response
    #     # return parsed_vin
    # except ImportError:
    #     return "VIN: Placeholder (python-can not installed)"
    # except Exception as e:
    #     return f"VIN: Placeholder (Error getting VIN - {e})"
    return "VIN_Placeholder_NotImplemented" # Return a clear placeholder status


def get_ecu_serial(ecu_name: str) -> str:
    """
    Placeholder function to retrieve a specific ECU's serial number or identifier.

    Note: Actual implementation requires diagnostic communication interfaces
    (e.g., UDS, OBD-II) and potentially manufacturer-specific UDS DIDs.
    """
    logging.info(f"Attempting to get ECU serial for '{ecu_name}' (placeholder).")
    # Example of how a real implementation might look (requires external libraries):
    # try:
    #     import uds
    #     # Connect to ECU (via CAN/Ethernet gateway), send UDS ReadDataByIdentifier request for Serial Number DID
    #     # Parse serial number from response
    #     # return parsed_serial
    # except ImportError:
    #     return f"ECU '{ecu_name}' Serial: Placeholder (uds library not installed)"
    # except Exception as e:
    #     return f"ECU '{ecu_name}' Serial: Placeholder (Error getting serial - {e})"
    return f"ECU_Serial_Placeholder_{ecu_name}_NotImplemented"


def get_sensor_unique_id(sensor_type: str, sensor_location: str) -> str:
    """
    Placeholder function to retrieve a unique ID (e.g., serial number, calibration ID)
    for a specific sensor instance.

    Note: Actual implementation depends heavily on the sensor type and how it exposes
    its ID (e.g., via a middleware topic message, a sensor-specific API call,
    reading from a configuration file published by the sensor driver).
    """
    logging.info(f"Attempting to get unique ID for {sensor_type} at {sensor_location} (placeholder).")
    # Example implementation might involve:
    # - Subscribing to a specific sensor status/info topic (requires middleware like ROS/DDS)
    # - Calling a sensor SDK function
    # - Reading a configuration file generated by the sensor driver
    return f"Sensor_ID_Placeholder_{sensor_type}_{sensor_location}_NotImplemented"


# --- Aggregator Function ---

def collect_all_ids() -> Dict[str, Any]:
    """
    Collects various identification numbers from the host system and vehicle
    (using placeholders for vehicle/component specific IDs).

    Returns:
        Dict[str, Any]: A dictionary containing collected IDs, grouped by category.
    """
    logging.info("Starting collection of various IDs...")
    all_ids: Dict[str, Any] = {
        "host_ids": {},
        "vehicle_ids": {},
        "component_ids": {} # Example category for ECU/sensor IDs
    }

    # --- Collect Host IDs ---
    try:
        all_ids["host_ids"]["machine_id"] = get_host_machine_id()
        all_ids["host_ids"]["hostname"] = get_host_hostname()
        all_ids["host_ids"]["mac_addresses"] = get_host_mac_addresses()
    except Exception as e:
        # Catch unexpected errors during host ID collection
        all_ids["host_ids"]["collection_error"] = f"Unexpected error during host ID collection: {e}"
        logging.error(all_ids["host_ids"]["collection_error"])


    # --- Collect Vehicle IDs (Placeholders) ---
    try:
        all_ids["vehicle_ids"]["vin"] = get_vehicle_vin()
        # Add other vehicle-level IDs here
    except Exception as e:
         all_ids["vehicle_ids"]["collection_error"] = f"Unexpected error during vehicle ID collection: {e}"
         logging.error(all_ids["vehicle_ids"]["collection_error"])


    # --- Collect Component IDs (Placeholders) ---
    try:
        # Example calls for component IDs
        all_ids["component_ids"]["brake_ecu_serial"] = get_ecu_serial("BrakeECU")
        all_ids["component_ids"]["adas_ecu_serial"] = get_ecu_serial("ADAS_Domain_Controller")
        all_ids["component_ids"]["front_lidar_id"] = get_sensor_unique_id("LiDAR", "Front")
        all_ids["component_ids"]["main_camera_id"] = get_sensor_unique_id("Camera", "FrontMain")
        # Add other component ID calls here
    except Exception as e:
         all_ids["component_ids"]["collection_error"] = f"Unexpected error during component ID collection: {e}"
         logging.error(all_ids["component_ids"]["collection_error"])


    logging.info("Finished collection of various IDs.")
    return all_ids


# Example Usage
if __name__ == "__main__":
    print("--- Collecting All Relevant IDs ---")
    all_collected_ids = collect_all_ids()

    import json
    print("\n--- Collected IDs Report (JSON Output) ---")
    print(json.dumps(all_collected_ids, indent=4))

    # Example of processing the results
    print("\n--- Collected IDs Summary ---")

    host_ids = all_collected_ids.get("host_ids", {})
    print("\nHost IDs:")
    print(f"  Machine ID: {host_ids.get('machine_id', 'N/A')}")
    print(f"  Hostname: {host_ids.get('hostname', 'N/A')}")
    macs = host_ids.get('mac_addresses')
    if macs:
        print("  MAC Addresses:")
        if isinstance(macs, dict):
            for iface, mac in macs.items():
                print(f"    {iface}: {mac}")
        else: # Handle status string case
             print(f"    Status: {macs}")
    if host_ids.get("collection_error"):
         print(f"  Collection Error: {host_ids['collection_error']}")


    vehicle_ids = all_collected_ids.get("vehicle_ids", {})
    print("\nVehicle IDs:")
    print(f"  VIN: {vehicle_ids.get('vin', 'N/A')}")
    if vehicle_ids.get("collection_error"):
         print(f"  Collection Error: {vehicle_ids['collection_error']}")


    component_ids = all_collected_ids.get("component_ids", {})
    print("\nComponent IDs:")
    if component_ids:
        for comp_key, comp_id in component_ids.items():
             print(f"  {comp_key}: {comp_id}")
    if component_ids.get("collection_error"):
         print(f"  Collection Error: {component_ids['collection_error']}")

    # Check for overall collection errors if needed
    # This is handled by the individual category collection errors above
