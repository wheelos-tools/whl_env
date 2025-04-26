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
import os
import glob  # For finding sensor files in sysfs
import re   # For parsing sensor file names and labels
import json  # For parsing 'sensors -j' output if available
# Added List for run_command signature
from typing import Dict, Any

from whl_env.utils import run_command

# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def _read_sysfs_value(path: str, value_type: Callable[[str], Any], default: Any = None) -> Any:
    """
    Safely reads a value from a sysfs file and attempts to cast it.

    Args:
        path: The full path to the sysfs file.
        value_type: The type to cast the read value to (e.g., int, float, str).
        default: The default value to return if reading or casting fails.

    Returns:
        The read and cast value, or the default value on failure.
    """
    try:
        with open(path, 'r') as f:
            value_str = f.read().strip()
        return value_type(value_str)
    except (FileNotFoundError, ValueError, TypeError, OSError) as e:
        # File not found, couldn't cast, or other OS error
        logging.debug(f"Could not read/parse sysfs file {path}: {e}")
        return default
    except Exception as e:
        logging.error(f"Unexpected error reading sysfs file {path}: {e}")
        return default


def get_hardware_sensors_info() -> Dict[str, Any]:
    """
    Collects hardware sensor information (temperature, fan speed, voltages, power draw)
    by reading sysfs and/or executing command-line tools.

    Returns:
        Dict[str, Any]: A dictionary containing categorized sensor information.
                        Includes 'temperatures_celsius', 'fan_speeds_rpm',
                        'voltages_volts', 'power_draw_watts', 'errors', 'notes'.
                        Values within categories are dictionaries mapping sensor
                        labels/names to measured values.
    """
    sensor_data: Dict[str, Any] = {
        "temperatures_celsius": {},
        "fan_speeds_rpm": {},
        "voltages_volts": {},
        "power_draw_watts": {},
        "errors": [],
        "notes": []
    }

    logging.info("Starting hardware sensor information collection...")

    # --- 1. Collect data from Sysfs (standard Linux interface) ---

    # 1a. Thermal Zones (/sys/class/thermal/thermal_zone*/temp)
    logging.info("Attempting to read thermal zones from sysfs...")
    thermal_zones_path = "/sys/class/thermal/thermal_zone*"
    for zone_path in glob.glob(thermal_zones_path):
        temp_path = os.path.join(zone_path, 'temp')
        type_path = os.path.join(zone_path, 'type')

        # Read temperature (usually in millidegrees Celsius)
        temp_millicel = _read_sysfs_value(temp_path, int, default=None)
        if temp_millicel is not None:
            temp_celsius = temp_millicel / 1000.0  # Convert millidegrees to degrees Celsius
            # Read the type/label for the zone (e.g., "cpu-thermal", "nvme")
            zone_type = _read_sysfs_value(type_path, str, default=os.path.basename(
                zone_path))  # Use folder name as fallback

            # Use a descriptive name, combine type and zone number if type is generic
            zone_name = zone_type
            # If type is generic like 'thermal_zoneN', use the full path component
            if re.match(r'thermal_zone\d+', os.path.basename(zone_path)):
                zone_name = os.path.basename(
                    zone_path) + (f" ({zone_type})" if zone_type != os.path.basename(zone_path) else "")

            # Store the temperature, prefer non-generic names if available
            # Avoid overwriting potentially better data from hwmon/sensors later
            if zone_name not in sensor_data["temperatures_celsius"] or "thermal_zone" in sensor_data["temperatures_celsius"].get(zone_name, "").lower():
                sensor_data["temperatures_celsius"][zone_name] = temp_celsius

    if not sensor_data["temperatures_celsius"]:
        sensor_data["notes"].append(
            "No thermal zone temperatures found in sysfs.")
        logging.info("No thermal zone temperatures found in sysfs.")

    # 1b. HWMON sensors (/sys/class/hwmon/hwmon*/{temp,fan,in}*_input)
    # This is more complex as file names and labels vary.
    logging.info("Attempting to read hwmon sensors from sysfs...")
    hwmon_path = "/sys/class/hwmon/hwmon*"
    hwmon_sensors_found = False
    for hwmon_dir in glob.glob(hwmon_path):
        device_name_path = os.path.join(hwmon_dir, 'name')
        device_name = _read_sysfs_value(device_name_path, str, default=os.path.basename(
            hwmon_dir))  # e.g., "coretemp", "nct6796"

        hwmon_sensors_found = True  # At least one hwmon directory exists

        # Read temperatures
        for temp_input_path in glob.glob(os.path.join(hwmon_dir, 'temp*_input')):
            temp_label_path = temp_input_path.replace('_input', '_label')
            temp_type_path = temp_input_path.replace(
                '_input', '_type')  # Alternative label

            temp_label = _read_sysfs_value(temp_label_path, str, default=_read_sysfs_value(
                temp_type_path, str, default=os.path.basename(temp_input_path).replace('_input', '')))
            temp_millicel = _read_sysfs_value(
                temp_input_path, int, default=None)

            if temp_millicel is not None:
                temp_celsius = temp_millicel / 1000.0
                # e.g., "coretemp_Package id 0"
                sensor_name = f"{device_name}_{temp_label}"

                # Store, preferring hwmon label if already found via thermal zones
                sensor_data["temperatures_celsius"][sensor_name] = temp_celsius
                logging.debug(
                    f"Read hwmon temp: {sensor_name}={temp_celsius}°C")

        # Read fan speeds
        for fan_input_path in glob.glob(os.path.join(hwmon_dir, 'fan*_input')):
            fan_label_path = fan_input_path.replace('_input', '_label')
            fan_label = _read_sysfs_value(fan_label_path, str, default=os.path.basename(
                fan_input_path).replace('_input', ''))
            fan_rpm = _read_sysfs_value(fan_input_path, int, default=None)

            if fan_rpm is not None and fan_rpm >= 0:  # Fan speed should be non-negative
                # e.g., "nct6796_Fan1"
                sensor_name = f"{device_name}_{fan_label}"
                sensor_data["fan_speeds_rpm"][sensor_name] = fan_rpm
                logging.debug(f"Read hwmon fan: {sensor_name}={fan_rpm} RPM")

        # Read voltages
        for in_input_path in glob.glob(os.path.join(hwmon_dir, 'in*_input')):
            in_label_path = in_input_path.replace('_input', '_label')
            in_label = _read_sysfs_value(in_label_path, str, default=os.path.basename(
                in_input_path).replace('_input', ''))
            in_millivolts = _read_sysfs_value(in_input_path, int, default=None)

            if in_millivolts is not None:
                voltage_volts = in_millivolts / 1000.0  # Convert millivolts to Volts
                # e.g., "nct6796_Vcore"
                sensor_name = f"{device_name}_{in_label}"
                sensor_data["voltages_volts"][sensor_name] = voltage_volts
                logging.debug(
                    f"Read hwmon voltage: {sensor_name}={voltage_volts} V")

    if not hwmon_sensors_found:
        sensor_data["notes"].append("No hwmon directories found in sysfs.")
        logging.info("No hwmon directories found in sysfs.")
    elif not sensor_data["temperatures_celsius"] and not sensor_data["fan_speeds_rpm"] and not sensor_data["voltages_volts"]:
        sensor_data["notes"].append(
            "Hwmon directories found but no sensor data could be read/parsed.")
        logging.warning(
            "Hwmon directories found but no sensor data could be read/parsed.")

    # 1c. Power Supply (/sys/class/power_supply/*) - for battery, AC adapter voltage/status
    logging.info("Attempting to read power supply info from sysfs...")
    power_supply_path = "/sys/class/power_supply/*"
    power_supply_found = False
    for ps_path in glob.glob(power_supply_path):
        ps_name = os.path.basename(ps_path)
        ps_type = _read_sysfs_value(os.path.join(
            ps_path, 'type'), str, default='Unknown')  # e.g., "Battery", "AC"

        power_supply_found = True  # At least one power_supply directory exists

        # e.g., "Charging", "Discharging", "Full"
        status = _read_sysfs_value(os.path.join(
            ps_path, 'status'), str, default=None)
        voltage_now_uv = _read_sysfs_value(os.path.join(
            ps_path, 'voltage_now'), int, default=None)  # In microvolts
        current_now_ua = _read_sysfs_value(os.path.join(
            ps_path, 'current_now'), int, default=None)  # In microamperes
        capacity_percent = _read_sysfs_value(os.path.join(
            ps_path, 'capacity'), int, default=None)  # Percentage

        ps_details: Dict[str, Any] = {"type": ps_type, "status": status}

        if voltage_now_uv is not None:
            ps_details["voltage_v"] = voltage_now_uv / \
                1000000.0  # Microvolts to Volts
        if current_now_ua is not None:
            ps_details["current_a"] = current_now_ua / \
                1000000.0  # Microamperes to Amperes
        if capacity_percent is not None:
            ps_details["capacity_percent"] = capacity_percent

        # Store power supply info, maybe under a dedicated key or aggregate
        # Let's aggregate voltage under voltages_volts if available,
        # and add other details under notes or a new 'power_supply' key.
        sensor_name = f"power_supply_{ps_name}"
        sensor_data[sensor_name] = ps_details  # Store all details here

        if 'voltage_v' in ps_details:
            # Add voltage to the general voltages section as well if meaningful
            voltage_label = f"{ps_name}_voltage"
            sensor_data["voltages_volts"][voltage_label] = ps_details['voltage_v']

    if not power_supply_found:
        sensor_data["notes"].append("No power_supply info found in sysfs.")
        logging.info("No power_supply info found in sysfs.")

    # --- 2. Collect data using command-line tools (fallbacks/specific data) ---

    # 2a. lm-sensors via 'sensors -j' (provides comprehensive data if configured)
    # This often duplicates sysfs but can provide more context and reach sensors
    # not exposed cleanly via standard hwmon labels. We can use it as a fallback
    # or to augment data. Let's try to use it as a potential source to fill gaps
    # or provide better labels if sysfs parsing was insufficient.
    logging.info("Attempting to get sensor data via 'sensors -j'...")
    sensors_cmd = ['sensors', '-j']
    success_sensors, output_sensors = run_command(sensors_cmd, timeout=10)

    if success_sensors and output_sensors:
        logging.info("'sensors -j' command successful. Parsing JSON output...")
        try:
            sensors_json = json.loads(output_sensors)
            # sensors_json structure is {adapter_name: {chip_name: {sensor_name: {unit: value, ...}}}}

            for adapter_name, chips in sensors_json.items():
                # Skip common virtual/less useful ones
                if adapter_name in ["acpitz-virtual-0", "thinkpad-isa-0000"]:
                    continue  # Example filtering

                for chip_name, sensors in chips.items():
                    for sensor_key, details in sensors.items():
                        # sensor_key is like "temp1", "fan2", "in0"
                        # details is like {"temp1_input": 45.0, "temp1_max": 80.0, "temp1_label": "Package id 0"}

                        # Use label if available
                        sensor_label = details.get(
                            f"{sensor_key}_label", sensor_key)
                        # Key for the actual value
                        sensor_input_key = f"{sensor_key}_input"

                        if sensor_input_key in details:
                            value = details[sensor_input_key]
                            # e.g., "coretemp_Package id 0"
                            full_sensor_name = f"{chip_name}_{sensor_label}"

                            if sensor_key.startswith('temp'):
                                if isinstance(value, (int, float)):
                                    # sensors output is already in Celsius
                                    sensor_data["temperatures_celsius"][full_sensor_name] = value
                                    logging.debug(
                                        f"Read sensors temp: {full_sensor_name}={value}°C")

                            elif sensor_key.startswith('fan'):
                                if isinstance(value, (int, float)) and value >= 0:
                                    # sensors output is usually already in RPM
                                    sensor_data["fan_speeds_rpm"][full_sensor_name] = value
                                    logging.debug(
                                        f"Read sensors fan: {full_sensor_name}={value} RPM")

                            elif sensor_key.startswith('in'):
                                if isinstance(value, (int, float)):
                                    # sensors output is usually already in Volts
                                    sensor_data["voltages_volts"][full_sensor_name] = value
                                    logging.debug(
                                        f"Read sensors voltage: {full_sensor_name}={value} V")

            if not sensor_data["temperatures_celsius"] and not sensor_data["fan_speeds_rpm"] and not sensor_data["voltages_volts"]:
                sensor_data["notes"].append(
                    "'sensors -j' executed but no temperature, fan, or voltage data was parsed.")
                logging.warning(
                    "'sensors -j' executed but no temperature, fan, or voltage data was parsed.")

        except json.JSONDecodeError as e:
            err_msg = f"Error parsing JSON output from 'sensors -j': {e}"
            sensor_data["errors"].append(err_msg)
            logging.error(err_msg)
        except Exception as e:
            err_msg = f"Unexpected error parsing 'sensors -j' output: {e}"
            sensor_data["errors"].append(err_msg)
            logging.error(err_msg)

    elif not success_sensors:
        if "command not found" in output_sensors.lower():
            sensor_data["notes"].append(
                "'sensors' command not found (lm-sensors not installed or in PATH).")
            logging.warning("'sensors' command not found.")
        else:
            err_msg = f"Error executing 'sensors -j': {output_sensors}"
            sensor_data["errors"].append(err_msg)
            logging.error(err_msg)
    # else: success_sensors is True but output_sensors is empty (unlikely for sensors -j if sensors exist)

    # 2b. nvidia-smi (specific for NVIDIA GPUs)
    # This provides GPU temperature and power draw if an NVIDIA GPU is present and driver is installed.
    logging.info("Attempting to get NVIDIA GPU info via nvidia-smi...")
    nvidia_smi_cmd = [
        'nvidia-smi',
        '--query-gpu=name,temperature.gpu,power.draw',
        '--format=csv,noheader'
    ]
    success_nvidia, output_nvidia = run_command(nvidia_smi_cmd, timeout=5)

    if success_nvidia and output_nvidia:
        logging.info("'nvidia-smi' command successful. Parsing output...")
        # Expected CSV format: name, temperature.gpu [C], power.draw [W]
        for i, line in enumerate(output_nvidia.strip().split('\n')):
            if not line.strip():
                continue
            try:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) == 3:
                    gpu_name = parts[0]
                    # Remove unit suffixes and convert
                    temp_celsius = float(parts[1].split(' ')[0]) if parts[1].split(' ')[
                        0].isdigit() else None
                    power_watts = float(parts[2].split(' ')[0]) if parts[2].split(
                        ' ')[0].replace('.', '', 1).isdigit() else None  # Handle float

                    # Use GPU name + index as key if multiple GPUs
                    gpu_key = f"{gpu_name}_{i}" if len(
                        output_nvidia.strip().split('\n')) > 1 else gpu_name

                    if temp_celsius is not None:
                        sensor_data["temperatures_celsius"][f"{gpu_key}_GPU"] = temp_celsius
                        logging.debug(
                            f"Read nvidia-smi temp: {gpu_key}_GPU={temp_celsius}°C")

                    if power_watts is not None:
                        sensor_data["power_draw_watts"][f"{gpu_key}_GPU"] = power_watts
                        logging.debug(
                            f"Read nvidia-smi power: {gpu_key}_GPU={power_watts} W")

                else:
                    sensor_data["errors"].append(
                        f"Unexpected nvidia-smi output format for line: {line}")
                    logging.warning(sensor_data["errors"][-1])

            except (ValueError, IndexError) as e:
                sensor_data["errors"].append(
                    f"Error parsing nvidia-smi output line '{line}': {e}")
                logging.error(sensor_data["errors"][-1])
            except Exception as e:
                sensor_data["errors"].append(
                    f"Unexpected error parsing nvidia-smi line '{line}': {e}")
                logging.error(sensor_data["errors"][-1])

    elif not success_nvidia:
        if "command not found" in output_nvidia.lower():
            sensor_data["notes"].append(
                "'nvidia-smi' command not found (No NVIDIA GPU or driver not installed).")
            logging.info("'nvidia-smi' command not found.")
        else:
            err_msg = f"Error executing 'nvidia-smi': {output_nvidia}"
            sensor_data["errors"].append(err_msg)
            logging.error(err_msg)
    # else: success_nvidia is True but output_nvidia is empty (unlikely if GPU is present)

    # --- 3. Notes on Other Potential Sources (IPMI, Direct i2c, Vendor Tools) ---
    sensor_data["notes"].append(
        "Sensor data collected from sysfs (/sys/class/thermal, /sys/class/hwmon, /sys/class/power_supply)"
        " and potentially command-line tools ('sensors', 'nvidia-smi')."
    )
    sensor_data["notes"].append(
        "Comprehensive hardware monitoring often requires tools like 'ipmitool' (for IPMI),"
        " vendor-specific utilities, or low-level access via libraries (e.g., python-smbus for i2c)."
        " These methods are not included in this general implementation."
    )
    # Add notes about potential need for root privileges for some tools ('sensors', 'ipmitool')
    # The run_command implementation should ideally handle potential permission errors.

    logging.info("Hardware sensor information collection finished.")
    return sensor_data


# Example Usage
if __name__ == "__main__":
    print("Gathering hardware sensor information...")
    sensors_report = get_hardware_sensors_info()

    import json
    print("\n--- Hardware Sensor Report (JSON Output) ---")
    print(json.dumps(sensors_report, indent=4))

    # Example of processing the results
    print("\n--- Hardware Sensor Summary ---")

    temps = sensors_report.get('temperatures_celsius', {})
    if temps:
        print("\nTemperatures (°C):")
        for label, temp in temps.items():
            print(f"  {label}: {temp:.2f}")
    else:
        print("\nTemperatures: Not available or could not be read.")

    fans = sensors_report.get('fan_speeds_rpm', {})
    if fans:
        print("\nFan Speeds (RPM):")
        for label, rpm in fans.items():
            print(f"  {label}: {rpm}")
    else:
        print("\nFan Speeds: Not available or could not be read.")

    volts = sensors_report.get('voltages_volts', {})
    if volts:
        print("\nVoltages (V):")
        for label, volt in volts.items():
            print(f"  {label}: {volt:.3f}")
    else:
        print("\nVoltages: Not available or could not be read.")

    power = sensors_report.get('power_draw_watts', {})
    if power:
        print("\nPower Draw (W):")
        for label, watts in power.items():
            print(f"  {label}: {watts:.2f}")
    else:
        print("\nPower Draw: Not available or could not be read.")

    # Optional: Print detailed power supply info if collected
    ps_info_keys = [k for k in sensors_report.keys(
    ) if k.startswith('power_supply_')]
    if ps_info_keys:
        print("\nPower Supply Details:")
        for key in ps_info_keys:
            ps_details = sensors_report[key]
            print(
                f"  {key.replace('power_supply_', '')} (Type: {ps_details.get('type', 'N/A')}):")
            print(f"    Status: {ps_details.get('status', 'N/A')}")
            if 'voltage_v' in ps_details:
                print(f"    Voltage: {ps_details['voltage_v']:.3f} V")
            if 'current_a' in ps_details:
                print(f"    Current: {ps_details['current_a']:.3f} A")
            if 'capacity_percent' in ps_details:
                print(f"    Capacity: {ps_details['capacity_percent']}%")

    notes = sensors_report.get('notes', [])
    if notes:
        print("\nNotes:")
        for note in notes:
            print(f"- {note}")

    errors = sensors_report.get('errors', [])
    if errors:
        print("\nErrors Encountered:")
        for error in errors:
            print(f"- {error}")

    if not any([temps, fans, volts, power]) and not errors and not notes:
        print("\nNo hardware sensor data could be collected using the available methods.")
