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

from whl_env.hardware.compute_unit.cpu import get_cpu_info
from whl_env.hardware.compute_unit.gpu import get_gpu_info
from whl_env.hardware.compute_unit.memory import get_memory_info
from whl_env.hardware.compute_unit.disk import get_filesystem_usage
from whl_env.hardware.compute_unit.network import get_network_info
from whl_env.software.autopilot import get_wheelos_version
from whl_env.software.system import get_system_info
from whl_env.software.drivers import get_gpu_driver_version


def collect_system_info() -> Dict[str, Any]:
    """
    Collects various system information and merges it into a single dictionary
    with keys ordered logically.

    Returns:
        dict: A dictionary containing collected system information with keys
              ordered in a logical sequence.
    """
    system_data: Dict[str, Any] = {}

    try:
        # Collect and merge data in a logical order
        system_data["system_info"] = get_system_info()
        system_data["wheelos_version"] = get_wheelos_version()
        system_data["gpu_driver_version"] = get_gpu_driver_version()
        system_data["cpu_info"] = get_cpu_info()
        system_data["gpu_info"] = get_gpu_info()
        system_data["memory_info"] = get_memory_info()
        system_data["filesystem_usage"] = get_filesystem_usage()
        system_data["network_info"] = get_network_info()

    except Exception as e:
        print(f"An error occurred during information collection: {e}")
        # Return partial data if an error occurs
        pass  # Or re-raise the exception if desired

    return system_data


if __name__ == "__main__":
    system_information_dict = collect_system_info()
    print(system_information_dict)
