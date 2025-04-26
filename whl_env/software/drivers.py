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
import re
from whl_env.utils import run_command


def get_gpu_driver_version() -> Dict[str, Any]:
    """
    Attempts to retrieve the GPU driver version on Linux using common tools.

    Returns:
        A dictionary containing the driver information, including 'status' and 'version'.
    """
    info: Dict[str, Any] = {
        "status": "Failed to determine driver version on Linux", "version": None, "method": None}

    # Method 1: Try nvidia-smi (for NVIDIA GPUs)
    nvidia_smi_output = run_command(
        ['nvidia-smi', '--query-gpu=driver_version', '--format=csv,noheader'])
    if nvidia_smi_output:
        info["status"] = "Success"
        info["version"] = nvidia_smi_output
        info["method"] = "nvidia-smi"
        return info

    # Method 2: Try glxinfo (for OpenGL driver version, often tied to GPU driver)
    glxinfo_output = run_command(['glxinfo'])
    if glxinfo_output:
        # Parse glxinfo output
        match_version = re.search(
            r"^OpenGL(?: version string| core profile version string):.*$", glxinfo_output, re.MULTILINE)
        if match_version:
            version_string = match_version.group(0).split(':', 1)[1].strip()
            info["status"] = "Success (via OpenGL version)"
            info["version"] = version_string
            info["method"] = "glxinfo (OpenGL version)"
            return info

        # As a fallback, try finding the OpenGL renderer string
        match_renderer = re.search(
            r"^OpenGL renderer string:.*$", glxinfo_output, re.MULTILINE)
        if match_renderer:
            renderer_string = match_renderer.group(0).split(':', 1)[1].strip()
            info["status"] = "Success (via OpenGL renderer)"
            # Note: This is renderer info, not strict version
            info["version"] = renderer_string
            info["method"] = "glxinfo (OpenGL renderer)"
            # Don't return immediately, maybe other info is available, though less likely

    # If none of the methods worked
    info["status"] = "Could not determine GPU driver version using common Linux tools (nvidia-smi, glxinfo)."
    info["details"] = "Ensure 'nvidia-smi' is in PATH for NVIDIA, 'glxinfo' is installed (e.g., mesa-utils), and you have a display environment if using glxinfo."

    return {"gpu_driver": info}


if __name__ == "__main__":
    # Example usage
    driver_info = get_gpu_driver_version()
    print(driver_info)
