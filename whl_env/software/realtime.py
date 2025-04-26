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
import re
from typing import Dict, Any, Optional, Tuple, List

from whl_env.utils import run_command

# Configure basic logging if not already configured
# In a real application, you would configure logging more elaborately
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---


def _read_proc_file(path: str) -> Tuple[Optional[str], List[str]]:
    """
    Safely reads the content of a /proc file.

    Returns:
        Tuple[Optional[str], List[str]]: A tuple containing the file content
        (or None if error) and a list of error messages encountered.
    """
    errors: List[str] = []
    try:
        with open(path, 'r') as f:
            return f.read().strip(), errors
    except FileNotFoundError:
        err_msg = f"Proc file not found: {path}"
        logging.warning(err_msg)
        errors.append(err_msg)
        return None, errors
    except Exception as e:
        err_msg = f"Error reading proc file {path}: {e}"
        logging.error(err_msg)
        errors.append(err_msg)
        return None, errors

# Note: _format_uptime is not used in the RT analysis but was in the previous
# system_info context. We can keep it if this module is intended for general
# system info, or remove it if strictly focused on RT. Keeping it for now
# as it's a useful helper.
# def _format_uptime(seconds: float) -> str: ... (Definition from previous response)


# --- Real-time System Status Components ---

def get_cpu_scheduling_policy_info() -> Dict[str, Any]:
    """
    Analyzes CPU scheduling policy configuration (isolcpus, rtkit, cgroups).

    Returns:
        Dict[str, Any]: Dictionary containing policy info, errors, and notes.
        Structure: {'policy_info': {...}, 'errors': [...], 'notes': [...]}
    """
    policy_info: Dict[str, Any] = {}
    errors: List[str] = []
    notes: List[str] = []

    logging.info(
        "Analyzing CPU scheduling policy (isolcpus, rtkit, cgroups)...")

    # 1a. Check for isolcpus in /proc/cmdline
    cmdline_content, cmdline_errors = _read_proc_file("/proc/cmdline")
    errors.extend(cmdline_errors)
    if cmdline_content:
        isolcpus_match = re.search(
            r'isolcpus=([^,\s]+(?:,[^,\s]+)*)', cmdline_content)
        if isolcpus_match:
            isolated_cpus = isolcpus_match.group(1)
            policy_info['isolcpus_active'] = True
            policy_info['isolated_cpus'] = isolated_cpus
            notes.append(f"Kernel booted with isolcpus: {isolated_cpus}")
            logging.info(f"Found isolcpus: {isolated_cpus}")
        else:
            policy_info['isolcpus_active'] = False
            logging.info("isolcpus kernel parameter not found.")
    else:
        policy_info['isolcpus_active'] = "Error reading /proc/cmdline"
        policy_info['isolated_cpus'] = None

    # 1b. Check for rtkit-daemon process (common indicator of rtkit usage)
    # Use ps to list processes and grep for rtkit-daemon
    logging.info("Checking for rtkit-daemon process...")
    ps_rtkit_cmd = ['ps', 'aux']
    success_ps, output_ps = run_command(ps_rtkit_cmd, timeout=5)
    if success_ps and output_ps:
        # Look for a line containing 'rtkit-daemon' but not the grep command itself
        if re.search(r'\n[^ ]+ +\d+.*? rtkit-daemon', output_ps):
            policy_info['rtkit_daemon_running'] = True
            notes.append("rtkit-daemon process detected.")
            logging.info("rtkit-daemon process found.")
        else:
            policy_info['rtkit_daemon_running'] = False
            logging.info("rtkit-daemon process not found.")
    elif not success_ps:
        err_msg = f"Error executing ps to check rtkit-daemon: {output_ps}"
        policy_info['rtkit_daemon_running'] = err_msg
        errors.append(err_msg)
        logging.error(err_msg)
    # else: success_ps is True but output_ps is empty (unlikely for 'ps aux')

    # 1c. Check for relevant cgroup controllers in /proc/cgroups
    logging.info("Checking cgroup controllers in /proc/cgroups...")
    cgroups_content, cgroups_errors = _read_proc_file("/proc/cgroups")
    errors.extend(cgroups_errors)
    cgroup_controllers = {}
    if cgroups_content:
        # File format: #subsys_name hierarchy num_cgroups enabled
        # We are interested in 'cpu', 'cpuset', 'schedtune' (for EAS)
        controller_pattern = re.compile(
            r'^(cpu|cpuset|schedtune)\s+\d+\s+\d+\s+(\d+)$', re.MULTILINE)
        matches = controller_pattern.findall(cgroups_content)
        if matches:
            policy_info['cgroups_enabled'] = True
            policy_info['enabled_rt_controllers'] = {}
            for controller, enabled_flag in matches:
                is_enabled = (enabled_flag == '1')
                policy_info['enabled_rt_controllers'][controller] = is_enabled
                if is_enabled:
                    logging.info(
                        f"Cgroup controller '{controller}' is enabled.")
                else:
                    logging.info(
                        f"Cgroup controller '{controller}' is disabled.")
            # Should not happen if matches is not empty, but safety check
            if not policy_info['enabled_rt_controllers']:
                policy_info['cgroups_enabled'] = False
                policy_info['enabled_rt_controllers'] = "No relevant controllers found or parsed"
                logging.warning(
                    "Relevant cgroup controllers not found in /proc/cgroups content.")

        else:
            policy_info['cgroups_enabled'] = False
            policy_info['enabled_rt_controllers'] = "No relevant controllers found or parsed"
            logging.info(
                "No relevant cgroup controllers found or parsed from /proc/cgroups.")

    else:
        policy_info['cgroups_enabled'] = "Error reading /proc/cgroups"
        policy_info['enabled_rt_controllers'] = None

    policy_info['note'] = "Checks for isolcpus kernel param, rtkit-daemon process, and enabled cgroup controllers."
    return {'policy_info': policy_info, 'errors': errors, 'notes': notes}


def get_realtime_thread_stats() -> Dict[str, Any]:
    """
    Collects statistics and details on real-time threads (FIFO/Round-Robin).

    Returns:
        Dict[str, Any]: Dictionary containing thread stats, errors, and notes.
        Structure: {'thread_stats': {...}, 'errors': [...], 'notes': [...]}
    """
    thread_stats: Dict[str, Any] = {
        "total_rt_threads": 0,
        "fifo_threads": 0,
        "rr_threads": 0,
        "top_rt_threads": [],  # List of dicts
    }
    errors: List[str] = []
    notes: List[str] = [
        "Statistics derived from 'ps -eo pid,comm,cls,rtprio' output."]

    logging.info("Collecting real-time thread statistics...")

    # Use ps with specific format to list process/thread scheduling class and RT priority
    # --sort=-rtprio sorts by RT priority descending
    ps_rt_cmd = ['ps', '-eo', 'pid,comm,cls,rtprio', '--sort=-rtprio']
    success_ps_rt, output_ps_rt = run_command(ps_rt_cmd, timeout=10)

    if success_ps_rt and output_ps_rt:
        logging.info(
            "'ps -eo ... --sort=-rtprio' command successful. Parsing output...")
        lines = output_ps_rt.strip().split('\n')
        if len(lines) > 1:  # Skip header line
            header = lines[0].split()  # Expected: PID COMM CLS RTPRIO
            # Find column indices (might vary slightly) - assuming fixed order for -eo
            try:
                # Using findall for more robust column splitting based on header positions
                # Regex to find column values based on header positions, handling varying whitespace
                # Get start/end positions of headers
                header_pos = {name: header.find(name) for name in [
                    'PID', 'COMM', 'CLS', 'RTPRIO']}
                # Sort by position
                sorted_headers = sorted(
                    header_pos.items(), key=lambda item: item[1])

                # Build regex pattern based on header positions to capture column values
                # Example: PID\s+(.*?)\s+COMM\s+(.*?)\s+CLS\s+(.*?)\s+RTPRIO\s+(.*) -- simplified
                # More robust: Use actual positions
                # This is still tricky with variable length COMM. Let's rely on splitting by whitespace and index.
                # ps -eo output *is* generally splitable by arbitrary whitespace for these fields.
                # Let's re-parse the header to ensure indices.
                parts = lines[0].split()
                pid_idx = parts.index('PID') if 'PID' in parts else -1
                comm_idx = parts.index('COMM') if 'COMM' in parts else -1
                cls_idx = parts.index('CLS') if 'CLS' in parts else -1
                rtprio_idx = parts.index('RTPRIO') if 'RTPRIO' in parts else -1

                if -1 in [pid_idx, comm_idx, cls_idx, rtprio_idx]:
                    err_msg = f"Could not find required columns (PID, COMM, CLS, RTPRIO) in ps output header: {lines[0]}"
                    errors.append(err_msg)
                    logging.error(err_msg)
                    # Cannot parse data lines without correct indices
                else:
                    for line in lines[1:]:
                        if not line.strip():
                            continue
                        # Split by arbitrary whitespace. This is generally safe for ps -o output.
                        parts = line.split()

                        # Ensure enough parts are present before accessing indices
                        if len(parts) > max(pid_idx, comm_idx, cls_idx, rtprio_idx):
                            try:
                                pid = int(parts[pid_idx])
                                # Comm might be truncated by ps
                                comm = parts[comm_idx]
                                cls = parts[cls_idx]
                                rtprio_str = parts[rtprio_idx]

                                if cls in ['RR', 'FF']:
                                    thread_stats["total_rt_threads"] += 1
                                    if cls == 'RR':
                                        thread_stats['rr_threads'] += 1
                                    else:  # FF
                                        thread_stats['fifo_threads'] += 1

                                    # Try to parse RT priority (RTPRIO column might be '-' for non-RT)
                                    try:
                                        rtprio = int(
                                            rtprio_str) if rtprio_str != '-' else 0
                                    except ValueError:
                                        rtprio = 0  # Should not happen for RR/FF but safety

                                    # Store top N threads (e.g., top 10) by priority
                                    # Keep list size reasonable, sort by priority descending
                                    thread_entry = {
                                        "pid": pid,
                                        "comm": comm,
                                        "class": cls,
                                        "priority": rtprio
                                    }
                                    thread_stats['top_rt_threads'].append(
                                        thread_entry)
                                    # Sort and trim after adding to keep list small
                                    thread_stats['top_rt_threads'].sort(
                                        key=lambda x: x['priority'], reverse=True)
                                    # Keep only top 10
                                    thread_stats['top_rt_threads'] = thread_stats['top_rt_threads'][:10]

                            except (ValueError, IndexError) as e:
                                err_msg = f"Error parsing ps RT data line '{line}': {e}"
                                errors.append(err_msg)
                                logging.error(err_msg)
                            except Exception as e:  # Catch other unexpected errors
                                err_msg = f"Unexpected error processing ps RT data line '{line}': {e}"
                                errors.append(err_msg)
                                logging.error(err_msg)
                        else:
                            # Line doesn't have enough columns based on header indices
                            err_msg = f"Skipping ps RT line with insufficient columns: {line}"
                            # Often header or summary lines, or malformed
                            logging.warning(err_msg)
                            # errors.append(err_msg) # Decide if this warrants an error or just warning

            except ValueError as e:  # Header parsing error
                err_msg = f"Error parsing ps RT header line '{lines[0]}': {e}"
                errors.append(err_msg)
                logging.error(err_msg)

        elif len(lines) == 1:  # Only header
            logging.info(
                "'ps -eo ...' returned only header, no processes/threads found?")
        # else: output was empty (handled by success check)

    elif not success_ps_rt:
        err_msg = f"Error executing 'ps -eo ...': {output_ps_rt}"
        errors.append(err_msg)
        notes[0] = f"Statistics could not be fully derived due to 'ps' execution error: {output_ps_rt}"
        logging.error(err_msg)

    return {'thread_stats': thread_stats, 'errors': errors, 'notes': notes}


def get_system_latency_analysis_info() -> Dict[str, Any]:
    """
    Reports on system latency analysis tools (cyclictest availability).
    Does NOT run latency benchmarks.

    Returns:
        Dict[str, Any]: Dictionary containing latency analysis info, errors, and notes.
        Structure: {'latency_info': {...}, 'errors': [...], 'notes': [...]}
    """
    latency_info: Dict[str, Any] = {}
    errors: List[str] = []
    notes: List[str] = []

    logging.info("Checking for system latency analysis tools (cyclictest)...")

    # Check if cyclictest command is available
    which_cyclictest_cmd = ['which', 'cyclictest']
    success_which, output_which = run_command(which_cyclictest_cmd, timeout=5)

    if success_which and output_which.strip():
        latency_info['cyclictest_available'] = True
        latency_info['cyclictest_path'] = output_which.strip()
        notes.append(
            "Cyclictest is available. It is the standard tool for measuring Linux RT latency."
            " Running it requires specific parameters and test conditions."
            " Its results (max latency, histograms) are typically parsed from its output files."
            " This function only reports availability, it does NOT run cyclictest."
        )
        logging.info("Cyclictest command found.")
    elif not success_which:
        latency_info['cyclictest_available'] = False
        latency_info['cyclictest_path'] = None
        note_msg = (
            "'cyclictest' command not found. It is the standard tool for measuring Linux RT latency."
            " Install 'rt-tests' package on RT kernel systems to get it."
        )
        notes.append(note_msg)

        if "command not found" in output_which.lower():
            logging.warning(note_msg)
        else:
            err_msg = f"Error executing 'which cyclictest': {output_which}"
            errors.append(err_msg)
            logging.error(err_msg)

    # Placeholder for parsing cyclictest results if needed in the future
    # latency_info['cyclictest_last_results'] = "Parsing not implemented" # Example

    return {'latency_info': latency_info, 'errors': errors, 'notes': notes}


def get_irq_binding_info() -> Dict[str, Any]:
    """
    Analyzes IRQ binding status by parsing /proc/interrupts.

    Returns:
        Dict[str, Any]: Dictionary containing IRQ binding info, errors, and notes.
        Structure: {'irq_binding_info': {...}, 'errors': [...], 'notes': [...]}
    """
    irq_binding_info: Dict[str, Any] = {
        "total_irqs_listed": 0,
        "irqs_with_per_cpu_counts": [],  # List of IRQs that report counts per CPU
        "bound_irqs_heuristic": [],  # List of IRQs that *appear* bound based on counts
    }
    errors: List[str] = []
    notes: List[str] = [
        "IRQ affinity (binding) is heuristically determined by looking at per-CPU counts in /proc/interrupts. For definitive binding status, check /proc/irq/*/smp_affinity."]

    logging.info("Analyzing IRQ binding from /proc/interrupts...")
    interrupts_content, interrupts_errors = _read_proc_file("/proc/interrupts")
    errors.extend(interrupts_errors)

    if interrupts_content:
        logging.info("Successfully read /proc/interrupts. Parsing...")
        lines = interrupts_content.strip().split('\n')
        if len(lines) > 1:
            header = lines[0].strip()
            # Extract CPU names from the header line (e.g., "CPU0 CPU1 CPU2...")
            cpu_names = header.split()
            num_cpus = len(cpu_names)
            if num_cpus > 0:  # Ensure at least one CPU column was found

                # Find indices of CPU columns in the data lines.
                # Data lines format: IRQ_NUM: count0 count1 ... type DEVICE_NAME
                # The counts line up with the CPU columns in the header.
                # Split data lines by whitespace. The first part is IRQ_NUM:, last part is DEVICE_NAME.
                # The parts in between are the counts. Need to handle potential multi-word device names.
                # Let's split by ':' first to isolate IRQ_NUM:
                # Then split the rest by whitespace. The counts are the first `num_cpus` values.

                irq_lines = lines[1:]
                # Filter out summary lines that don't start with a digit followed by ':'
                irq_lines = [line for line in irq_lines if line.strip(
                ) and re.match(r'^\d+:', line.strip())]

                irq_binding_info["total_irqs_listed"] = len(irq_lines)

                for line in irq_lines:
                    line = line.strip()
                    if not line:
                        continue  # Skip empty lines

                    parts_colon_split = line.split(':', 1)
                    # Already filtered lines to start with digit:, but adding check for safety
                    if len(parts_colon_split) != 2:
                        logging.warning(
                            f"Skipping malformed IRQ line (unexpected format): {line}")
                        continue

                    irq_num_part = parts_colon_split[0].strip()
                    data_part = parts_colon_split[1].strip()

                    # Split the data part by whitespace. The first `num_cpus` parts should be the counts.
                    data_parts = data_part.split()

                    if len(data_parts) > num_cpus:
                        # Extract counts for each CPU
                        per_cpu_counts_str = data_parts[:num_cpus]
                        # e.g., "IO-APIC", "Edge", "fwnode"
                        interrupt_type = data_parts[num_cpus]
                        # The rest is the device name
                        device_name = " ".join(data_parts[num_cpus + 1:])

                        per_cpu_counts: Dict[str, int] = {}
                        total_count = 0
                        per_cpu_valid_counts = 0  # Count how many CPUs have non-zero interrupts

                        try:
                            for i in range(num_cpus):
                                count = int(per_cpu_counts_str[i])
                                per_cpu_counts[cpu_names[i]] = count
                                total_count += count
                                if count > 0:
                                    per_cpu_valid_counts += 1

                            # Store IRQ details
                            irq_details = {
                                "irq": irq_num_part,
                                "type": interrupt_type,
                                "device": device_name,
                                "counts": per_cpu_counts,
                                "total_count": total_count
                            }

                            if total_count > 0:  # Only consider IRQs that have occurred
                                irq_binding_info["irqs_with_per_cpu_counts"].append(
                                    irq_details)

                                # Heuristic check for binding: If interrupts only occurred on
                                # a strict subset of CPUs where the total count > 0.
                                # If total_count > 0 and per_cpu_valid_counts < num_cpus
                                # and per_cpu_valid_counts > 0 (not all counts are zero)
                                if per_cpu_valid_counts > 0 and per_cpu_valid_counts < num_cpus:
                                    # Identify the CPUs where counts are non-zero
                                    bound_cpus = [
                                        cpu for cpu, count in per_cpu_counts.items() if count > 0]
                                    irq_details["bound_cpus_heuristic"] = ", ".join(
                                        bound_cpus)
                                    irq_binding_info["bound_irqs_heuristic"].append(
                                        irq_details)
                                    logging.debug(
                                        f"Heuristic bound IRQ {irq_num_part} to CPUs: {bound_cpus}")

                            else:
                                # IRQ listed but no interrupts occurred yet - can't determine binding heuristically
                                # logging.debug(f"IRQ {irq_num_part} listed but no counts yet.")
                                pass

                        except (ValueError, IndexError) as e:
                            err_msg = f"Error parsing /proc/interrupts count data for line '{line}': {e}"
                            errors.append(err_msg)
                            logging.error(err_msg)
                        except Exception as e:  # Catch other unexpected errors
                            err_msg = f"Unexpected error processing /proc/interrupts line '{line}': {e}"
                            errors.append(err_msg)
                            logging.error(err_msg)

                    else:
                        err_msg = f"Unexpected /proc/interrupts data part format (expected >{num_cpus} parts): {line}"
                        errors.append(err_msg)
                        logging.warning(err_msg)

            else:
                err_msg = f"Could not parse CPU names from /proc/interrupts header: {header}"
                errors.append(err_msg)
                logging.error(err_msg)

        elif len(lines) == 1:  # Only header
            logging.info(
                "/proc/interrupts contains only header, no IRQs found?")
        # else: content was empty (handled by _read_proc_file)

    return {'irq_binding_info': irq_binding_info, 'errors': errors, 'notes': notes}


# --- Aggregator Function ---

def collect_realtime_system_status() -> Dict[str, Any]:
    """
    Collects comprehensive status information related to real-time scheduling
    and system configuration by calling dedicated functions.

    Returns:
        Dict[str, Any]: A dictionary containing aggregated real-time system status.
        Includes:
        - 'cpu_scheduling_policy': Details on isolcpus, rtkit, cgroups.
        - 'realtime_threads': Statistics and top threads.
        - 'system_latency_analysis': Info on relevant tools like cyclictest.
        - 'irq_binding': Details on IRQ affinity.
        - 'aggregated_errors': List of all collection errors.
        - 'aggregated_notes': List of all informational notes.
    """
    logging.info(
        "Starting comprehensive real-time system status collection...")

    aggregated_results: Dict[str, Any] = {
        "cpu_scheduling_policy": {},
        "realtime_threads": {},
        "system_latency_analysis": {},
        "irq_binding": {},
        "aggregated_errors": [],
        "aggregated_notes": []
    }

    # Call individual collection functions and aggregate their results
    policy_result = get_cpu_scheduling_policy_info()
    aggregated_results["cpu_scheduling_policy"] = policy_result['policy_info']
    aggregated_results["aggregated_errors"].extend(policy_result['errors'])
    aggregated_results["aggregated_notes"].extend(policy_result['notes'])

    threads_result = get_realtime_thread_stats()
    aggregated_results["realtime_threads"] = threads_result['thread_stats']
    aggregated_results["aggregated_errors"].extend(threads_result['errors'])
    aggregated_results["aggregated_notes"].extend(threads_result['notes'])

    latency_result = get_system_latency_analysis_info()
    aggregated_results["system_latency_analysis"] = latency_result['latency_info']
    aggregated_results["aggregated_errors"].extend(latency_result['errors'])
    aggregated_results["aggregated_notes"].extend(latency_result['notes'])

    irq_result = get_irq_binding_info()
    aggregated_results["irq_binding"] = irq_result['irq_binding_info']
    aggregated_results["aggregated_errors"].extend(irq_result['errors'])
    aggregated_results["aggregated_notes"].extend(irq_result['notes'])

    logging.info("Finished comprehensive real-time system status collection.")
    return aggregated_results


# Example Usage
if __name__ == "__main__":
    print("Gathering real-time system status information (collected by aggregator)...")
    rt_status_report = collect_realtime_system_status()

    import json
    print("\n--- Real-time System Status Report (JSON Output) ---")
    print(json.dumps(rt_status_report, indent=4))

    # Example of processing the results (can refer back to the structure)
    print("\n--- Real-time System Status Summary ---")

    # CPU Scheduling Policy
    policy = rt_status_report.get('cpu_scheduling_policy', {})
    print("\nCPU Scheduling Policy:")
    print(f"  isolcpus Active: {policy.get('isolcpus_active', 'N/A')}")
    if policy.get('isolcpus_active') is True:
        print(f"  Isolated CPUs: {policy.get('isolated_cpus', 'N/A')}")
    print(
        f"  rtkit-daemon Running: {policy.get('rtkit_daemon_running', 'N/A')}")
    print(f"  Cgroups Enabled: {policy.get('cgroups_enabled', 'N/A')}")
    if policy.get('cgroups_enabled') is True and policy.get('enabled_rt_controllers'):
        print(
            f"  Enabled RT Cgroup Controllers: {policy['enabled_rt_controllers']}")

    # Real-time Thread Statistics
    rt_threads = rt_status_report.get('realtime_threads', {})
    print("\nReal-time Thread Statistics:")
    print(
        f"  Total RT Threads (RR/FF): {rt_threads.get('total_rt_threads', 'N/A')}")
    print(f"  FIFO Threads: {rt_threads.get('fifo_threads', 'N/A')}")
    print(f"  Round-Robin Threads: {rt_threads.get('rr_threads', 'N/A')}")
    if rt_threads.get('top_rt_threads'):
        print("  Top RT Threads (by priority):")
        for thread in rt_threads['top_rt_threads']:
            print(
                f"    PID: {thread.get('pid')}, COMM: {thread.get('comm')}, CLS: {thread.get('class')}, PRIO: {thread.get('priority')}")
    else:
        print("  No RT threads found or could not be listed.")

    # System Latency Analysis
    latency = rt_status_report.get('system_latency_analysis', {})
    print("\nSystem Latency Analysis (Cyclictest):")
    print(
        f"  Cyclictest Command Available: {latency.get('cyclictest_available', 'N/A')}")
    print(f"  Note: {latency.get('note', 'N/A')}")

    # IRQ Binding
    irq_bind = rt_status_report.get('irq_binding', {})
    print("\nIRQ Binding Analysis:")
    print(
        f"  Total IRQs Listed (/proc/interrupts): {irq_bind.get('total_irqs_listed', 'N/A')}")
    if irq_bind.get('bound_irqs_heuristic'):
        print("  Heuristically Bound IRQs (based on /proc/interrupts counts):")
        for irq_details in irq_bind['bound_irqs_heuristic']:
            print(f"    IRQ {irq_details.get('irq')}: Device '{irq_details.get('device', 'N/A')}' (Type: {irq_details.get('type', 'N/A')}) appears bound to CPUs: {irq_details.get('bound_cpus_heuristic', 'N/A')}")
            # Optional: Print counts per CPU
            # print(f"      Counts: {irq_details.get('counts', 'N/A')}")
    else:
        print("  No IRQs found or no heuristic binding detected based on counts.")
    print(f"  Note: {irq_bind.get('note', 'N/A')}")

    # Errors and Notes
    errors = rt_status_report.get('aggregated_errors', [])
    if errors:
        print("\nAggregated Errors Encountered:")
        for error in errors:
            print(f"- {error}")

    notes = rt_status_report.get('aggregated_notes', [])
    if notes:
        print("\nAggregated Notes:")
        for note in notes:
            print(f"- {note}")

    if not any([policy, rt_threads, latency, irq_bind]) and not errors and not notes:
        print("\nCould not collect any real-time system status information using available methods.")
