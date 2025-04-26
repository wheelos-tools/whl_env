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

from whl_env.utils import run_command


def _parse_timedatectl(output: str) -> Dict[str, Any]:
    """Parses output from timedatectl show-timesync and timedatectl status."""
    info: Dict[str, Any] = {}
    if not output:
        return {"error": "No output from timedatectl"}

    # Use show-timesync for more structured data if available
    # Newer systemd versions support 'timedatectl show-timesync'
    timesync_output = run_command(['timedatectl', 'show-timesync'])
    if timesync_output:
        try:
            for line in timesync_output.splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Convert boolean-like strings to bool
                    if value.lower() in ['yes', 'true']:
                        info[key] = True
                    elif value.lower() in ['no', 'false']:
                        info[key] = False
                    else:
                        info[key] = value.strip('"')  # Remove potential quotes
            # Check overall sync status explicitly if not in show-timesync
            if 'SystemNTPSynchronized' not in info and 'NTPSynchronized' in info:
                # Compatibility
                info['SystemNTPSynchronized'] = info['NTPSynchronized']
            if 'SystemClockSynchronized' not in info and 'System clock synchronized' in info:
                # Compatibility
                info['SystemClockSynchronized'] = info['System clock synchronized']

        except Exception as e:
            info[
                "parse_error_show-timesync"] = f"Failed to parse timedatectl show-timesync output: {e}"
            # Keep raw output for debugging
            info["raw_show-timesync_output"] = timesync_output

    # Fallback or add general status from timedatectl status
    # This is less machine-readable but provides overall sync state and service
    status_output = run_command(['timedatectl', 'status'])
    if status_output:
        # Always keep raw status output
        info["raw_status_output"] = status_output
        try:
            for line in status_output.splitlines():
                line = line.strip()
                if line.startswith("NTP enabled:"):
                    info["NTP enabled (status)"] = "yes" in line.lower()
                elif line.startswith("NTP synchronized:"):
                    info["NTP synchronized (status)"] = "yes" in line.lower()
                elif line.startswith("System clock synchronized:"):
                    info["System clock synchronized (status)"] = "yes" in line.lower(
                    )
                elif line.startswith("RTC in local time:"):
                    info["RTC in local time (status)"] = "yes" in line.lower()
                elif line.startswith("NTP service:"):
                    info["NTP service (status)"] = line.split(
                        ":", 1)[1].strip()
        except Exception as e:
            info["parse_error_status"] = f"Failed to parse timedatectl status output: {e}"

    return info


def _check_ntp_chrony_ptp() -> Dict[str, Any]:
    """Checks NTP, Chrony, and potential PTP status on Linux."""
    status: Dict[str, Any] = {}

    # Check overall status using timedatectl (covers systemd-timesyncd, chrony, ntpd via systemd integration)
    # Pass empty string, parsing handles command calls
    status['timedatectl'] = _parse_timedatectl("")

    # Check Chrony status if it seems to be the service or just attempt
    chrony_tracking_output = run_command(['chronyc', 'tracking'])
    if chrony_tracking_output:
        status['chrony_tracking'] = {"status": "Output available"}
        try:
            # Basic parsing of chronyc tracking
            for line in chrony_tracking_output.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    status['chrony_tracking'][key.strip()] = value.strip()
            status['chrony_tracking']['synchronized'] = "System time" in status[
                'chrony_tracking'] and "synchronized" in status['chrony_tracking']["System time"].lower()
        except Exception as e:
            status['chrony_tracking'][
                "parse_error"] = f"Failed to parse chronyc tracking output: {e}"
            # Keep raw output
            status['chrony_tracking']["raw_output"] = chrony_tracking_output

        chrony_sources_output = run_command(['chronyc', 'sources'])
        if chrony_sources_output:
            status['chrony_sources'] = {
                "status": "Output available", "sources": []}
            try:
                # Simple parsing: skip header, split lines
                lines = chrony_sources_output.splitlines()
                if len(lines) > 1:  # Check if header + at least one source line exists
                    source_lines = lines[1:]
                    # This is a basic split; a more robust parser would handle column alignment
                    for line in source_lines:
                        parts = line.split()
                        if len(parts) >= 10:  # Expect at least 10 columns
                            source_info = {
                                'sync_state': parts[0],  # e.g., ^, *, +, x, ?
                                'name_ip': parts[1],
                                'stratum': parts[2],
                                'poll': parts[6],
                                'reach': parts[7],
                                'last_rx': parts[8],
                                'offset': parts[9],
                                'jitter_or_variance': parts[10] if len(parts) > 10 else 'N/A'
                            }
                            status['chrony_sources']['sources'].append(
                                source_info)
                    if not status['chrony_sources']['sources']:
                        status['chrony_sources']['status'] = "No sources listed (after header)"

            except Exception as e:
                status['chrony_sources'][
                    "parse_error"] = f"Failed to parse chronyc sources output: {e}"
                # Keep raw output
                status['chrony_sources']["raw_output"] = chrony_sources_output
        else:
            status['chrony_sources'] = {
                "status": "chronyc sources command failed or not available"}

    else:
        status['chrony_tracking'] = {
            "status": "chronyc tracking command failed or not available (Is Chrony running?)"}
        status['chrony_sources'] = {
            "status": "chronyc sources command failed or not available (Is Chrony running?)"}

    # Check NTPd status if it seems to be the service or just attempt
    # Note: NTPd and Chronyd typically don't run at the same time.
    ntpq_p_output = run_command(['ntpq', '-p'])
    if ntpq_p_output:
        status['ntpq_-p'] = {"status": "Output available", "peers": []}
        try:
            lines = ntpq_p_output.splitlines()
            if len(lines) > 1:  # Check if header + at least one peer line exists
                peer_lines = lines[2:]  # Skip header lines
                # This parsing is sensitive to column alignment
                for line in peer_lines:
                    line = line.strip()
                    if not line or line.startswith("====="):
                        continue
                    # A more robust parser might use fixed column widths or regex
                    parts = line.split()
                    if len(parts) >= 10:  # Expect at least 10 columns for standard output
                        peer_info = {
                            'remote': parts[0],
                            'refid': parts[1],
                            'st': parts[2],
                            't': parts[3],
                            'when': parts[4],
                            'poll': parts[5],
                            'reach': parts[6],
                            'delay': parts[7],
                            'offset': parts[8],
                            'jitter': parts[9]
                        }
                        status['ntpq_-p']['peers'].append(peer_info)
                if not status['ntpq_-p']['peers']:
                    status['ntpq_-p']['status'] = "No peers listed (after headers)"

        except Exception as e:
            status['ntpq_-p']["parse_error"] = f"Failed to parse ntpq -p output: {e}"
            status['ntpq_-p']["raw_output"] = ntpq_p_output  # Keep raw output
    else:
        status['ntpq_-p'] = {
            "status": "ntpq -p command failed or not available (Is NTPd running?)"}

    # PTP Status (Basic Check)
    # Checking PTP sync status via standard tools is complex and setup-dependent.
    # We can check if ptp4l process is running as a basic indicator.
    # A real PTP check would involve 'pmc' or checking ptp4l logs/management interface.
    pgrep_ptp4l = run_command(['pgrep', 'ptp4l'])
    status['ptp4l_process'] = {"running": pgrep_ptp4l is not None}
    if pgrep_ptp4l is None:
        status['ptp4l_process']['status'] = "ptp4l process not found."
    else:
        status['ptp4l_process'][
            'status'] = f"ptp4l process(es) found with PIDs: {pgrep_ptp4l}"
        status['ptp4l_process']['note'] = "Note: Finding the process doesn't confirm sync status. Detailed PTP status requires 'pmc' or specific daemon logs."

    return status


def _check_system_rtc() -> Dict[str, Any]:
    """Checks System RTC (Hardware Clock) status on Linux."""
    status: Dict[str, Any] = {"hwclock": {}, "timedatectl": {}}

    # Get hwclock time
    hwclock_output = run_command(['hwclock', '--show'])
    if hwclock_output:
        status['hwclock']['status'] = "Output available"
        status['hwclock']['time_raw'] = hwclock_output.split(":", 1)[1].strip(
        ) if ":" in hwclock_output else hwclock_output  # Basic attempt to isolate time
        status['hwclock']['note'] = "Timezone and format depend on hwclock configuration/locale."
    else:
        status['hwclock']['status'] = "hwclock --show failed or not available."

    # Get RTC setting from timedatectl status
    # This info is already included in the timedatectl output from _check_ntp_chrony_ptp,
    # but we can get it specifically here for clarity or if calling separately.
    # Re-using the parser, focusing on RTC info.
    # Re-run timedatectl status/show-timesync
    tdctl_info = _parse_timedatectl("")
    status['timedatectl']['rtc_local_time'] = tdctl_info.get(
        'RTCInLocalTimeZone', tdctl_info.get('RTC in local time (status)'))  # Check both keys
    status['timedatectl']['status'] = "Timedatectl info parsed" if tdctl_info else "Timedatectl command failed or parsing issue."
    if 'error' in tdctl_info:
        status['timedatectl']['status'] = f"Timedatectl parsing error: {tdctl_info['error']}"
    if 'parse_error_status' in tdctl_info:
        status['timedatectl'][
            'status'] = f"Timedatectl status parsing error: {tdctl_info['parse_error_status']}"
    if 'parse_error_show-timesync' in tdctl_info:
        status['timedatectl'][
            'status'] = f"Timedatectl show-timesync parsing error: {tdctl_info['parse_error_show-timesync']}"

    return status


def _check_gps_sync_status(sync_status_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks if GPS/PPS source is used based on NTP/Chrony status output.
    This requires NTP/Chrony to be configured to use a GPS/PPS source.
    """
    status: Dict[str, Any] = {
        "status": "GPS/PPS source not detected or time service not running/reporting."}

    # Check Chrony sources output
    chrony_sources = sync_status_info.get('chrony_sources')
    if chrony_sources and chrony_sources.get('sources'):
        for source in chrony_sources['sources']:
            # Look for common indicators of GPS/PPS sources
            # e.g., refid like 'GPS', 'PPS(0)', source name mentioning '/dev/' or 'GPS'
            name_ip = source.get('name_ip', '').upper()
            refid = source.get('refid', '').upper()
            sync_state = source.get('sync_state')

            # Check for PPS indicators
            # 0.0.0.0 often indicates PPS driver
            if 'PPS' in name_ip or 'PPS' in refid or (refid == '0.0.0.0' and sync_state in ('*', '^')):
                status['status'] = "Potential GPS/PPS source detected in Chrony."
                status['details'] = f"Detected source: {source}"
                status['detected_via'] = 'chrony_sources (PPS indicator)'
                return status  # Found a likely GPS/PPS source

            # Check for GPS indicators in name/refid
            # Check for /dev/ paths often used for serial GPS
            if 'GPS' in name_ip or 'GPS' in refid or '/DEV/' in name_ip:
                status['status'] = "Potential GPS/Serial source detected in Chrony."
                status['details'] = f"Detected source: {source}"
                status['detected_via'] = 'chrony_sources (GPS/Serial indicator)'
                # Don't return yet, a PPS source is a stronger indicator of precise GPS sync

    # Check NTPd peers output
    ntpq_peers = sync_status_info.get('ntpq_-p')
    if ntpq_peers and ntpq_peers.get('peers'):
        for peer in ntpq_peers['peers']:
            # Look for common indicators of GPS/PPS sources in ntpq output
            remote = peer.get('remote', '').upper()
            refid = peer.get('refid', '').upper()
            # The sync state flag (*, +, #, etc.)
            sync_state_flag = remote[0] if remote else ''

            # Check for PPS indicators
            # .GPS. is common refid for NTP GPS driver
            if 'PPS' in remote or 'PPS' in refid or (refid == '.GPS.' and sync_state_flag == '*'):
                status['status'] = "Potential GPS/PPS source detected in NTPd."
                status['details'] = f"Detected peer: {peer}"
                status['detected_via'] = 'ntpq -p (PPS indicator)'
                return status  # Found a likely GPS/PPS source

            # Check for GPS indicators
            if 'GPS' in remote or 'GPS' in refid:
                status['status'] = "Potential GPS source detected in NTPd."
                status['details'] = f"Detected peer: {peer}"
                status['detected_via'] = 'ntpq -p (GPS indicator)'
                # Don't return yet, PPS is stronger

    # If neither Chrony nor NTPd show GPS/PPS sources
    status['status'] = "No obvious GPS/PPS source detected via NTP/Chrony status."
    status[
        'note'] = "This check relies on NTP/Chrony being configured with a GPS/PPS source and reporting it in their status outputs ('chronyc sources', 'ntpq -p'). Direct PPS signal status or serial port reading requires more specific tools/configuration."

    return status


def get_time_sync_status() -> Dict[str, Any]:
    """
    Retrieves comprehensive time synchronization status on Linux.
    Includes checks for NTP/Chrony/PTP, System RTC, and potential GPS sync sources.
    """
    status: Dict[str, Any] = {
        "overall_status": "Checking...",
        "ntp_chrony_ptp": {},
        "system_rtc": {},
        "gps_sync_source": {}
    }

    # 1. Check NTP/Chrony/PTP status
    status["ntp_chrony_ptp"] = _check_ntp_chrony_ptp()

    # 2. Check System RTC status
    status["system_rtc"] = _check_system_rtc()

    # 3. Check GPS time sync source (based on NTP/Chrony reporting)
    # Pass the results from NTP/Chrony check to potentially find GPS source details
    status["gps_sync_source"] = _check_gps_sync_status(
        status["ntp_chrony_ptp"])

    # Determine overall status based on timedatectl
    tdctl_info = status["ntp_chrony_ptp"].get('timedatectl', {})
    ntp_sync = tdctl_info.get('SystemNTPSynchronized',
                              tdctl_info.get('NTP synchronized (status)'))
    clock_sync = tdctl_info.get('SystemClockSynchronized', tdctl_info.get(
        'System clock synchronized (status)'))

    if ntp_sync is True:
        status["overall_status"] = "Time is synchronized via NTP/NTP-like service."
    elif clock_sync is True:
        # This might happen if manually synced or using another method timedatectl recognizes
        status["overall_status"] = "System clock is synchronized (method may vary)."
    elif ntp_sync is False or clock_sync is False:
        status["overall_status"] = "Time synchronization is NOT active or NOT synchronized."
    else:
        status["overall_status"] = "Could not determine overall synchronization status from timedatectl."

    return status


if __name__ == "__main__":
    print("--- Time Synchronization Status (Linux Only) ---")
    sync_status = get_time_sync_status()

    # Pretty print the results
    import json
    print(json.dumps(sync_status, indent=4))

    print("\n--- Summary ---")
    print(f"Overall Status: {sync_status.get('overall_status')}")

    tdctl = sync_status.get('ntp_chrony_ptp', {}).get('timedatectl', {})
    print(
        f"NTP enabled (timedatectl): {tdctl.get('NTP enabled', tdctl.get('NTP enabled (status)', 'N/A'))}")
    print(
        f"NTP synchronized (timedatectl): {tdctl.get('SystemNTPSynchronized', tdctl.get('NTP synchronized (status)', 'N/A'))}")
    print(
        f"System clock synchronized (timedatectl): {tdctl.get('SystemClockSynchronized', tdctl.get('System clock synchronized (status)', 'N/A'))}")
    print(
        f"NTP service (timedatectl): {tdctl.get('NTPService', tdctl.get('NTP service (status)', 'N/A'))}")

    chrony_trk = sync_status.get(
        'ntp_chrony_ptp', {}).get('chrony_tracking', {})
    if chrony_trk.get('status') != "chronyc tracking command failed or not available (Is Chrony running?)":
        print(f"\nChrony Tracking Status: {chrony_trk.get('status', 'N/A')}")
        print(f"Chrony Synchronized: {chrony_trk.get('synchronized', 'N/A')}")
        if chrony_trk.get('Reference ID'):
            print(f"Chrony Reference ID: {chrony_trk.get('Reference ID')}")
            print(f"Chrony Stratum: {chrony_trk.get('Stratum')}")
            print(f"Chrony Last Offset: {chrony_trk.get('Last offset')}")

    ntpq_p = sync_status.get('ntp_chrony_ptp', {}).get('ntpq_-p', {})
    if ntpq_p.get('status') != "ntpq -p command failed or not available (Is NTPd running?)":
        print(f"\nNTPq Peer Status: {ntpq_p.get('status', 'N/A')}")
        if ntpq_p.get('peers'):
            print(f"NTP Peers ({len(ntpq_p['peers'])} found):")
            for peer in ntpq_p['peers'][:5]:  # Print first 5 peers
                print(f"  {peer.get('remote')} (refid: {peer.get('refid')}, st: {peer.get('st')}, reach: {peer.get('reach')}, offset: {peer.get('offset')})")
            if len(ntpq_p['peers']) > 5:
                print("  ...")
        else:
            print("  (No NTP peers listed)")

    ptp_proc = sync_status.get('ntp_chrony_ptp', {}).get('ptp4l_process', {})
    print(f"\nptp4l Process Running: {ptp_proc.get('running', 'N/A')}")
    if ptp_proc.get('status'):
        print(f"ptp4l Process Status Details: {ptp_proc.get('status')}")
    if ptp_proc.get('note'):
        print(f"ptp4l Process Note: {ptp_proc.get('note')}")

    rtc_status = sync_status.get('system_rtc', {})
    print(
        f"\nSystem RTC Status: {rtc_status.get('timedatectl',{}).get('status', 'N/A')}")
    print(
        f"RTC in local time: {rtc_status.get('timedatectl',{}).get('rtc_local_time', 'N/A')}")
    print(
        f"HWClock Time (raw): {rtc_status.get('hwclock',{}).get('time_raw', 'N/A')}")

    gps_sync = sync_status.get('gps_sync_source', {})
    print(f"\nGPS Sync Source Status: {gps_sync.get('status', 'N/A')}")
    if gps_sync.get('details'):
        print(f"GPS Sync Details: {gps_sync.get('details')}")
    if gps_sync.get('detected_via'):
        print(f"GPS Sync Detected Via: {gps_sync.get('detected_via')}")
    if gps_sync.get('note'):
        print(f"GPS Sync Note: {gps_sync.get('note')}")

    print("-" * 30)
