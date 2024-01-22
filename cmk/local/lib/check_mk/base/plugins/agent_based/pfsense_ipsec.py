# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Checkmk special agent for pfSense - Fyotta (https://github.com/Fyotta/checkmk-pfsense-agent)
# This code is distributed under the terms of the GNU General Public License, version 3 (GPLv3).
# See the LICENSE file for details on the license terms.
from .agent_based_api.v1 import *
from typing import List
import json

def join_section(section: List[List[str]]) -> str:
    return '\n'.join([' '.join(line) for line in section])

def serialize_section(section: List[List[str]]):
    json_str = join_section(section)
    return json.loads(json_str)

def discover_plugin(section):
    phase1_list = serialize_section(section)
    for phase1_item in phase1_list:
        desc = phase1_item['description']
        yield Service(item=desc)

def check_plugin(item, params, section):
    phase1_list = serialize_section(section)
    ph2_min = params['ph2_min']
    for phase1_item in phase1_list:
        if phase1_item['description'] == item:
            if phase1_item['state'] != 'connected':
                state = State.CRIT
                summary = f"Phase 1: Disconnected"
            elif phase1_item['ph2_connected'] < ph2_min:
                state = State.CRIT
                summary = f"Phase 1: OK, Phase 2: {phase1_item['ph2_connected']} out of {ph2_min}"
            else:
                state = State.OK
                ph2_summary = ["Phase 2 (%s): %s" % (ph2_item['description'], ph2_item['state']) for ph2_item in phase1_item['ph2']]
                summary = f"Phase 1: OK, Phase 2: {phase1_item['ph2_connected']} out of {ph2_min}, details: {' '.join(ph2_summary)}"
                if phase1_item['ph2_connected'] > 0:
                    total_bytes_in = sum(int(ph2_item['stats']['bytes_in']) for ph2_item in phase1_item['ph2'])
                    total_packets_in = sum(int(ph2_item['stats']['packets_in']) for ph2_item in phase1_item['ph2'])
                    total_bytes_out = sum(int(ph2_item['stats']['bytes_out']) for ph2_item in phase1_item['ph2'])
                    total_packets_out = sum(int(ph2_item['stats']['packets_out']) for ph2_item in phase1_item['ph2'])
                    yield Metric("total_bytes_in", total_bytes_in)
                    yield Metric("total_packets_in", total_packets_in)
                    yield Metric("total_bytes_out", total_bytes_out)
                    yield Metric("total_packets_out", total_packets_out)
            yield Result(state = state, summary = summary)
            return

register.check_plugin(
    name = "pfsense_ipsec",
    service_name = "pfSense VPN IPSec Tunnel %s",
    discovery_function = discover_plugin,
    check_function = check_plugin,
    check_default_parameters={"ph2_min": 1},
    check_ruleset_name="pfsense_ipsec"
)
