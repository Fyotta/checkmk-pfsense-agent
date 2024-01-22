# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Checkmk special agent for pfSense - Fyotta (https://github.com/Fyotta/checkmk-pfsense-agent)
# This code is distributed under the terms of the GNU General Public License, version 3 (GPLv3).
# See the LICENSE file for details on the license terms.
from cmk.gui.i18n import _l
from cmk.gui.plugins.metrics.utils import graph_info, indexed_color, metric_info

metric_info["total_bytes_in"] = {
    "title": _("Total Bytes In"),
    "unit": "bytes",
    "color": "#80ff40"
}
metric_info["total_bytes_out"] = {
    "title": _("Total Bytes Out"),
    "unit": "bytes",
    "color": "#ff0000"
}
metric_info["total_packets_in"] = {
    "title": _("Total Packets In"),
    "unit": "count",
    "color": "#80ff40"
}
metric_info["total_packets_out"] = {
    "title": _("Total Packets Out"),
    "unit": "count",
    "color": "#ff0000"
}
graph_info["bandwidth"] = {
    "title": _("Bandwidth"),
    "metrics": [
        ("total_bytes_in", "area"),
        ("total_bytes_out", "-area"),
    ],
}
graph_info["packets"] = {
    "title": _("Packets"),
    "metrics": [
        ("total_packets_in", "line"),
        ("total_packets_out", "-line"),
    ],
}
