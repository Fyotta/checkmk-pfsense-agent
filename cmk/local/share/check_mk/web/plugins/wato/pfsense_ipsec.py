# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Checkmk special agent for pfSense - Fyotta (https://github.com/Fyotta/checkmk-pfsense-agent)
# This code is distributed under the terms of the GNU General Public License, version 3 (GPLv3).
# See the LICENSE file for details on the license terms.
from cmk.gui.i18n import _

from cmk.gui.valuespec import (
    Dictionary,
    Integer,
    TextInput,
)

from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithItem,
    rulespec_registry,
    RulespecGroupEnforcedServicesNetworking,
)

def _item_valuespec_pfsense_ipsec():
    return TextInput(title="Phase 1 description", help="Insert the 'description' of phase 1 here")

def _parameter_valuespec_pfsense_ipsec():
    return Dictionary(
        elements=[
            ("ph2_min", Integer(title=_("Minimum quantity of phase 2 connected"))),
        ],
    )

rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="pfsense_ipsec",
        group=RulespecGroupEnforcedServicesNetworking,
        match_type="dict",
        item_spec=_item_valuespec_pfsense_ipsec,
        parameter_valuespec=_parameter_valuespec_pfsense_ipsec,
        title=lambda: _("pfSense VPN IPSec minimum quantity of phase 2 connected"),
    ))
