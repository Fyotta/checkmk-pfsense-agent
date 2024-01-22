# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Checkmk special agent for pfSense - Fyotta (https://github.com/Fyotta/checkmk-pfsense-agent)
# This code is distributed under the terms of the GNU General Public License, version 3 (GPLv3).
# See the LICENSE file for details on the license terms.
from cmk.gui.plugins.wato.utils import IndividualOrStoredPassword
from cmk.gui.valuespec import (
    Dictionary,
    Integer,
    TextAscii,
    DropdownChoice,
    FixedValue
)

from cmk.gui.plugins.wato import (
    HostRulespec,
    rulespec_registry,
)

from cmk.gui.i18n import _
from cmk.gui.plugins.wato.datasource_programs import RulespecGroupVMCloudContainer

def _valuespec_special_agents_pfsense():
    return Dictionary(
        title=_("pfSense"),
        elements=[
            (
                "user",
                TextAscii(
                    title=_("User"),
                    allow_empty=False
                ),
            ),
            (
                "secret",
                IndividualOrStoredPassword(
                    title=_("Password"),
                    allow_empty=False
                ),
            ),
            (
                "port",
                Integer(
                    title=_("TCP Port"),
                    default_value=443
                ),
            ),
            (
                "timeout",
                Integer(
                    title=_("Timeout"),
                    default_value=5
                ),
            ),
            (
                'protocol',
                DropdownChoice(
                    title=_('Protocol'),
                    choices=[
                        ('http', 'HTTP'),
                        ('https', 'HTTPS'),
                    ],
                    default_value='https',
                ),
            ),
            (
                'ignore-ssl-errors',
                FixedValue(
                    value=True,
                    totext='',
                    title=_('Ignore SSL errors'),
                ),
            ),
        ],
        required_keys=['user', 'secret']
    )

rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupVMCloudContainer,
        name="special_agents:pfsense",
        valuespec=_valuespec_special_agents_pfsense,
    )
)
