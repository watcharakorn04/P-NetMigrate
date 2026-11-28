"""2-tuple port numbering advisory (Cisco -> Huawei only, one deduplicated warning per conversion)."""

from __future__ import annotations

from app.core.renderers.common import WARN_TWO_TUPLE_PORTS
from app.i18n import translate_message
from tests.helpers import c2h, h2c

TWO_TUPLE_MANY = """\
hostname SW1
interface GigabitEthernet0/1
 description uplink
interface GigabitEthernet0/2
 switchport mode access
interface FastEthernet0/3
 shutdown
"""


def test_two_tuple_interfaces_emit_single_warning():
    result = c2h(TWO_TUPLE_MANY)
    assert result.warnings.count(WARN_TWO_TUPLE_PORTS) == 1


def test_two_tuple_port_numbers_still_preserved():
    text = c2h(TWO_TUPLE_MANY).annotated_text
    assert "GigabitEthernet0/1" in text and "0/0/1" not in text


def test_two_tuple_interface_range_triggers_warning():
    result = c2h("interface range GigabitEthernet0/1 - 4\n switchport mode access\n")
    assert result.warnings.count(WARN_TWO_TUPLE_PORTS) == 1


def test_two_tuple_subinterface_triggers_warning():
    result = c2h("interface GigabitEthernet0/1.100\n ip address 10.0.0.1 255.255.255.0\n")
    assert result.warnings.count(WARN_TWO_TUPLE_PORTS) == 1


def test_three_tuple_interfaces_do_not_trigger_warning():
    result = c2h(
        "interface GigabitEthernet0/0/1\n description a\n"
        "interface GigabitEthernet1/0/2\n shutdown\n"
    )
    assert WARN_TWO_TUPLE_PORTS not in result.warnings


def test_virtual_interfaces_do_not_trigger_warning():
    result = c2h("interface Loopback0\n ip address 1.1.1.1 255.255.255.255\ninterface Vlan10\n shutdown\n")
    assert WARN_TWO_TUPLE_PORTS not in result.warnings


def test_mixed_two_and_three_tuple_emit_one_warning():
    result = c2h("interface GigabitEthernet0/0/1\n shutdown\ninterface GigabitEthernet0/1\n shutdown\n")
    assert result.warnings.count(WARN_TWO_TUPLE_PORTS) == 1


def test_huawei_to_cisco_does_not_emit_warning():
    result = h2c("interface GigabitEthernet0/1\n shutdown\n#\nreturn\n")
    assert WARN_TWO_TUPLE_PORTS not in result.warnings


def test_warning_has_thai_and_english_text():
    assert translate_message(WARN_TWO_TUPLE_PORTS, "th") == WARN_TWO_TUPLE_PORTS
    en = translate_message(WARN_TWO_TUPLE_PORTS, "en")
    assert en.startswith("2-tuple interface numbering (e.g., 0/1) was preserved from the source")
    assert en.endswith("adjust to 0/0/1 before applying.")
