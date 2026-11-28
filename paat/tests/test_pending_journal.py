# SPDX-License-Identifier: Apache-2.0
"""pending_changes(): system-generated candidate changes (no journal entries) do not block a push; admin changes do."""
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from panlab.pusher import XapiDevice, journal_has_admin_changes

YES = "<result>yes</result>"
NO = "<result>no</result>"
EMPTY_JOURNAL = "<result></result>"
ADMIN_JOURNAL = ("<result><journal><entry><xpath>/config/devices/entry[@name='localhost.localdomain']/device-group/"
                 "entry[@name='DG-EXAMPLE']/tag/entry[@name='T1']</xpath><owner>admin2</owner><action> CREATE</action>"
                 "</entry></journal></result>")


class FakeXapi:
    def __init__(self, answers, fail_journal=False):
        self.answers, self.fail_journal, self.element_result, self.calls = answers, fail_journal, None, []

    def op(self, cmd):
        self.calls.append(cmd)
        if "list><changes" in cmd and self.fail_journal:
            raise RuntimeError("Unknown command")
        key = "journal" if "list><changes" in cmd else "check"
        self.element_result = ET.fromstring(self.answers[key])


def dev(check, journal=EMPTY_JOURNAL, fail=False):
    x = FakeXapi({"check": check, "journal": journal}, fail_journal=fail)
    return XapiDevice(SimpleNamespace(xapi=x)), x


def test_no_pending_does_not_read_journal():
    d, x = dev(NO)
    assert d.pending_changes() is False
    assert len(x.calls) == 1


def test_system_generated_only_is_not_pending():
    d, _ = dev(YES, EMPTY_JOURNAL)
    assert d.pending_changes() is False


def test_admin_change_is_pending():
    d, _ = dev(YES, ADMIN_JOURNAL)
    assert d.pending_changes() is True


def test_unreadable_journal_stays_conservative():
    d, _ = dev(YES, fail=True)
    assert d.pending_changes() is True


def test_journal_helper():
    assert journal_has_admin_changes(None) is True
    assert journal_has_admin_changes(ET.fromstring(EMPTY_JOURNAL)) is False
    assert journal_has_admin_changes(ET.fromstring(ADMIN_JOURNAL)) is True
