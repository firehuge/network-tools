"""Plain-English explanations for PAN-OS API errors and update-server messages."""

from __future__ import annotations

import re

FRIENDLY = [
    (re.compile(r"(not found or not registered|device is not found|no valid (support|license)|support license|not licensed|license.*(expired|invalid)|"
                r"failed to (check|download).*licen|valid.*support)", re.I),
     "This device is not registered or has no valid support license with Palo Alto Networks, so it cannot download "
     "software or content. Register it and activate support (Customer Support Portal > Assets), then run the check again."),
    (re.compile(r"(failed to connect|unable to connect|could not resolve|name resolution|timed? ?out).*"
                r"(update|server|paloalto)", re.I),
     "The device could not reach the Palo Alto Networks update server. Check its DNS, default gateway and that "
     "updates.paloaltonetworks.com is allowed out."),
    (re.compile(r"content version of .*(or greater|minimum)|requires a content version", re.I),
     "The installed Apps/Threats content is too old for this PAN-OS version. Run the content step first, then retry."),
    (re.compile(r"(disk space|no space|insufficient space)", re.I),
     "Not enough disk space. Delete old software images (Device > Software) and retry."),
    (re.compile(r"(base image|must download.*base)", re.I),
     "The base image of this feature release must be downloaded first; the plan adds that step."),
    (re.compile(r"(another .* in progress|is currently running|pending jobs|job.*in progress)", re.I),
     "Another job is running on the device. Wait for it to finish (Tasks / show jobs all) and retry."),
    (re.compile(r"(invalid credential|invalid api key|403|unauthori)", re.I),
     "The API key was rejected. Generate a new key for the panlab-api user and update the customer env file."),
]


def friendly(msg: str) -> str:
    for rx, text in FRIENDLY:
        if rx.search(msg or ""):
            return text
    return ""


