# SPDX-License-Identifier: Apache-2.0
"""URL filter self-service: requesters ask for URL Filtering changes, approvers review and push.

One URL Filtering profile per customer, in that customer's device group (Panorama) or vsys
(standalone firewall), plus two optional custom URL categories (an allow list and a block list).
The customer profile opts in with a ``url_filter:`` block::

    url_filter:
      target: pano-1              # Panorama or firewall target in this profile
      device_group: DG-EXAMPLE    # Panorama only (vsys: vsys1 for a firewall)
      profile: URL-example      # default URL-<customer>
      allow_category: URL-example-ALLOW   # default <profile>-ALLOW
      block_category: URL-example-BLOCK   # default <profile>-BLOCK
      verify_targets: [fw-1]  # firewalls to read back after a Panorama push (optional)
      allow_self_approval: false  # a requester may not approve their own request (default)

Flow: ``read_live`` (categories from the device's predefined list, current actions from the live
profile) -> ``create_request`` (only real changes are stored, with a hash of the live state) ->
``approve`` (re-reads live; refuses and marks the request **stale** if the live profile changed;
builds the API operations, the rollback operations and a CR change plan) -> ``push`` (live only where
the existing rule allows it: a standalone firewall, or Panorama with ``allow_live_panorama_push``;
everything else stays dry-run with the plan for a manual change) -> commit, push the device group,
read back and verify. ``rollback`` restores the snapshot taken at approval. Every step is written to
the request's history and to the customer audit log. Attaching the profile to security rules (via
a security profile group) is the administrators' job; ``attachment`` reports whether it is used.

Recommended actions follow Palo Alto Networks' public best-practice guidance (block the known-
malicious and threat-adjacent categories, alert on the rest); sources are in the user manual.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from panlab.customers import Profile

TZ = ZoneInfo("America/Chicago")
ACTIONS = ("allow", "alert", "continue", "override", "block")
STATUSES = ("pending", "stale", "approved", "rejected", "pushing", "pushed", "failed", "rolling-back", "rolled-back")
REQ_RE = re.compile(r"^url-\d{8}-\d{6}-[0-9a-f]{6}$")
DG_XP = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']"
VSYS_XP = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
MAX_URLS = 200
JOB_TIMEOUT = 900  # seconds to wait for a commit / commit-all job
POLL_SECONDS = 5

# Palo Alto Networks best practice (Internet gateway URL Filtering profile): block these 11, alert on the rest.
# ransomware is a newer category in the same "known threats" class. Sources: docs/user-manual/url-filtering.md.
PA_BLOCK = frozenset({"command-and-control", "copyright-infringement", "dynamic-dns", "extremism", "malware", "phishing",
                      "proxy-avoidance-and-anonymizers", "unknown", "newly-registered-domain", "grayware", "parked",
                      "ransomware"})
# Categories Palo Alto says to weigh against your own legal / compliance policy (recommendation stays alert).
CONSIDER = frozenset({"hacking", "compromised-website", "scanning-activity", "abused-drugs", "adult", "gambling",
                      "peer-to-peer", "questionable", "weapons", "insufficient-content", "not-resolved", "encrypted-dns"})
GROUP_ORDER = ("Palo Alto recommends block", "Consider blocking (your policy)", "Potential threats", "Legal and policy risk",
               "Artificial intelligence", "Risk ratings", "Everyday sites", "Other")

# (id, display name, content group, plain-language description). The live device decides which categories exist.
CATALOG: list[tuple[str, str, str, str]] = [
    ("command-and-control", "Command and Control", "Known threats", "Domains malware uses to talk to an attacker's server or steal data."),
    ("compromised-website", "Compromised Website", "Known threats", "Normal sites that were hacked and now host malware or bad scripts."),
    ("grayware", "Grayware", "Known threats", "Not always a virus, but pushy or unwanted: adware, hijackers, clickjacking, embedded miners."),
    ("malware", "Malware", "Known threats", "Sites known to host viruses, trojans, malicious scripts or code."),
    ("phishing", "Phishing", "Known threats", "Sites that try to steal passwords, cards, or other personal information."),
    ("ransomware", "Ransomware", "Known threats", "Sites tied to ransomware campaigns or tools that lock or steal data."),
    ("scanning-activity", "Scanning Activity", "Known threats", "Hosts probing networks for weaknesses. Advanced URL Filtering only."),
    ("copyright-infringement", "Copyright Infringement", "Potential threats", "Sites that offer illegal downloads of software or other copyrighted material."),
    ("dynamic-dns", "Dynamic DNS", "Potential threats", "Services that map changing IPs to names. Attackers use this a lot."),
    ("encrypted-dns", "Encrypted DNS", "Potential threats", "DNS-over-HTTPS style resolvers that can hide what sites users look up."),
    ("hacking", "Hacking", "Potential threats", "How-to content for breaking into systems or bypassing licenses. Make exceptions for your own testers if needed."),
    ("insufficient-content", "Insufficient Content", "Potential threats", "Empty pages, test pages, or APIs with nothing useful to show a person."),
    ("newly-registered-domain", "Newly Registered Domains", "Potential threats", "Domains registered in the last 32 days. Often used in attacks."),
    ("not-resolved", "Not-Resolved", "Potential threats", "Firewall could not look the site up in the URL database or the cloud."),
    ("parked", "Parked", "Potential threats", "Placeholder pages or domains for sale. Little real content."),
    ("proxy-avoidance-and-anonymizers", "Proxy Avoidance and Anonymizers", "Potential threats", "Tools that hide browsing and bypass your filters."),
    ("unknown", "Unknown", "Potential threats", "Palo Alto has not classified the site yet."),
    ("browser-runtime-attack", "Browser Runtime Attack", "Potential threats", "Page found malicious while it was rendering in the browser."),
    ("real-time-detection", "Real-time Detection", "Potential threats", "Caught by live inline analysis. Advanced URL Filtering only."),
    ("private-ip-addresses", "Private IP Addresses", "Potential threats", "RFC 1918 private addresses and local names (.local, .onion). Internal sites land here."),
    ("abused-drugs", "Abused Drugs", "Legal and policy risk", "Promotes abuse of legal or illegal drugs, or selling drug gear."),
    ("adult", "Adult", "Legal and policy risk", "Sexually explicit material or adult services."),
    ("alcohol-and-tobacco", "Alcohol and Tobacco", "Legal and policy risk", "Sale or use of alcohol, tobacco, or e-cigarettes."),
    ("cryptocurrency", "Cryptocurrency", "Legal and policy risk", "Crypto coins, exchanges, wallets, and mining sites (not embedded miners)."),
    ("extremism", "Extremism", "Legal and policy risk", "Terrorism, racism, or other content that targets people by group."),
    ("gambling", "Gambling", "Legal and policy risk", "Real or virtual-money betting, odds, and gambling how-tos."),
    ("marijuana", "Marijuana", "Legal and policy risk", "Use, sale, or growing of marijuana, including paraphernalia."),
    ("peer-to-peer", "Peer-to-peer", "Legal and policy risk", "BitTorrent and similar file-sharing clients and sites."),
    ("questionable", "Questionable", "Legal and policy risk", "Tasteless or offensive content aimed at a group of people."),
    ("weapons", "Weapons", "Legal and policy risk", "Sale or how-to content for weapons and armor."),
    ("artificial-intelligence", "Artificial Intelligence (parent)", "Artificial intelligence", "Older parent bucket. New AI sites go into the AI subcategories below."),
    ("ai-code-assistant", "AI Code Assistant", "Artificial intelligence", "AI that writes, completes, or fixes code."),
    ("ai-conversational-assistant", "AI Conversational Assistant", "Artificial intelligence", "ChatGPT-style assistants that take text or files and talk back."),
    ("ai-data-and-workflow-optimizer", "AI Data and Workflow Optimizer", "Artificial intelligence", "AI that cleans data or automates office workflows."),
    ("ai-meeting-assistant", "AI Meeting Assistant", "Artificial intelligence", "AI that summarizes meetings and makes action lists."),
    ("ai-media-service", "AI Media Service", "Artificial intelligence", "AI that makes or edits images, voice, music, or video. Adult AI media is Adult, not this."),
    ("ai-platform-service", "AI Platform Service", "Artificial intelligence", "Platforms to build, train, and host GenAI apps."),
    ("ai-website-generator", "AI Website Generator", "Artificial intelligence", "AI that builds websites from a prompt."),
    ("ai-writing-assistant", "AI Writing Assistant", "Artificial intelligence", "AI that writes marketing, school, or other text. Translation is its own category."),
    ("abortion", "Abortion", "Everyday sites", "Information, advocacy, procedures, or support for or against abortion."),
    ("auctions", "Auctions", "Everyday sites", "Person-to-person sale sites. Charity auctions are Society."),
    ("business-and-economy", "Business and Economy", "Everyday sites", "Marketing, running a business, shipping, ISPs, general corporate content."),
    ("computer-and-internet-info", "Computer and Internet Info", "Everyday sites", "Computer science, hardware, software, security, and programming info."),
    ("content-delivery-networks", "Content Delivery Networks", "Everyday sites", "CDN hosts that deliver ads, files, images, or media for other sites."),
    ("dating", "Dating", "Everyday sites", "Dating services and personal ads. Sexual chat rooms are Adult."),
    ("educational-institutions", "Educational Institutions", "Everyday sites", "Schools, colleges, districts, and established tutoring academies."),
    ("entertainment-and-arts", "Entertainment and Arts", "Everyday sites", "Movies, TV, comics, museums, celebrity and entertainment news."),
    ("file-converter", "File Converter", "Everyday sites", "Convert, compress, or change documents, images, audio, or video."),
    ("financial-services", "Financial Services", "Everyday sites", "Banking, loans, credit cards, insurance. Not stock trading."),
    ("games", "Games", "Everyday sites", "Online or downloadable games, cheats, and game news."),
    ("government", "Government", "Everyday sites", "Official local, state, and national government sites."),
    ("health-and-medicine", "Health and Medicine", "Everyday sites", "Health info, clinics, gyms, medical insurance, cosmetic surgery."),
    ("home-and-garden", "Home and Garden", "Everyday sites", "Home repair, design, construction, decor, gardening."),
    ("hunting-and-fishing", "Hunting and Fishing", "Everyday sites", "Tips and gear. Firearm sales are Weapons."),
    ("internet-communications-and-telephony", "Internet Communications and Telephony", "Everyday sites", "Video chat, instant messaging, and phone-over-internet services."),
    ("internet-portals", "Internet Portals", "Everyday sites", "Start pages that collect many topics in one place."),
    ("job-search", "Job Search", "Everyday sites", "Job listings, employer reviews, and interview tips."),
    ("legal", "Legal", "Everyday sites", "Law, legal advice, and law firm sites."),
    ("military", "Military", "Everyday sites", "Military branches, recruitment, operations, veteran groups."),
    ("motor-vehicles", "Motor Vehicles", "Everyday sites", "Cars, bikes, boats, trucks, RVs - reviews, sales, parts."),
    ("music", "Music", "Everyday sites", "Artists, lyrics, labels. Not streaming music services."),
    ("news", "News", "Everyday sites", "Newspapers, radio, magazines, podcasts, current events."),
    ("nudity", "Nudity", "Everyday sites", "Nude or seminude images, including art and naturist sites."),
    ("online-storage-and-backup", "Online Storage and Backup", "Everyday sites", "Cloud file storage and photo sharing."),
    ("personal-sites-and-blogs", "Personal Sites and Blogs", "Everyday sites", "Personal websites and blogs."),
    ("philosophy-and-political-advocacy", "Philosophy and Political Advocacy", "Everyday sites", "Political or philosophical views and campaigns."),
    ("real-estate", "Real Estate", "Everyday sites", "Rentals, sales, agents, listings. Mortgages are Financial Services."),
    ("recreation-and-hobbies", "Recreation and Hobbies", "Everyday sites", "Hobby forums and clubs. Stores that sell hobby gear are Shopping."),
    ("reference-and-research", "Reference and Research", "Everyday sites", "Dictionaries, maps, libraries, census, science references."),
    ("religion", "Religion", "Everyday sites", "Faith groups, worship, fortune-telling. Religious schools are Education."),
    ("remote-access", "Remote Access", "Everyday sites", "Tools for approved remote access to a computer or network."),
    ("search-engines", "Search Engines", "Everyday sites", "Keyword search that returns sites, images, or files."),
    ("sex-education", "Sex Education", "Everyday sites", "Reproduction, safe sex, STDs, birth control."),
    ("shareware-and-freeware", "Shareware and Freeware", "Everyday sites", "Free software, icons, wallpapers. Not GitHub-style dev platforms."),
    ("shopping", "Shopping", "Everyday sites", "Online stores and price-comparison shopping."),
    ("social-networking", "Social Networking", "Everyday sites", "Communities where people post and talk in groups."),
    ("society", "Society", "Everyday sites", "Fashion, beauty, charities, restaurants, general-interest society topics."),
    ("sports", "Sports", "Everyday sites", "Teams, scores, fantasy sports. Sporting-goods stores are Shopping."),
    ("stock-advice-and-tools", "Stock Advice and Tools", "Everyday sites", "Markets, trading, portfolios, quotes."),
    ("streaming-media", "Streaming Media", "Everyday sites", "Streaming audio or video, online radio, podcast archives."),
    ("swimsuits-and-intimate-apparel", "Swimsuits and Intimate Apparel", "Everyday sites", "Swimwear and intimate clothing sites."),
    ("training-and-tools", "Training and Tools", "Everyday sites", "Online training and workplace learning."),
    ("translation", "Translation", "Everyday sites", "Translate text or whole web pages. Can be used to dodge filters."),
    ("travel", "Travel", "Everyday sites", "Hotels, airlines, tourism, rentals. Online casino play is Gambling."),
    ("web-advertisements", "Web Advertisements", "Everyday sites", "Ad networks, banners, subscribe/unsubscribe ad pages."),
    ("web-based-email", "Web-based Email", "Everyday sites", "Web inboxes used to send and receive mail."),
    ("web-hosting", "Web Hosting", "Everyday sites", "Paid or free web hosting and site-building help."),
    ("high-risk", "High Risk", "Risk ratings", "Sites with weak reputation or past malware/phishing/C2. Stay here at least 30 days."),
    ("medium-risk", "Medium Risk", "Risk ratings", "Former bad sites that have been clean 30+ days, plus most cloud storage."),
    ("low-risk", "Low Risk", "Risk ratings", "Sites that have looked safe for at least 90 days."),
]
_CAT = {c[0].lower(): c for c in CATALOG}  # devices spell some ids differently (AI-code-assistant)


class UrlFilterError(RuntimeError):
    pass


class StaleError(UrlFilterError):
    pass


def now() -> datetime:
    return datetime.now(TZ)


def _x(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _q(name: str) -> str:
    if not name or "'" in name or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,63}", name):
        raise UrlFilterError(f"name {name!r} is not a safe PAN-OS object name")
    return name


# ---------------------------------------------------------------- config

@dataclass
class Config:
    target: str
    backend: str  # panorama | firewall
    device_group: str = ""
    vsys: str = "vsys1"
    profile: str = ""
    allow_category: str = ""
    block_category: str = ""
    verify_targets: list[str] = field(default_factory=list)
    allow_self_approval: bool = False

    @property
    def base(self) -> str:
        return DG_XP.format(dg=_q(self.device_group)) if self.backend == "panorama" else VSYS_XP.format(vsys=_q(self.vsys))

    @property
    def where(self) -> str:
        return f"device group {self.device_group}" if self.backend == "panorama" else f"vsys {self.vsys}"

    def profile_xpath(self) -> str:
        return f"{self.base}/profiles/url-filtering/entry[@name='{_q(self.profile)}']"

    def custom_xpath(self, name: str) -> str:
        return f"{self.base}/profiles/custom-url-category/entry[@name='{_q(name)}']"


def config_for(profile: Profile) -> Config | None:
    """The customer's URL filter self-service settings, or None when the customer has not opted in."""
    raw = getattr(profile, "url_filter", None) or {}
    if not isinstance(raw, dict) or not raw.get("target") or raw.get("enabled") is False:
        return None
    tgt = [t for t in profile.targets if t.name == raw["target"]]
    if len(tgt) != 1:
        raise UrlFilterError(f"url_filter.target {raw['target']!r} is not a target of {profile.name}")
    backend = tgt[0].type
    if backend == "panorama" and not raw.get("device_group"):
        raise UrlFilterError("url_filter.device_group is required for a Panorama target")
    prof = str(raw.get("profile") or f"URL-{profile.name}")
    cfg = Config(target=tgt[0].name, backend=backend, device_group=str(raw.get("device_group") or ""),
                 vsys=str(raw.get("vsys") or (tgt[0].vsys[0] if tgt[0].vsys else "vsys1")), profile=prof,
                 allow_category=str(raw.get("allow_category") or f"{prof}-ALLOW"),
                 block_category=str(raw.get("block_category") or f"{prof}-BLOCK"),
                 verify_targets=[str(v) for v in raw.get("verify_targets") or []],
                 allow_self_approval=bool(raw.get("allow_self_approval", False)))
    for n in (cfg.profile, cfg.allow_category, cfg.block_category):
        _q(n)
    for v in cfg.verify_targets:
        if not any(t.name == v and t.type == "firewall" for t in profile.targets):
            raise UrlFilterError(f"url_filter.verify_targets: {v!r} is not a firewall target of {profile.name}")
    return cfg


def live_allowed(profile: Profile, cfg: Config) -> bool:
    """Same rule as the push area: a standalone firewall may be pushed live; Panorama only with the explicit opt-in."""
    from panlab.pusher import live_panorama_push_allowed

    return cfg.backend == "firewall" or live_panorama_push_allowed(profile)


# ---------------------------------------------------------------- device access

class UrlDevice(Protocol):
    def show(self, xpath: str) -> ET.Element | None: ...          # running config node (the entry itself) or None
    def predefined_categories(self) -> list[str]: ...
    def edit(self, xpath: str, element: str) -> None: ...
    def delete(self, xpath: str) -> None: ...
    def pending_changes(self) -> bool: ...
    def revert(self) -> None: ...
    def commit(self, description: str) -> dict: ...
    def commit_all(self, cmd: str) -> dict: ...
    def pushed_policy(self) -> ET.Element | None: ...             # firewall: show config pushed-shared-policy


class XapiUrlDevice:
    """Wraps ``pusher.XapiDevice`` (pan-os-python). Credentials stay inside the Firewall object."""

    def __init__(self, dev):
        self.dev, self.x = dev, dev.fw.xapi

    def show(self, xpath: str) -> ET.Element | None:
        try:
            self.x.show(xpath=xpath)
        except Exception as exc:  # noqa: BLE001
            if "no such node" in str(exc).lower():
                return None
            raise
        res = self.x.element_result
        kids = list(res) if res is not None else []
        return kids[0] if kids else None

    def predefined_categories(self) -> list[str]:
        self.x.op(cmd="<show><predefined><xpath>/predefined/pan-url-categories</xpath></predefined></show>")
        res = self.x.element_result
        return [e.get("name") for e in (res.findall(".//entry") if res is not None else []) if e.get("name")]

    def edit(self, xpath: str, element: str) -> None:
        self.x.edit(xpath=xpath, element=element)

    def delete(self, xpath: str) -> None:
        self.x.delete(xpath=xpath)

    def pending_changes(self) -> bool:
        return self.dev.pending_changes()

    def revert(self) -> None:
        self.dev.revert()

    def commit(self, description: str) -> dict:
        return self._job(f"<commit><description>{_x(description)}</description></commit>", None)

    def commit_all(self, cmd: str) -> dict:
        return self._job(cmd, "all")

    def _job(self, cmd: str, action: str | None, timeout: int = JOB_TIMEOUT) -> dict:
        """Start a commit / commit-all and poll the job ourselves: a busy Panorama (another commit-all or a
        software job queued) can take longer than pan-os-python's default wait, and a job that finishes later
        must not be reported as failed."""
        import time

        self.x.commit(cmd=cmd, action=action) if action else self.x.commit(cmd=cmd)
        res = self.x.element_result
        jid = res.findtext(".//job") if res is not None else None
        if not jid:  # "There are no changes to commit" and similar
            msg = "".join(res.itertext()).strip() if res is not None else ""
            return {"jobid": None, "success": "no changes" in msg.lower(), "messages": [msg[:300]]}
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.x.op(cmd=f"<show><jobs><id>{int(jid)}</id></jobs></show>")
            j = self.x.element_result.find(".//job")
            if j is not None and (j.findtext("status") or "") == "FIN":
                msgs = [(ln.text or "").strip() for ln in j.iter("line") if (ln.text or "").strip()][:20]
                return {"jobid": int(jid), "success": (j.findtext("result") or "") == "OK", "messages": msgs}
            time.sleep(POLL_SECONDS)
        return {"jobid": int(jid), "success": False, "messages": [f"job {jid} still running after {timeout}s; check Panorama > Tasks"]}

    def pushed_policy(self) -> ET.Element | None:
        self.x.op(cmd="<show><config><pushed-shared-policy></pushed-shared-policy></config></show>")
        return self.x.element_result


def connect(profile: Profile, target: str) -> XapiUrlDevice:
    from panlab.pusher import connect_target

    return XapiUrlDevice(connect_target(profile, target))


# ---------------------------------------------------------------- live state

def _members(el: ET.Element | None, tag: str) -> list[str]:
    if el is None or el.find(tag) is None:
        return []
    return [(m.text or "").strip() for m in el.find(tag).findall("member") if (m.text or "").strip()]


def parse_profile(el: ET.Element | None) -> dict[str, str]:
    """{category: action} from a url-filtering profile entry (categories not listed are 'allow' on PAN-OS)."""
    out: dict[str, str] = {}
    for a in ACTIONS:
        for c in _members(el, a):
            out[c] = a
    return out


def read_live(dev: UrlDevice, cfg: Config) -> dict:
    """What the device has now: predefined categories, the profile's actions and the two custom lists."""
    cats = sorted(set(dev.predefined_categories()))
    pel = dev.show(cfg.profile_xpath())
    acts = parse_profile(pel)
    custom = {}
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        cel = dev.show(cfg.custom_xpath(name))
        custom[kind] = {"exists": cel is not None, "urls": sorted(_members(cel, "list"))}
    return {"categories": cats, "exists": pel is not None, "listed": sorted(acts),
            "actions": {c: acts.get(c, "allow") for c in cats},
            "custom_actions": {k: acts.get(n) for k, n in (("allow", cfg.allow_category), ("block", cfg.block_category))},
            "custom": custom, "profile_xml": ET.tostring(pel, encoding="unicode") if pel is not None else "",
            "read_at": now().isoformat(timespec="seconds")}


def state_hash(state: dict) -> str:
    key = {"exists": state["exists"], "actions": state["actions"], "custom": state["custom"],
           "custom_actions": state.get("custom_actions") or {}}
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16]


def recommended(cat: str) -> str:
    return "block" if cat.lower() in PA_BLOCK else "alert"


def risk_group(cat: str) -> str:
    c = cat.lower()
    if c in PA_BLOCK:
        return GROUP_ORDER[0]
    if c in CONSIDER:
        return GROUP_ORDER[1]
    return _CAT[c][2] if c in _CAT else "Other"


def rows(state: dict) -> list[dict]:
    """One row per live category, ordered by risk group then name."""
    out = []
    for c in state["categories"]:
        meta = _CAT.get(c.lower(), (c, c.replace("-", " ").title(), "Other", ""))
        out.append({"id": c, "name": meta[1], "desc": meta[3], "group": risk_group(c), "current": state["actions"][c],
                    "recommended": recommended(c)})
    out.sort(key=lambda r: (GROUP_ORDER.index(r["group"]) if r["group"] in GROUP_ORDER else 99, r["id"]))
    return out


# ---------------------------------------------------------------- custom URL entries

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_URL_RE = re.compile(rf"^(?:\*\.|\^\.)?{_LABEL}(?:\.{_LABEL})*(?:\.\^)?\.?(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/?-]*)?$")
_IP_RE = re.compile(r"^(\d{1,3})(?:\.(\d{1,3})){3}(?:/[A-Za-z0-9._~%/-]*)?$")


def check_url(raw: str) -> tuple[str | None, str | None]:
    """(normalized entry, None) or (None, why). PAN-OS URL list format: host[/path], optional leading *. or ^."""
    u = (raw or "").strip()
    if not u:
        return None, None
    if re.match(r"^[a-z]+://", u, re.I):
        return None, f"{u}: leave out http:// or https:// (write just the site, e.g. example.com)"
    if ":" in u.split("/", 1)[0]:
        return None, f"{u}: leave out the port"
    if any(ch.isspace() for ch in u) or len(u) > 255:
        return None, f"{u}: one entry per line, no spaces"
    host = u.split("/", 1)[0]
    if host in ("*", "^") or re.fullmatch(r"[*^]\.[A-Za-z0-9-]+\.?", host):
        return None, f"{u}: too broad (a wildcard over a whole top-level domain)"
    m = _IP_RE.match(u)
    if m:
        if any(int(o) > 255 for o in host.split(".")):
            return None, f"{u}: not a valid IP address"
        return u, None
    if not _URL_RE.match(u) or "." not in host.strip("*^."):
        return None, f"{u}: not a valid site name (example.com, *.example.com, example.com/path)"
    h, _, path = u.partition("/")
    return h.lower().rstrip(".") + (("/" + path) if path else ""), None


def parse_urls(text: str) -> tuple[list[str], list[str]]:
    good, errs = [], []
    for line in re.split(r"[\r\n,]+", text or ""):
        v, why = check_url(line)
        if why:
            errs.append(why)
        elif v and v not in good:
            good.append(v)
    return good, errs


# ---------------------------------------------------------------- requests

def _req_dir(profile: Profile) -> Path:
    return profile.data_dir("urlfilter")


def _path(profile: Profile, rid: str) -> Path:
    if not REQ_RE.match(rid or ""):
        raise UrlFilterError("bad request id")
    return _req_dir(profile) / f"{rid}.json"


def save(profile: Profile, req: dict) -> None:
    p = _path(profile, req["id"])
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(req, f, indent=2)
    os.replace(tmp, p)


def load(profile: Profile, rid: str) -> dict:
    p = _path(profile, rid)
    if not p.is_file():
        raise UrlFilterError(f"no request {rid}")
    return json.loads(p.read_text(encoding="utf-8"))


def list_requests(profile: Profile) -> list[dict]:
    out = []
    for p in sorted(_req_dir(profile).glob("url-*.json"), reverse=True):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def _hist(req: dict, what: str, actor: str, **kw: Any) -> None:
    req.setdefault("history", []).append({"ts": now().isoformat(timespec="seconds"), "by": actor, "step": what, **kw})


def _audit(profile: Profile, req: dict, actor: str, action: str, result: str, **kw: Any) -> None:
    from panlab.pusher import audit

    audit(profile, actor=actor, action=f"urlfilter_{action}", request=req["id"], result=result, **kw)


def create_request(profile: Profile, cfg: Config, state: dict, *, actor: str, desired: dict[str, str],
                   allow_add: list[str] = (), allow_remove: list[str] = (), block_add: list[str] = (),
                   block_remove: list[str] = (), notes: str = "") -> dict:
    """Store only what differs from the live state. Raises UrlFilterError when nothing would change."""
    changes = {}
    for cat, act in (desired or {}).items():
        if cat not in state["actions"]:
            raise UrlFilterError(f"unknown category {cat!r}")
        if act not in ACTIONS:
            raise UrlFilterError(f"{cat}: action must be one of {', '.join(ACTIONS)}")
        if act != state["actions"][cat]:
            changes[cat] = {"from": state["actions"][cat], "to": act}
    custom = {}
    for kind, add, rem in (("allow", allow_add, allow_remove), ("block", block_add, block_remove)):
        have = set(state["custom"][kind]["urls"])
        a = [u for u in dict.fromkeys(add) if u not in have]
        r = [u for u in dict.fromkeys(rem) if u in have]
        if len(have) + len(a) - len(r) > MAX_URLS:
            raise UrlFilterError(f"{kind} list would exceed {MAX_URLS} entries")
        custom[kind] = {"add": a, "remove": r}
    both = set(custom["allow"]["add"]) & set(custom["block"]["add"])
    if both:
        raise UrlFilterError("the same site cannot be on both the allow and the block list: " + ", ".join(sorted(both)))
    if not changes and not any(v["add"] or v["remove"] for v in custom.values()):
        raise UrlFilterError("nothing to change: every choice already matches the live profile")
    t = now()
    req = {"id": f"url-{t.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}", "customer": profile.name, "status": "pending",
           "requester": actor, "created": t.isoformat(timespec="seconds"), "notes": (notes or "")[:2000],
           "target": cfg.target, "where": cfg.where, "profile": cfg.profile, "profile_existed": state["exists"],
           "changes": changes, "custom": custom, "base_hash": state_hash(state), "history": []}
    _hist(req, "submitted", actor, changes=len(changes), custom=sum(len(v["add"]) + len(v["remove"]) for v in custom.values()))
    save(profile, req)
    _audit(profile, req, actor, "request", "pending", changes=len(changes), url_profile=cfg.profile, target=cfg.target)
    return req


def deviations(req: dict) -> list[str]:
    """Requested actions that differ from the Palo Alto recommendation (the approver should look twice)."""
    out = []
    for cat, ch in sorted(req["changes"].items()):
        rec = recommended(cat)
        if ch["to"] != rec:
            weaker = rec == "block" and ch["to"] in ("allow", "alert", "continue", "override")
            out.append(f"{cat}: requested {ch['to']}, Palo Alto recommends {rec}" + (" (weaker than recommended)" if weaker else ""))
    if req["custom"]["allow"]["add"]:
        out.append("allow list additions bypass category blocking for: " + ", ".join(req["custom"]["allow"]["add"]))
    return out


def diff_lines(req: dict) -> list[str]:
    L = [f"{cat}: {ch['from']} -> {ch['to']}" for cat, ch in sorted(req["changes"].items())]
    for kind in ("allow", "block"):
        L += [f"{kind} list: + {u}" for u in req["custom"][kind]["add"]]
        L += [f"{kind} list: - {u}" for u in req["custom"][kind]["remove"]]
    return L


def is_stale(req: dict, state: dict) -> bool:
    return state_hash(state) != req["base_hash"]


def rebase(profile: Profile, req: dict, state: dict, *, actor: str) -> dict:
    """Approver re-review after the live profile changed: recompute the diff against what is live now."""
    if req["status"] not in ("pending", "stale"):
        raise UrlFilterError(f"request is {req['status']}")
    changes = {c: {"from": state["actions"][c], "to": ch["to"]} for c, ch in req["changes"].items()
               if c in state["actions"] and state["actions"][c] != ch["to"]}
    custom = {}
    for kind in ("allow", "block"):
        have = set(state["custom"][kind]["urls"])
        custom[kind] = {"add": [u for u in req["custom"][kind]["add"] if u not in have],
                        "remove": [u for u in req["custom"][kind]["remove"] if u in have]}
    dropped = len(diff_lines(req)) - len(diff_lines({"changes": changes, "custom": custom}))
    req.update(changes=changes, custom=custom, base_hash=state_hash(state), status="pending", profile_existed=state["exists"])
    _hist(req, "re-reviewed against the live profile", actor, dropped_already_live=dropped)
    save(profile, req)
    _audit(profile, req, actor, "rebase", "pending", dropped=dropped)
    return req


def desired_state(req: dict, state: dict) -> dict:
    acts = dict(state["actions"])
    acts.update({c: ch["to"] for c, ch in req["changes"].items()})
    custom = {}
    for kind in ("allow", "block"):
        urls = [u for u in state["custom"][kind]["urls"] if u not in req["custom"][kind]["remove"]]
        custom[kind] = sorted(set(urls) | set(req["custom"][kind]["add"]))
    return {"actions": acts, "custom": custom}


# ---------------------------------------------------------------- operations and change plan

def _list_el(tag: str, vals: list[str]) -> str:
    return f"<{tag}>" + "".join(f"<member>{_x(v)}</member>" for v in vals) + f"</{tag}>"


def _custom_el(name: str, urls: list[str], kind: str) -> str:
    return (f'<entry name="{_x(name)}"><list>' + "".join(f"<member>{_x(u)}</member>" for u in urls) + "</list>"
            f"<type>URL List</type><description>panlab URL filter self-service {kind} list</description></entry>")


def _profile_el(cfg: Config, state: dict, acts: dict[str, str], custom: dict[str, list[str]]) -> str:
    lists: dict[str, list[str]] = {a: [] for a in ACTIONS}
    for c in sorted(acts):
        lists[acts[c]].append(c)
    if custom["allow"]:
        lists["allow"].insert(0, cfg.allow_category)
    if custom["block"]:
        lists["block"].insert(0, cfg.block_category)
    keep = ""
    if state.get("profile_xml"):  # keep settings the self-service page does not manage (logging, credential detection ...)
        old = ET.fromstring(state["profile_xml"])
        keep = "".join(ET.tostring(ch, encoding="unicode") for ch in old if ch.tag not in ACTIONS)
    else:
        keep = "<description>panlab URL filter self-service</description>"
    return f'<entry name="{_x(cfg.profile)}">' + "".join(_list_el(a, lists[a]) for a in ACTIONS if lists[a]) + keep + "</entry>"


def build_ops(cfg: Config, state: dict, req: dict) -> tuple[list[dict], list[dict]]:
    """(apply ops, rollback ops). Each op: {op: edit|delete, xpath, element?, what}.

    Apply: create/update custom categories, then the profile, then delete categories that became empty.
    Rollback: restore categories that existed, then the profile (or delete it), then delete categories this created.
    """
    want = desired_state(req, state)
    first, last, back_first, back_last = [], [], [], []
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        had, now_urls = state["custom"][kind], want["custom"][kind]
        if now_urls == had["urls"] and had["exists"] == bool(now_urls):
            continue
        xp = cfg.custom_xpath(name)
        if now_urls:
            first.append({"op": "edit", "xpath": xp, "element": _custom_el(name, now_urls, kind), "what": f"custom URL category {name}"})
        elif had["exists"]:
            last.append({"op": "delete", "xpath": xp, "what": f"custom URL category {name} (now empty)"})
        if had["exists"]:
            back_first.append({"op": "edit", "xpath": xp, "element": _custom_el(name, had["urls"], kind), "what": f"restore {name}"})
        else:
            back_last.append({"op": "delete", "xpath": xp, "what": f"remove {name} (created by this change)"})
    pxp = cfg.profile_xpath()
    prof_op = {"op": "edit", "xpath": pxp, "element": _profile_el(cfg, state, want["actions"], want["custom"]),
               "what": f"URL Filtering profile {cfg.profile}"}
    prof_back = ({"op": "edit", "xpath": pxp, "element": state["profile_xml"], "what": f"restore {cfg.profile}"}
                 if state["exists"] else {"op": "delete", "xpath": pxp, "what": f"remove {cfg.profile} (created by this change)"})
    return first + [prof_op] + last, back_first + [prof_back] + back_last


def commit_all_cmd(cfg: Config) -> str:
    return (f'<commit-all><shared-policy><device-group><entry name="{_x(cfg.device_group)}"/></device-group>'
            "<include-template>no</include-template></shared-policy></commit-all>")


def _set_cli(cfg: Config, req: dict, state: dict) -> list[str]:
    pre = f"set device-group {cfg.device_group} " if cfg.backend == "panorama" else f"set "
    want = desired_state(req, state)
    L = []
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        if want["custom"][kind] != state["custom"][kind]["urls"]:
            if want["custom"][kind]:
                L.append(f"{pre}profiles custom-url-category {name} type \"URL List\" list [ {' '.join(want['custom'][kind])} ]")
            else:
                L.append(f"{pre.replace('set ', 'delete ', 1)}profiles custom-url-category {name}")
    by: dict[str, list[str]] = {}
    for c, ch in sorted(req["changes"].items()):
        by.setdefault(ch["to"], []).append(c)
        if c in state.get("listed", ()):
            L.append(f"{pre.replace('set ', 'delete ', 1)}profiles url-filtering {cfg.profile} {ch['from']} {c}")
    for act, cats in by.items():
        L.append(f"{pre}profiles url-filtering {cfg.profile} {act} [ {' '.join(cats)} ]")
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        if want["custom"][kind] and not state["custom"][kind]["urls"]:
            L.append(f"{pre}profiles url-filtering {cfg.profile} {kind} {name}")
    return L


def render_plan(profile: Profile, cfg: Config, req: dict, state: dict, ops: list[dict], back: list[dict], cr: str) -> str:
    """CR change plan (markdown), same section names as the other PAAT change plans."""
    devs = ", ".join(cfg.verify_targets) or "the device group's members"
    L = [f"# URL filter change: {cfg.profile} ({profile.name})", "",
         f"- CR: {cr}", f"- Request: {req['id']} by {req['requester']} on {req['created']} (America/Chicago)",
         f"- Approved by: {req.get('reviewer') or '?'}" + (f" — {req['review_comment']}" if req.get("review_comment") else ""),
         f"- Where: {cfg.target}, {cfg.where}", f"- Live state read: {state['read_at']} (hash {state_hash(state)})",
         f"- Requester notes: {req['notes'] or 'none'}", "", "## Summary", ""]
    L += [f"- {x}" for x in diff_lines(req)] or ["- (no changes)"]
    dev = deviations(req)
    if dev:
        L += ["", "Differs from the Palo Alto recommendation:"] + [f"- {d}" for d in dev]
    if not state["exists"]:
        L += ["", f"The profile {cfg.profile} does not exist yet; this change creates it (unlisted categories = allow)."]
    nav = f"Objects > Device Group {cfg.device_group}" if cfg.backend == "panorama" else "Objects"
    L += ["", "## Implementation Plan", ""]
    n = 1
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        if any(name in o["xpath"] for o in ops if "custom-url-category" in o["xpath"]):
            L.append(f"{n}. {nav} > Custom Objects > URL Category > **{name}** (type URL List): set the list to the "
                     f"entries in the Summary ({kind} list).")
            n += 1
    L.append(f"{n}. {nav} > Security Profiles > URL Filtering > **{cfg.profile}** > Categories: set Site Access for each "
             "category in the Summary" + (f"; {cfg.allow_category} = allow, {cfg.block_category} = block." if
                                           any("custom-url-category" in o["xpath"] for o in ops) else "."))
    n += 1
    if cfg.backend == "panorama":
        L.append(f"{n}. Commit to Panorama with description `panlab {cr} urlfilter {req['id']}`, then Push to Devices: "
                 f"device group **{cfg.device_group}** only (Edit Selections, no templates).")
    else:
        L.append(f"{n}. Commit with description `panlab {cr} urlfilter {req['id']}`.")
    L += ["", "### CLI (configure mode)", "", "```"] + _set_cli(cfg, req, state) + ["commit description \"panlab " + cr + "\"", "```",
          "", "### XML API (what PAAT runs)", ""]
    for i, o in enumerate(ops, 1):
        L.append(f"{i}. `type=config&action={o['op']}` xpath `{o['xpath']}` ({o['what']})")
    L.append(f"{len(ops) + 1}. `type=commit` description `panlab {cr} urlfilter {req['id']} by <approver>`")
    if cfg.backend == "panorama":
        L.append(f"{len(ops) + 2}. `type=commit&action=all` `{commit_all_cmd(cfg)}`")
    L += ["", "## Verification", "",
          f"1. Read back {cfg.profile} on {cfg.target}: every category in the Summary has its new action.",
          f"2. On {devs}: `show config pushed-shared-policy` contains {cfg.profile} with the same actions." if cfg.backend == "panorama"
          else "2. `show running url-filtering` / the profile in the running config shows the new actions.",
          "3. Monitor > Logs > URL Filtering: a test visit to a changed category shows the expected action.",
          f"4. The profile only takes effect on rules that use it (directly or in a security profile group) in {cfg.where}.",
          "", "## Backout Plan", "",
          "Restore the profile and custom categories as they were when this request was approved "
          "(PAAT keeps the snapshot; the request page has a Roll back button where live push is enabled):", ""]
    for i, o in enumerate(back, 1):
        L.append(f"{i}. `type=config&action={o['op']}` xpath `{o['xpath']}` ({o['what']})")
    L += [f"{len(back) + 1}. Commit" + (" and push the device group, as above." if cfg.backend == "panorama" else "."), ""]
    return "\n".join(L)


# ---------------------------------------------------------------- attachment check

def attachment(dev: UrlDevice, cfg: Config) -> dict:
    """Which profile groups contain the profile and which security rules use it (directly or via a group)."""
    groups = []
    for base in (cfg.base, "/config/shared"):
        el = dev.show(f"{base}/profile-group")
        for g in (el.findall("entry") if el is not None else []):
            if cfg.profile in _members(g, "url-filtering"):
                groups.append(g.get("name"))
    rules = []
    bases = [(f"{cfg.base}/{rb}/security/rules", rb) for rb in ("pre-rulebase", "post-rulebase")] if cfg.backend == "panorama" \
        else [(f"{cfg.base}/rulebase/security/rules", "rulebase")]
    for xp, rb in bases:
        el = dev.show(xp)
        for r in (el.findall("entry") if el is not None else []):
            ps = r.find("profile-setting")
            if ps is None or (r.findtext("disabled") or "").strip() == "yes":
                continue
            direct = cfg.profile in _members(ps.find("profiles"), "url-filtering") if ps.find("profiles") is not None else False
            via = [g for g in _members(ps, "group") if g in groups]
            if direct or via:
                rules.append({"rule": r.get("name"), "rulebase": rb, "via": via[0] if via else "direct"})
    return {"groups": groups, "rules": rules, "attached": bool(rules)}


# ---------------------------------------------------------------- review, push, rollback

def approve(profile: Profile, cfg: Config, req: dict, dev: UrlDevice, *, actor: str, cr: str, comment: str = "") -> dict:
    from panlab.pusher import check_cr

    if req["status"] not in ("pending", "stale"):
        raise UrlFilterError(f"request is {req['status']}; only a pending request can be approved")
    if actor == req["requester"] and not cfg.allow_self_approval:
        raise UrlFilterError("you cannot approve your own request; another approver must review it")
    cr = check_cr(profile, cr)
    state = read_live(dev, cfg)
    if is_stale(req, state):
        req["status"] = "stale"
        _hist(req, "approve refused: the live profile changed since the request was made", actor)
        save(profile, req)
        _audit(profile, req, actor, "approve", "stale")
        raise StaleError("the live profile changed since this request was made; re-review it against the live profile first")
    ops, back = build_ops(cfg, state, req)
    req.update(status="approved", reviewer=actor, reviewed_at=now().isoformat(timespec="seconds"), review_comment=(comment or "")[:1000],
               cr=cr, ops=ops, rollback_ops=back, approved_state=state, mode="live" if live_allowed(profile, cfg) else "dry-run")
    req["plan_md"] = render_plan(profile, cfg, req, state, ops, back, cr)
    _hist(req, "approved", actor, cr=cr, mode=req["mode"], ops=len(ops))
    save(profile, req)
    _audit(profile, req, actor, "approve", "approved", cr=cr, mode=req["mode"], target=cfg.target)
    return req


def reject(profile: Profile, req: dict, *, actor: str, comment: str) -> dict:
    if req["status"] not in ("pending", "stale", "approved"):
        raise UrlFilterError(f"request is {req['status']}")
    if not (comment or "").strip():
        raise UrlFilterError("say why the request is rejected (the requester sees this comment)")
    req.update(status="rejected", reviewer=actor, reviewed_at=now().isoformat(timespec="seconds"), review_comment=comment.strip()[:1000])
    _hist(req, "rejected", actor, comment=req["review_comment"])
    save(profile, req)
    _audit(profile, req, actor, "reject", "rejected")
    return req


def _matches(state: dict, want: dict, cfg: Config) -> list[str]:
    bad = [f"{c}: is {state['actions'].get(c)}, expected {a}" for c, a in want["actions"].items() if state["actions"].get(c) != a]
    for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
        if state["custom"][kind]["urls"] != want["custom"][kind]:
            bad.append(f"{name}: list differs")
        if want["custom"][kind] and state["custom_actions"].get(kind) != kind:
            bad.append(f"{name}: not set to {kind} in the profile")
    return bad


def _state_from_pushed(root: ET.Element | None, cfg: Config, cats: list[str]) -> dict:
    """Firewall view of the Panorama-pushed profile (``show config pushed-shared-policy``)."""
    pel = None
    custom = {}
    if root is not None:
        for e in root.iter("entry"):
            if e.get("name") == cfg.profile and any(e.find(a) is not None for a in ACTIONS):
                pel = e
        for kind, name in (("allow", cfg.allow_category), ("block", cfg.block_category)):
            hit = [e for e in root.iter("entry") if e.get("name") == name and e.find("list") is not None]
            custom[kind] = {"exists": bool(hit), "urls": sorted(_members(hit[0], "list")) if hit else []}
    else:
        custom = {k: {"exists": False, "urls": []} for k in ("allow", "block")}
    acts = parse_profile(pel)
    return {"exists": pel is not None, "actions": {c: acts.get(c, "allow") for c in cats}, "custom": custom,
            "custom_actions": {k: acts.get(n) for k, n in (("allow", cfg.allow_category), ("block", cfg.block_category))}}


def _run(profile: Profile, cfg: Config, req: dict, dev: UrlDevice, ops: list[dict], want: dict, *, actor: str, label: str,
         verify_devs: dict[str, UrlDevice] | None) -> tuple[bool, str, list[dict]]:
    if dev.pending_changes():
        return False, f"{cfg.target} has uncommitted changes from someone else; commit or revert them first", []
    done = 0
    try:
        for o in ops:
            (dev.delete(o["xpath"]) if o["op"] == "delete" else dev.edit(o["xpath"], o["element"]))
            done += 1
    except Exception as exc:  # noqa: BLE001
        dev.revert()
        return False, f"write failed after {done} item(s): {str(exc)[:300]}; candidate reverted, nothing committed", []
    _hist(req, f"{label}: candidate written", actor, items=done)
    try:
        job = dev.commit(f"panlab {req['cr']} urlfilter {req['id']} {label} by {actor}")
    except Exception as exc:  # noqa: BLE001
        job = {"jobid": None, "success": False, "messages": [str(exc)[:300]]}
    req.setdefault("jobs", []).append({"step": f"{label}-commit", **job})
    if not job.get("success"):
        try:
            dev.revert()
        except Exception:  # noqa: BLE001
            pass
        return False, "commit failed: " + "; ".join(job.get("messages") or ["unknown"]) + "; candidate reverted", []
    _hist(req, f"{label}: committed on {cfg.target}", actor, job=job.get("jobid"))
    checks = []
    after = read_live(dev, cfg)
    bad = _matches(after, want, cfg)
    checks.append({"check": f"{cfg.profile} on {cfg.target} matches", "ok": not bad, "detail": "; ".join(bad[:5])})
    if cfg.backend == "panorama":
        try:
            pj = dev.commit_all(commit_all_cmd(cfg))
        except Exception as exc:  # noqa: BLE001
            pj = {"jobid": None, "success": False, "messages": [str(exc)[:300]]}
        req["jobs"].append({"step": f"{label}-push {cfg.device_group}", **pj})
        _hist(req, f"{label}: push device group {cfg.device_group}", actor, job=pj.get("jobid"), success=pj.get("success"))
        if not pj.get("success"):
            return False, "committed on Panorama, but the device-group push failed: " + "; ".join(pj.get("messages") or ["unknown"]), checks
        for name, fw in (verify_devs or {}).items():
            try:
                st = _state_from_pushed(fw.pushed_policy(), cfg, after["categories"])
                bad = _matches(st, want, cfg)
            except Exception as exc:  # noqa: BLE001
                bad = [f"could not read: {str(exc)[:200]}"]
            checks.append({"check": f"{cfg.profile} pushed to {name} matches", "ok": not bad, "detail": "; ".join(bad[:5])})
    ok = all(c["ok"] for c in checks)
    return ok, ("committed" + (" and pushed" if cfg.backend == "panorama" else "") + " and verified" if ok
                else "committed, but verification failed: " + "; ".join(c["check"] for c in checks if not c["ok"])), checks


def push(profile: Profile, cfg: Config, req: dict, dev: UrlDevice, *, actor: str, confirm_target: str,
         verify_devs: dict[str, UrlDevice] | None = None) -> dict:
    if req["status"] != "approved":
        raise UrlFilterError(f"request is {req['status']}; approve it first")
    if not live_allowed(profile, cfg):
        _audit(profile, req, actor, "push", "refused", detail="dry-run only for this customer")
        raise UrlFilterError("live push is off for this customer (Panorama dry-run only): implement the change plan by hand")
    if (confirm_target or "").strip() != cfg.target:
        raise UrlFilterError("typed target does not match; nothing was changed")
    state = read_live(dev, cfg)
    if state_hash(state) != state_hash(req["approved_state"]):
        req["status"] = "stale"
        _hist(req, "push refused: the live profile changed after approval", actor)
        save(profile, req)
        _audit(profile, req, actor, "push", "stale")
        raise StaleError("the live profile changed after approval; re-review and approve again")
    want = desired_state(req, req["approved_state"])
    req["status"] = "pushing"  # a second click (or a rollback) while this runs is refused
    save(profile, req)
    ok, msg, checks = _run(profile, cfg, req, dev, req["ops"], want, actor=actor, label="push", verify_devs=verify_devs)
    req.update(status="pushed" if ok else "failed", pushed_by=actor, pushed_at=now().isoformat(timespec="seconds"),
               result=msg, verify=checks)
    _hist(req, f"push finished ({req['status']})", actor, detail=msg[:300])
    save(profile, req)
    _audit(profile, req, actor, "push", req["status"], cr=req["cr"], target=cfg.target, detail=msg[:300],
           job_ids=[j.get("jobid") for j in req.get("jobs", [])])
    return req


def rollback(profile: Profile, cfg: Config, req: dict, dev: UrlDevice, *, actor: str, confirm_target: str,
             verify_devs: dict[str, UrlDevice] | None = None) -> dict:
    if req["status"] not in ("pushed", "failed") or not req.get("jobs"):
        raise UrlFilterError(f"request is {req['status']}; only a pushed (or failed after commit) request can be rolled back")
    if not live_allowed(profile, cfg):
        raise UrlFilterError("live push is off for this customer")
    if (confirm_target or "").strip() != cfg.target:
        raise UrlFilterError("typed target does not match; nothing was changed")
    base = req["approved_state"]
    want = {"actions": base["actions"], "custom": {k: base["custom"][k]["urls"] for k in ("allow", "block")}}
    req["status"] = "rolling-back"
    save(profile, req)
    ok, msg, checks = _run(profile, cfg, req, dev, req["rollback_ops"], want, actor=actor, label="rollback", verify_devs=verify_devs)
    if not base["exists"]:  # profile removed: verify by absence instead of actions
        st = read_live(dev, cfg)
        ok = ok or (not st["exists"] and not any(st["custom"][k]["exists"] for k in ("allow", "block")))
    req.update(status="rolled-back" if ok else "failed", rolled_back_by=actor, rollback_result=msg, rollback_verify=checks)
    _hist(req, f"rollback finished ({req['status']})", actor, detail=msg[:300])
    save(profile, req)
    _audit(profile, req, actor, "rollback", req["status"], cr=req.get("cr"), target=cfg.target, detail=msg[:300])
    return req
