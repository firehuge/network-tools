"""PAN-OS version parsing, ordering, trains, recommended hotfix, and upgrade paths.

A PAN-OS version looks like ``11.1.6``, ``11.1.6-h32`` or (rarely) ``10.2.0-c123``.
Plain string sorting gets these wrong (``-h7`` sorts after ``-h32``;
``11.1.10`` before ``11.1.6``), so everything here compares parsed tuples.

* **train** (feature release): ``major.minor`` such as ``11.1``.
* **release** (maintenance release): ``major.minor.maint`` such as ``11.1.6``.
* **hotfix**: the ``-hN`` suffix; ``11.1.6-h32`` is newer than ``11.1.6-h7``
  and both are newer than ``11.1.6``.

Upgrade path rules (PAN-OS upgrade guide):

* Installing any release of a *different* train needs that train's base image
  (``x.y.0``) **downloaded** first (it does not have to be installed).
* Feature trains are stepped through one at a time (11.0 -> 11.1 -> 11.2);
  each intermediate train gets its base image downloaded and its newest
  available release installed and rebooted before moving on. (PAN-OS 10.1+
  also has "skip software version upgrade"; the wizard deliberately uses the
  conservative path so a junior never has to reason about it.)
* Downgrades are only offered for a firewall, only inside its current feature
  train (for example 11.1.13-h17 back to 11.1.13-h9), and only when the caller
  asks for them (``allow_downgrade``). A downgrade across feature trains
  (11.2 back to 11.1) needs a config-compatibility review that the wizard
  does not do; it is refused with a plain-English reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import total_ordering
from typing import Iterable

_VER_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(?:-([a-z])(\d+))?(?:[-.].*)?\s*$", re.I)


@total_ordering
@dataclass(frozen=True)
class PanosVersion:
    major: int
    minor: int
    maint: int
    suffix: str = ""   # "h" for hotfix, "c"/"b" for other builds, "" for GA
    suffix_n: int = 0
    raw: str = ""

    @classmethod
    def parse(cls, s: str) -> "PanosVersion":
        m = _VER_RE.match(str(s or ""))
        if not m:
            raise ValueError(f"not a PAN-OS version: {s!r}")
        return cls(int(m[1]), int(m[2]), int(m[3]), (m[4] or "").lower(), int(m[5] or 0), str(s).strip())

    @classmethod
    def try_parse(cls, s: str | None) -> "PanosVersion | None":
        try:
            return cls.parse(s or "")
        except ValueError:
            return None

    def key(self) -> tuple:
        # GA (no suffix) < any hotfix of the same release. Non-hotfix builds (-c, -b)
        # sort below GA so a special build is never picked as "newest".
        rank = {"": 1, "h": 2}.get(self.suffix, 0)
        return (self.major, self.minor, self.maint, rank, self.suffix_n)

    def __lt__(self, other: "PanosVersion") -> bool:
        return self.key() < other.key()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PanosVersion) and self.key() == other.key()

    def __hash__(self) -> int:
        return hash(self.key())

    @property
    def train(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def train_key(self) -> tuple[int, int]:
        return (self.major, self.minor)

    @property
    def release(self) -> str:
        return f"{self.major}.{self.minor}.{self.maint}"

    @property
    def is_base(self) -> bool:
        return self.maint == 0 and self.suffix == ""

    @property
    def is_hotfix(self) -> bool:
        return self.suffix == "h"

    @property
    def base(self) -> str:
        return f"{self.major}.{self.minor}.0"

    def __str__(self) -> str:
        if self.raw:
            return self.raw
        return self.release + (f"-{self.suffix}{self.suffix_n}" if self.suffix else "")


def V(s: str) -> PanosVersion:
    return PanosVersion.parse(s)


def train_of(s: str) -> str:
    return V(s).train


@dataclass
class Available:
    """One row of ``request system software info``."""
    version: str
    downloaded: bool = False
    current: bool = False
    latest: bool = False
    uploaded: bool = False
    size_mb: float = 0.0
    released_on: str = ""
    filename: str = ""

    @property
    def v(self) -> PanosVersion:
        return V(self.version)


@dataclass
class TrainView:
    train: str
    versions: list[Available] = field(default_factory=list)  # newest first

    @property
    def newest(self) -> Available | None:
        return self.versions[0] if self.versions else None


def parse_versions(items: Iterable[Available]) -> list[Available]:
    """Drop rows that are not parseable versions, de-duplicate, newest first."""
    seen: dict[PanosVersion, Available] = {}
    for a in items:
        v = PanosVersion.try_parse(a.version)
        if v is None:
            continue
        prev = seen.get(v)
        if prev is None or (a.downloaded and not prev.downloaded):
            seen[v] = a
    return [seen[k] for k in sorted(seen, reverse=True)]


def group_by_train(items: Iterable[Available]) -> list[TrainView]:
    out: dict[tuple[int, int], TrainView] = {}
    for a in parse_versions(items):
        v = a.v
        out.setdefault(v.train_key, TrainView(v.train)).versions.append(a)
    return [out[k] for k in sorted(out, reverse=True)]


def latest_in_train(items: Iterable[Available], train: str, *, exclude_special: bool = True) -> Available | None:
    best = None
    for a in parse_versions(items):
        v = a.v
        if v.train != train:
            continue
        if exclude_special and v.suffix not in ("", "h"):
            continue
        if best is None or v > best.v:
            best = a
    return best


def latest_hotfix_of_release(items: Iterable[Available], release: str) -> Available | None:
    best = None
    for a in parse_versions(items):
        v = a.v
        if v.release == release and v.suffix in ("", "h") and (best is None or v > best.v):
            best = a
    return best


@dataclass
class Recommendation:
    version: str | None
    why: str
    latest_same_release: str | None = None  # newest hotfix of the exact x.y.z
    latest_in_train: str | None = None


def recommend(current: str, items: Iterable[Available], preferred: Iterable[str] = (), ceiling: str | None = None) -> Recommendation:
    """Recommended default target: stay in the current train.

    1. If an operator-supplied *preferred* list (from PAN's release guidance)
       names versions in this train that are newer than current, take the newest.
    2. Otherwise the newest release in the current train (newest hotfix of the
       newest maintenance release).
    Nothing newer -> no recommendation ("you are on the latest in this train").

    ``ceiling`` is the version of the Panorama that manages this firewall: a firewall may not run a newer
    version than its Panorama, so nothing above it is recommended (``latest_in_train`` still shows the newest
    release the update server offers, so the page can say what Panorama would have to be upgraded to).
    """
    items = list(items)
    cur = V(current)
    full_train = latest_in_train(items, cur.train)
    cap = PanosVersion.try_parse(ceiling) if ceiling else None
    if cap is not None:
        items = [a for a in items if a.v <= cap]
    same_rel = latest_hotfix_of_release(items, cur.release)
    in_train = latest_in_train(items, cur.train)
    pref = sorted((p for p in (PanosVersion.try_parse(x) for x in preferred)
                   if p is not None and p.train == cur.train and p > cur), reverse=True)
    avail = {a.v for a in parse_versions(items)}
    rec = Recommendation(None, "", same_rel.version if same_rel else None, full_train.version if full_train else None)
    for p in pref:
        if p in avail:
            rec.version, rec.why = str(p), (f"{p} is on the preferred-release list for the {cur.train} train and is newer "
                                            f"than {current}.")
            return rec
    if in_train and in_train.v > cur:
        rec.version = in_train.version
        rec.why = (f"{in_train.version} is the newest release in the {cur.train} train you are already on. Staying in the "
                   "same train picks up security and bug fixes with the least change in behavior.")
    elif cap is not None and full_train and full_train.v > cap:
        rec.why = (f"{current} is already the newest release this firewall may run: its Panorama is on {ceiling}, and a firewall cannot be "
                   f"newer than its Panorama. The {cur.train} train offers up to {full_train.version}; upgrade Panorama first to go there.")
    else:
        rec.why = f"{current} is already the newest release in the {cur.train} train that this device can see."
    return rec


@dataclass
class PathStep:
    action: str          # "download" | "install"
    version: str
    why: str
    downgrade: bool = False


def is_downgrade(current: str, target: str) -> bool:
    c, t = PanosVersion.try_parse(current), PanosVersion.try_parse(target)
    return c is not None and t is not None and t < c


def upgrade_path(current: str, target: str, items: Iterable[Available], *, allow_downgrade: bool = False
                 ) -> tuple[list[PathStep], list[str]]:
    """Ordered download/install steps to go from current to target, plus errors.

    Errors (non-empty = blocked): downgrade (unless ``allow_downgrade`` and the
    same feature train), target not offered, a needed base image or
    intermediate train not offered by the device.
    """
    items = parse_versions(items)
    cur, tgt = V(current), V(target)
    by_v = {a.v: a for a in items}
    errors: list[str] = []
    steps: list[PathStep] = []
    if tgt < cur:
        if not allow_downgrade:
            return [], [f"{target} is older than the running {current}. Downgrades are not offered for this device."]
        if tgt.train_key != cur.train_key:
            return [], [f"{target} is in an older feature train than the running {current}. The wizard only downgrades inside "
                        f"the {cur.train} train (for example back to an earlier hotfix). Downgrading to {tgt.train} needs a config "
                        "compatibility review; do it by hand from the Palo Alto downgrade guide."]
        if tgt not in by_v:
            return [], [f"{target} is not in this device's list of available versions. Run the version check again."]
        steps = [PathStep("download", str(tgt), "Older image (the downgrade target).", True),
                 PathStep("install", str(tgt), f"Downgrade to {tgt}, then reboot. The config backup taken earlier in this plan is the "
                                                "safety net; the post-check compares the device afterwards.", True)]
        a = by_v.get(tgt)
        if a is not None and a.downloaded:
            steps[0].why += " (already downloaded; this step will be skipped)"
        return steps, []
    if tgt == cur:
        return [], [f"{target} is already running."]
    if tgt not in by_v:
        return [], [f"{target} is not in this device's list of available versions. Run the version check again."]
    trains = sorted({a.v.train_key for a in items})
    hops = [t for t in trains if cur.train_key < t < tgt.train_key]
    for t in hops:
        tname = f"{t[0]}.{t[1]}"
        base = V(f"{tname}.0")
        if base not in by_v:
            errors.append(f"Base image {tname}.0 for the intermediate {tname} train is not offered by the device.")
            continue
        newest = latest_in_train(items, tname)
        steps.append(PathStep("download", str(base), f"Base image for {tname}; required before any {tname} release can be installed."))
        if newest and newest.v != base:
            steps.append(PathStep("download", newest.version, f"Newest {tname} release, used as the stepping stone."))
        steps.append(PathStep("install", newest.version if newest else str(base),
                              f"Step through {tname} (feature trains are upgraded one at a time), then reboot."))
    if tgt.train_key != cur.train_key:
        base = V(tgt.base)
        if base not in by_v:
            errors.append(f"Base image {tgt.base} is not offered by the device; it must be downloaded before {target}.")
        elif base != tgt:
            steps.append(PathStep("download", str(base), f"Base image for {tgt.train}; required before {target} can be installed."))
    steps.append(PathStep("download", str(tgt), "Target image."))
    steps.append(PathStep("install", str(tgt), "Install the target, then reboot."))
    # Skip downloads the device already has.
    for s in steps:
        a = by_v.get(V(s.version))
        if s.action == "download" and a is not None and a.downloaded:
            s.why += " (already downloaded; this step will be skipped)"
    return steps, errors


def is_feature_jump(current: str, target: str) -> bool:
    return V(current).train_key != V(target).train_key
