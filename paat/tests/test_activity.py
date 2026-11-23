# SPDX-License-Identifier: Apache-2.0
"""panlab.activity: the shared 'is anything mid-flight?' check run before every PAAT restart."""

import json
import os
import time

from panlab import activity


def _w(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)


def test_idle_and_each_busy_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("PANLAB_DATA_DIR", str(tmp_path))
    _w(tmp_path / "c1" / "upgrade" / "upg-1.json", {"id": "upg-1", "status": "complete", "steps": [{"n": 1, "status": "ok"}]})
    _w(tmp_path / "c1" / "urlfilter" / "url-1.json", {"id": "url-1", "status": "pushed"})
    old = tmp_path / "c1" / "push" / "push-1.json"
    _w(old, {"status": "committed"})
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    assert activity.busy_items() == [] and activity.main([]) == 0
    _w(tmp_path / "c2" / "upgrade" / "upg-2.json", {"id": "upg-2", "status": "armed",
                                                     "steps": [{"n": 3, "action": "content", "status": "running"}]})
    _w(tmp_path / "c2" / "urlfilter" / "url-2.json", {"id": "url-2", "status": "pushing"})
    _w(tmp_path / "c2" / "push" / "push-2.json", {"status": "prepared"})
    _w(tmp_path / "c3" / "upgrade" / "upg-3.json", "{not json")
    items = activity.busy_items()
    assert any("upg-2 step 3 content running" in i for i in items)
    assert any("url-2 pushing" in i for i in items)
    assert any("push-2" in i for i in items)
    assert any("upg-3 unreadable" in i for i in items)  # fails closed
    assert activity.main([]) == 1
