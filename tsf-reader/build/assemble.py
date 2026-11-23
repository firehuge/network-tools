#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Splice style.css + unpack-worker.js + app.js into pan-tsf-triage.html."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
html = (ROOT / "pan-tsf-triage.html").read_text()
css = (BUILD / "style.css").read_text()
js = (BUILD / "app.js").read_text()
worker = (BUILD / "unpack-worker.js").read_text()
if '"@@WORKER_JS@@"' not in js:
    raise SystemExit("app.js is missing the @@WORKER_JS@@ placeholder")
js = js.replace('"@@WORKER_JS@@"', json.dumps(worker), 1)
si, se = html.find("<style>"), html.find("</style>")
if si < 0 or se < 0:
    raise SystemExit("style tags missing")
html = html[:si+7] + "\n" + css + "\n" + html[se:]
sci, sce = html.find("<script>"), html.rfind("</script>")
if sci < 0 or sce < 0:
    raise SystemExit("script tags missing")
html = html[:sci+8] + "\n" + js + "\n" + html[sce:]
if "showsens" not in html:
    raise SystemExit("expected #showsens in assembled HTML")
if "btn-cancel" not in html:
    raise SystemExit("expected #btn-cancel in assembled HTML")
(ROOT / "pan-tsf-triage.html").write_text(html)
print("assembled", ROOT / "pan-tsf-triage.html", "bytes", len(html))
