#!/usr/bin/env python3
"""Splice style.css + core.js + render.js + decom.js + app.js + decom-ui.js (+ embedded synthetic demo config) into pan-flowmapper.html."""
from pathlib import Path
import json, re

ROOT = Path(__file__).resolve().parent.parent
B = ROOT / "build"
html = (B / "template.html").read_text()
css = (B / "style.css").read_text()
core = (B / "core.js").read_text()
render = (B / "render.js").read_text()
decom = (B / "decom.js").read_text()
decom_ui = (B / "decom-ui.js").read_text()
app = (B / "app.js").read_text()
demo = (ROOT / "samples" / "fw-multi-vsys.xml").read_text()
if '"@@DEMO_XML@@"' not in app:
    raise SystemExit("app.js is missing the @@DEMO_XML@@ placeholder")
app = app.replace('"@@DEMO_XML@@"', json.dumps(demo).replace("</", "<\\/"), 1)
js = core + "\n" + render + "\n" + decom + "\n" + app + "\n" + decom_ui
if re.search(r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(", js):
    raise SystemExit("network API found in JS; the tool must stay offline")
if "</script" in js.lower():
    raise SystemExit("literal </script in JS")
html = html.replace("<style>\n</style>", "<style>\n" + css + "\n</style>", 1)
html = html.replace("<script>\n</script>", "<script>\n" + js + "\n</script>", 1)
(ROOT / "pan-flowmapper.html").write_text(html)
print("assembled", ROOT / "pan-flowmapper.html", "bytes", len(html))
