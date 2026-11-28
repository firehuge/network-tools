#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build pan-physical-upgrade.html from build/template.html + style.css + core.js + app.js + worker + catalog."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent.parent
B = ROOT / "build"
html = (B / "template.html").read_text()
css = (B / "style.css").read_text()
core = (B / "core.js").read_text()
app = (B / "app.js").read_text()
worker = (B / "unpack-worker.js").read_text()
catalog = json.loads((ROOT / "catalog" / "models.json").read_text())
for ph in ('"@@WORKER_JS@@"', '"@@CATALOG_JSON@@"'):
    if ph not in app:
        raise SystemExit("app.js is missing " + ph)
app = app.replace('"@@WORKER_JS@@"', json.dumps(worker), 1)
app = app.replace('"@@CATALOG_JSON@@"', json.dumps(catalog, separators=(",", ":")).replace("</", "<\\/"), 1)
js = core + "\n" + app
if "</script" in js.replace("<\\/script", ""):
    raise SystemExit("a literal </script in the JS would break the page")
html = html.replace("<style>\n</style>", "<style>\n" + css + "\n</style>", 1)
html = html.replace("<script>\n</script>", "<script>\n" + js + "\n</script>", 1)
out = ROOT / "pan-physical-upgrade.html"
out.write_text(html)
print("assembled", out, len(html), "bytes")
