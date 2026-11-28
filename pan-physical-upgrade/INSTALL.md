# Install

There is nothing to install on a server. The tool is one HTML file.

1. Download `pan-physical-upgrade.html` from a release (or copy it from this repository).
2. Put it on your computer, a USB stick or a shared folder.
3. Open it in a current browser (Chrome, Edge or Firefox). It works offline.

The only network call is an optional check for a newer model catalog (`catalog/models.json` in this repository). If it fails,
the catalog bundled in the page is used. The header badge says which one is active. You can also load a catalog file by hand.

## Privacy note
A tech-support file and a config export contain hostnames, serial numbers, IP addresses, usernames and secrets. The tool keeps
them in your browser. Do not commit real tech-support files or configs to this repository; the repository `.gitignore` blocks
`*.tgz` and `*.xml` except for the synthetic samples.

## Building from source (developers)
```
npm ci
npm run build    # python3 tools/build_catalog.py, then python3 build/assemble.py
npm test         # needs Chrome or Chromium for the UI tests (CHROME_PATH)
```
`build/assemble.py` splices `build/template.html`, `style.css`, `core.js`, `app.js`, `unpack-worker.js` and `catalog/models.json`
into `pan-physical-upgrade.html`.
