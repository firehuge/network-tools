# Install

There is nothing to install on a server. The tool is one HTML file.

1. Download `pan-tsf-triage.html` from a release (or copy it from this repository).
2. Put it on your computer, a USB stick or a shared folder.
3. Open it in a current browser. It works offline and has no external dependencies.

## Privacy note
A tech support file contains hostnames, serial numbers, IP addresses, usernames and the running configuration. The tool keeps it in your browser. Do not commit real tech-support files to this repository; the repository `.gitignore` blocks `*.tgz`.

## Building from source (developers)
```
python3 build/assemble.py   # splices build/style.css, build/unpack-worker.js and build/app.js into pan-tsf-triage.html
```
