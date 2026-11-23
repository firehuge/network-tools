# Vendored FlowMapper engine

`core.js`, `render.js` and `decom.js` are verbatim copies of `build/core.js`, `build/render.js` and
`build/decom.js` from the **flowmapper** folder of this repository. They are the single source for
path tracing, FCR annotation, local-backup merge, diagrams and decommission plans. Do not edit the copies.

`cli.js` belongs to PAAT: a small Node runner around `core.js`.

## Sync

From the `paat/` folder:

```bash
python3 tools/sync-flowmapper.py            # copies from ../flowmapper and rewrites manifest.json
python3 tools/sync-flowmapper.py --check    # verify the hashes only
```

The manifest records the engine version and the sha256 of each file; PAAT checks it before a trace.
