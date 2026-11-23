# Install

## Use it (no install)
1. Download `pan-flowmapper.html` from a release, or copy it from this repository.
2. Open it in a current Chrome, Edge, Firefox or Safari. It is one self-contained file, works offline and makes no network requests.
3. Optionally put it on a shared drive for your team.

## Build it from source
Requirements: Node.js 18 or newer and Python 3.
```
cd flowmapper
npm install
npm run build        # writes synthetic samples to samples/ and rebuilds pan-flowmapper.html
```
`build/assemble.py` splices `build/style.css`, `core.js`, `render.js`, `decom.js`, `app.js`, `decom-ui.js` and a synthetic demo config into `pan-flowmapper.html`. It fails if the JavaScript contains any network API, so the page stays offline.

## Run the tests
```
npm test             # needs Google Chrome or Chromium for the browser tests; set CHROME_PATH if it is not at a standard path
```

## Try it with synthetic samples
`npm run samples` writes synthetic firewall and Panorama configs (all made up, documentation addresses and `10.x` examples) to `samples/`. Load any of them into the page.
