/* SPDX-License-Identifier: Apache-2.0 */
/* Tiny loopback static server so UI tests do not use file:// (localStorage and
   sessionStorage on file:// are not reliably kept across reloads in headless Chrome). */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".txt": "text/plain; charset=utf-8",
};

export function startStaticServer(root) {
  const rootAbs = path.resolve(root);
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || "/", "http://127.0.0.1");
    let p = path.resolve(rootAbs, "." + decodeURIComponent(u.pathname));
    if (p !== rootAbs && !p.startsWith(rootAbs + path.sep)) { res.writeHead(403); res.end(); return; }
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, "index.html");
    fs.readFile(p, (err, data) => {
      if (err) { res.writeHead(404); res.end("not found"); return; }
      res.writeHead(200, { "Content-Type": MIME[path.extname(p).toLowerCase()] || "application/octet-stream" });
      res.end(data);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        port,
        url: (p) => "http://127.0.0.1:" + port + (p.startsWith("/") ? p : "/" + p),
        close: () => new Promise((r, j) => server.close((e) => e ? j(e) : r())),
      });
    });
  });
}

export function isLocalTestUrl(u, port) {
  return /^(file|blob|data):/.test(u) || u.startsWith("http://127.0.0.1:" + port + "/") || u === "http://127.0.0.1:" + port;
}
