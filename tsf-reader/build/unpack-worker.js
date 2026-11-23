/* Streaming TSF unpacker. Runs in a Web Worker. Never holds the whole archive. */
"use strict";

const dec = new TextDecoder("utf-8");
const TEXT_CAP = 4 * 1024 * 1024;
const TEXT_TAIL = 1 * 1024 * 1024;
const LOG_HEAD = 64 * 1024;
const LOG_TAIL = 256 * 1024;
const MAX_MATCH_LINES = 200;
const FULL_SOFT = 2 * 1024 * 1024;
const DEFAULT_BUDGET = 256 * 1024 * 1024; // ~256 MiB of kept text across the bundle
const BATCH_MAX = 16;
const BATCH_BYTES = 1 * 1024 * 1024;
const SKIP_RE = /\.(?:bin|so|pcap|pcapng|img|iso|mp3|jpg|jpeg|png|gif|pdf|ko|o|a)$/i;
const enc = new TextEncoder();

const ISSUE_RE = /split-brain|peer state active|link-monitor|link monitor|path-monitor|path monitor|preempt(?!ive)|commit-?all failed|CommitAll job .* fail|commit (job )?(failed|FAIL)|user-?id agent.*disconnect|agent .* disconnected|server-monitor.*disconnect|LDAP bind failed|useridd.*disconnect|authentication failed|auth(entication)? fail|lockout|BGP neighbor|hold timer expired|went down|certificate expired|ssl decryption error|untrusted (issuer|cert)|failed to forward logs|Panorama connectivity|disconnected from Panorama|log forwarding disconnected|cannot send logging|exited unexpectedly|core dumped|restart count|Process \S+ exited|SIGSEGV|restarting|\b(Error|Critical|Fatal|EMERG|ALERT|CRIT|panic)\b/i;

let cancelled = false;
let inBytes = 0;
let outBytes = 0;
let filesIndexed = 0;
let currentFile = "";
let lastProgress = 0;
let fileSize = 0;
let peakHeap = 0;
let onProgress = null;
let retainBudget = DEFAULT_BUDGET;
let retainedBytes = 0;
let budgetHit = false;
let budgetedCount = 0;
let batchFiles = [];
let batchXfer = [];
let extractTarget = null;
let extractFound = false;

function fmtBytes(n){
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n/1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n/1048576).toFixed(1) + " MB";
  return (n/1073741824).toFixed(2) + " GB";
}
function shortName(p){ return (p||"").split(/[\\/]/).filter(Boolean).pop() || p; }
function normPath(p){ return (p||"").replace(/\\/g,"/").replace(/^\.\//,""); }
function heapNow(){
  try {
    if (performance && performance.memory && performance.memory.usedJSHeapSize){
      const v = performance.memory.usedJSHeapSize;
      if (v > peakHeap) peakHeap = v;
      return v;
    }
  } catch (e){}
  return 0;
}
function progress(stage, force){
  const now = Date.now();
  if (!force && now - lastProgress < 80) return;
  lastProgress = now;
  const payload = {
    type: "progress",
    stage: stage || "reading",
    inBytes,
    outBytes,
    fileSize,
    filesIndexed,
    currentFile,
    heap: heapNow()
  };
  if (onProgress) onProgress(payload);
  else if (typeof self !== "undefined" && self.postMessage) self.postMessage(payload);
}
function checkCancel(){
  if (cancelled){
    const e = new Error("Cancelled");
    e.name = "AbortError";
    e.cancelled = true;
    throw e;
  }
}

function isPrimaryCli(path){
  const p = normPath(path).toLowerCase();
  const b = shortName(p);
  if (/\/tmp\/cli\/logs\//.test(p)) return false;
  if (/\/tmp\/cli\/.*techsupport[^/]*\.(txt|log)$/.test(p) || /^techsupport.*\.(txt|log)$/.test(b)) return true;
  if (/^cli\.(txt|log|out)$/.test(b) || /^output\.(txt|log)$/.test(b) || /^tech-?support/.test(b)) return true;
  return false;
}
function isConfigPath(path){
  const p = normPath(path).toLowerCase();
  if (/ha-remote|panorama_pushed|predefined|sysd_objects/i.test(p)) return false;
  return /running-config\.xml$/.test(p) || /\/saved-configs\/(techsupport-saved-currcfg|running-config|\.merged-running-config)\.xml$/.test(p) || /\/opt\/pancfg\/.*running-config\.xml$/.test(p);
}
function isLogPath(path){
  const p = normPath(path).toLowerCase();
  if (/\/var\/log\//.test(p) || /\/mp-log\//.test(p) || /\/dp-log\//.test(p)) return true;
  return /\.(log)(?:\.\d+)?$/.test(p) && !isPrimaryCli(path);
}
function looksGzip(u8){ return u8.length >= 2 && u8[0] === 0x1f && u8[1] === 0x8b; }
function looksZip(u8){ return u8.length >= 2 && u8[0] === 0x50 && u8[1] === 0x4b; }
function looksTar(u8){ return u8.length > 262 && dec.decode(u8.subarray(257, 262)) === "ustar"; }
function tarStr(h, a, b){
  return dec.decode(h.subarray(a,b)).replace(/\0.*$/s,"").trim();
}
function concatU8(chunks){
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks){ out.set(c, o); o += c.length; }
  return out;
}

function isBulkDataPath(path){
  const l = normPath(path).toLowerCase();
  return /(?:^|\/)(?:opt\/)?(?:panlogs|pan_logs|logdb|log-?db)(?:\/|$)/.test(l)
    || /(?:^|\/)(?:elasticsearch|esdata|es-data|es_data|es\/data)(?:\/|$)/.test(l)
    || /\/var\/lib\/elasticsearch(?:\/|$)/.test(l)
    || /(?:^|\/)(?:log-?collector(?:-data)?|logcollector|lcdata|lc-data|lc_data)(?:\/|$)/.test(l)
    || /(?:^|\/)(?:mongo(?:db)?|solr|clickhouse|filebeat|kibana)(?:\/|$)/.test(l);
}
function isEssential(name){
  return isPrimaryCli(name) || isConfigPath(name);
}
function namesMatch(a, b){
  return normPath(a) === normPath(b) || shortName(a) === shortName(b);
}
function classifyEntry(name, size){
  const l = normPath(name).toLowerCase();
  if (/\/var\/cores\//.test(l) || /\.core(\.\d+)?$/.test(l)) return {mode:"index", reason:"core dump (listed, not opened)", core:true};
  if (isBulkDataPath(l)) return {mode:"index", reason:"log collector / log database / search data"};
  if (SKIP_RE.test(l) || /\.dat$/i.test(l) || /\.(db|mdb|sqlite|dmp|vmdk|ova)$/i.test(l)) return {mode:"index", reason:"binary"};
  if (/\.(tgz|tar)$/i.test(l) || /\.tar\.gz$/i.test(l)) return {mode:"nested-tgz"};
  if (/\.zip$/i.test(l)) return {mode: size > 32*1024*1024 ? "index" : "nested-zip", reason:"binary"};
  if (isPrimaryCli(l) || isConfigPath(l)) return {mode:"full", cap: 8*1024*1024};
  if (/panorama_pushed\/(mergesp|predefined|newsp|lastsp)\.xml$/.test(l)) return {mode:"index", reason:"large Panorama pushed content"};
  if (/\/updates\/(curcontent|oldcontent)\//.test(l) || /ui_content|ui_predefined/.test(l)) return {mode:"index", reason:"content package"};
  if (/(candidatecfg|last-candidatecfg|refreshed-candidatecfg|tplsp_cfg|sysd_objects)/.test(l)) return {mode:"index", reason:"candidate or internal snapshot"};
  if (/\.(log|txt)\.(old|\d+)(?:\.gz)?$/i.test(l) || /\.log-\d{8}/i.test(l) || (/\.gz$/i.test(l) && /\.log/i.test(l))){
    return {mode:"index", reason:"rotated log"};
  }
  if (isLogPath(l) || /\.(log|txt)$/.test(l)){
    if (size > 512 * 1024) return {mode:"scan"};
    return {mode:"full", cap: TEXT_CAP};
  }
  if (/\.(xml|conf|cfg|csv)$/.test(l)){
    if (size > 8*1024*1024) return {mode:"index", reason:"too large"};
    return {mode:"full", cap: TEXT_CAP};
  }
  if (size > 1*1024*1024) return {mode:"index", reason:"unrecognized large file"};
  return {mode:"full", cap: TEXT_CAP};
}

function resetEmitState(budget){
  retainBudget = (budget == null || budget <= 0) ? DEFAULT_BUDGET : budget;
  retainedBytes = 0;
  budgetHit = false;
  budgetedCount = 0;
  batchFiles = [];
  batchXfer = [];
  extractTarget = null;
  extractFound = false;
}
function canRetain(n, essential){
  if (essential) return true;
  return retainedBytes + n <= retainBudget;
}
function flushBatch(){
  if (!batchFiles.length) return;
  const files = [];
  const xfer = [];
  for (const item of batchFiles){
    const f = item.meta;
    if (item.buf){
      f.textBuf = item.buf.buffer;
      xfer.push(item.buf.buffer);
    }
    files.push(f);
  }
  batchFiles = [];
  batchXfer = [];
  try {
    self.postMessage({type:"batch", files}, xfer);
  } catch (e){
    budgetHit = true;
    const slim = files.map(f => ({
      name: f.name, size: f.size, skip: f.skip || "indexed only (memory budget)",
      core: f.core, indexed: true, partial: false, budgeted: true,
      note: "This file was listed only because the browser was low on memory.",
      matchCount: f.matchCount || 0, loadable: !!f.loadable, textLen: 0
    }));
    budgetedCount += slim.length;
    try { self.postMessage({type:"batch", files: slim}); }
    catch (e2){ /* last resort: skip this batch rather than fail the load */ }
  }
}
function emitFile(rec){
  const essential = isEssential(rec.name);
  let text = rec.text || "";
  if (text && !canRetain(text.length, essential)){
    if (rec.matches && rec.matches.length){
      const slim = rec.matches.join("\n");
      if (canRetain(slim.length, false)){
        text = "[… kept matching issue lines only — memory budget …]\n\n" + slim;
        rec.partial = true;
        rec.budgeted = true;
        rec.note = "Only matching issue lines were kept (memory budget).";
      } else {
        text = "";
        rec.indexed = true;
        rec.budgeted = true;
        rec.skip = rec.skip || "indexed only (memory budget)";
        rec.partial = false;
      }
    } else {
      text = "";
      rec.indexed = true;
      rec.budgeted = true;
      rec.skip = rec.skip || "indexed only (memory budget)";
      rec.partial = false;
    }
    budgetHit = true;
    budgetedCount++;
  } else if (text && essential && retainedBytes + text.length > retainBudget && text.length > 2*1024*1024){
    const room = Math.max(2*1024*1024, retainBudget - retainedBytes);
    text = text.slice(0, room);
    rec.partial = true;
  }
  const skip = rec.skip || null;
  const isBin = !!rec.core || (skip && /binary|core dump|content package|search data|pcap/.test(skip));
  const meta = {
    name: rec.name,
    size: rec.size || 0,
    skip,
    core: !!rec.core,
    indexed: !!rec.indexed,
    partial: !!rec.partial,
    budgeted: !!rec.budgeted,
    note: rec.note || null,
    matchCount: rec.matchCount || 0,
    loadable: !isBin && (rec.size || 0) > 0 && (!text || rec.partial || rec.budgeted || rec.indexed),
    textLen: 0
  };
  let buf = null;
  if (text){
    buf = enc.encode(text);
    retainedBytes += buf.byteLength;
    meta.textLen = buf.byteLength;
  }
  batchFiles.push({meta, buf});
  const batchBytes = batchFiles.reduce((n, it) => n + (it.buf ? it.buf.byteLength : 0), 0);
  if (batchFiles.length >= BATCH_MAX || batchBytes >= BATCH_BYTES) flushBatch();
}

function countInputStream(readable){
  return readable.pipeThrough(new TransformStream({
    transform(chunk, ctl){
      inBytes += chunk.byteLength || chunk.length || 0;
      progress("decompressing");
      ctl.enqueue(chunk);
    }
  }));
}

function makeTarReader(readable){
  const reader = readable.getReader();
  const chunks = [];
  let offset = 0, bufLen = 0;
  async function fill(){
    checkCancel();
    const {done, value} = await reader.read();
    if (done) return false;
    if (value && value.length){
      chunks.push(value);
      bufLen += value.length;
      outBytes += value.length;
      progress("decompressing");
    }
    return true;
  }
  async function need(n){
    while (bufLen < n){
      if (!(await fill())) return false;
    }
    return true;
  }
  function shift(n){
    const out = new Uint8Array(n);
    let written = 0;
    while (written < n){
      const c = chunks[0];
      const take = Math.min(n - written, c.length - offset);
      out.set(c.subarray(offset, offset + take), written);
      written += take;
      offset += take;
      bufLen -= take;
      if (offset >= c.length){ chunks.shift(); offset = 0; }
    }
    return out;
  }
  async function discard(n){
    while (n > 0){
      if (bufLen === 0){
        if (!(await fill())) return false;
      }
      const c = chunks[0];
      const take = Math.min(n, c.length - offset);
      offset += take;
      bufLen -= take;
      n -= take;
      if (offset >= c.length){ chunks.shift(); offset = 0; }
    }
    return true;
  }
  function payloadStream(size, pad){
    let left = size;
    let finished = false;
    async function finish(){
      if (finished) return;
      finished = true;
      if (left > 0) await discard(left);
      const extra = pad - size;
      if (extra > 0) await discard(extra);
      left = 0;
    }
    return new ReadableStream({
      async pull(controller){
        try {
          checkCancel();
          if (left <= 0){ await finish(); controller.close(); return; }
          if (bufLen === 0){
            if (!(await fill())){ await finish(); controller.close(); return; }
          }
          const take = Math.min(left, bufLen);
          controller.enqueue(shift(take));
          left -= take;
        } catch (e){
          try { await finish(); } catch (e2){}
          controller.error(e);
        }
      },
      async cancel(){ await finish(); }
    }, { highWaterMark: 1 });
  }
  async function abort(){
    try { await reader.cancel(); } catch (e){}
    chunks.length = 0;
    bufLen = 0;
    offset = 0;
  }
  return {need, shift, discard, payloadStream, fill, abort};
}

async function collectStream(stream, size, cap){
  const reader = stream.getReader();
  const headNeed = (size > cap) ? Math.min(Math.max(TEXT_CAP, Math.floor(cap / 2)), cap) : cap;
  const tailNeed = (size > cap) ? Math.max(TEXT_TAIL, cap - headNeed) : 0;
  const head = [];
  let headLen = 0;
  const tail = [];
  let tailLen = 0;
  let seen = 0;
  while (true){
    const {done, value} = await reader.read();
    if (done) break;
    checkCancel();
    seen += value.length;
    if (headLen < headNeed){
      const needB = headNeed - headLen;
      if (value.length <= needB){ head.push(value); headLen += value.length; }
      else {
        head.push(value.subarray(0, needB));
        headLen += needB;
        pushTail(value.subarray(needB));
      }
    } else if (tailNeed){
      pushTail(value);
    }
    // if no tail needed and head is full, drain the rest without storing
  }
  function pushTail(u8){
    if (!tailNeed) return;
    tail.push(u8);
    tailLen += u8.length;
    while (tailLen > tailNeed && tail.length){
      const extra = tailLen - tailNeed;
      if (tail[0].length <= extra){ tailLen -= tail[0].length; tail.shift(); }
      else { tail[0] = tail[0].subarray(extra); tailLen -= extra; }
    }
  }
  const headU = concatU8(head);
  const tailU = tailNeed ? concatU8(tail) : new Uint8Array();
  function decode(u8){
    if (!u8.length) return "";
    if (u8[0] === 0xff && u8[1] === 0xfe) return new TextDecoder("utf-16le").decode(u8);
    return dec.decode(u8);
  }
  let text = decode(headU);
  const partial = size > headLen;
  if (partial){
    const omitted = Math.max(0, size - headLen - tailU.length);
    text += "\n\n[… " + fmtBytes(omitted) + " omitted from the middle of this file; kept the start and the end …]\n\n" + decode(tailU);
  }
  return {text, partial, kept: headLen + tailU.length};
}

function scanWindow(name, size){
  const l = (name||"").toLowerCase();
  if (/show_log_system|scheduled_report|syslog-system|req_stats|mp-monitor|dp-monitor|qtrace_|indexgen|nginx\/access|mgmt_httpd_access/.test(l)){
    return {head: 32*1024, tail: 64*1024};
  }
  return {head: LOG_HEAD, tail: LOG_TAIL};
}
async function scanStream(stream, size, name, opts){
  const matchesOnly = !!(opts && opts.matchesOnly);
  const win = matchesOnly ? {head:0, tail:0} : scanWindow(name, size);
  const reader = stream.getReader();
  const head = [];
  let headLen = 0;
  const tail = [];
  let tailLen = 0;
  const streamDec = new TextDecoder("utf-8");
  let lineBuf = "";
  let lineNo = 0;
  const matches = [];
  function pushTail(u8){
    tail.push(u8);
    tailLen += u8.length;
    while (tailLen > win.tail && tail.length){
      const extra = tailLen - win.tail;
      if (tail[0].length <= extra){ tailLen -= tail[0].length; tail.shift(); }
      else { tail[0] = tail[0].subarray(extra); tailLen -= extra; }
    }
  }
  while (true){
    const {done, value} = await reader.read();
    if (done) break;
    checkCancel();
    if (headLen < win.head){
      const needB = win.head - headLen;
      if (value.length <= needB){ head.push(value); headLen += value.length; }
      else {
        head.push(value.subarray(0, needB));
        headLen += needB;
        pushTail(value.subarray(needB));
      }
    } else {
      pushTail(value);
    }
    const s = streamDec.decode(value, {stream:true});
    lineBuf += s;
    let i;
    while ((i = lineBuf.indexOf("\n")) >= 0){
      const line = lineBuf.slice(0, i);
      lineBuf = lineBuf.slice(i + 1);
      lineNo++;
      if (line && ISSUE_RE.test(line) && matches.length < MAX_MATCH_LINES){
        ISSUE_RE.lastIndex = 0;
        matches.push(line.length > 400 ? line.slice(0, 400) : line);
      }
    }
    if (lineBuf.length > 1048576) lineBuf = lineBuf.slice(-4096);
  }
  if (lineBuf){
    lineNo++;
    if (ISSUE_RE.test(lineBuf) && matches.length < MAX_MATCH_LINES){
      matches.push(lineBuf.slice(0, 400));
    }
  }
  const headText = dec.decode(concatU8(head));
  const tailText = tailLen ? dec.decode(concatU8(tail)) : "";
  const extra = matches.filter(m => !headText.includes(m) && !tailText.includes(m));
  let text = headText;
  const partial = size > headLen;
  if (partial){
    const omitted = Math.max(0, size - headLen - tailLen);
    text += "\n\n[… " + fmtBytes(omitted) + " omitted from the middle of this log; kept the start, matching issue lines, and the end …]\n\n";
    if (extra.length) text += extra.join("\n") + "\n\n";
    text += tailText;
  }
  return {text, partial, matchCount: matches.length, kept: headLen + tailLen, matches};
}

async function drainStream(stream){
  const reader = stream.getReader();
  while (true){
    const {done} = await reader.read();
    if (done) break;
    checkCancel();
  }
}

async function parseTarStream(readable, depth){
  if (depth > 4) return;
  const tar = makeTarReader(readable);
  let longName = null, paxPath = null;
  while (await tar.need(512)){
    checkCancel();
    const h = tar.shift(512);
    if (h.every(b => !b)) break;
    let name = tarStr(h, 0, 100);
    const prefix = tarStr(h, 345, 500);
    if (prefix) name = prefix + "/" + name;
    const size = parseInt(tarStr(h, 124, 136) || "0", 8) || 0;
    const type = String.fromCharCode(h[156] || 48);
    const pad = Math.ceil(size / 512) * 512;
    if (type === "L" || type === "K" || type === "x" || type === "g"){
      if (!(await tar.need(pad))) break;
      const data = size ? tar.shift(pad).subarray(0, size) : new Uint8Array();
      if (type === "L" || type === "K") longName = dec.decode(data).replace(/\0.*$/s,"");
      else {
        const txt = dec.decode(data);
        const m = txt.match(/\bpath=([^\n]+)/);
        if (m) paxPath = m[1].trim();
      }
      continue;
    }
    if (longName){ name = longName; longName = null; }
    if (paxPath){ name = paxPath; paxPath = null; }
    name = name.replace(/^\.\//,"").replace(/\\/g,"/");
    if (type === "5"){
      if (pad) await tar.discard(pad);
      continue;
    }
    if (type !== "0" && type !== "\0" && type !== ""){
      if (pad) await tar.discard(pad);
      continue;
    }
    currentFile = name;
    const kind = classifyEntry(name, size);
    filesIndexed++;
    progress("indexing", filesIndexed % 20 === 0);
    if (kind.mode === "index"){
      if (pad) await tar.discard(pad);
      emitFile({name, text:"", size, skip: kind.reason, core: !!kind.core, indexed:true});
      if (extractTarget && namesMatch(name, extractTarget)){ extractFound = true; await tar.abort(); return; }
      continue;
    }
    const ps = tar.payloadStream(size, pad);
    if (kind.mode === "nested-tgz"){
      try {
        const inner = ps.pipeThrough(new DecompressionStream("gzip"));
        await parseTarStream(inner, depth + 1);
        if (extractFound){ await tar.abort(); return; }
      } catch (e){
        if (e && e.cancelled) throw e;
        emitFile({name, text:"", size, skip: "could not unpack nested archive: " + (e && e.message || e), indexed:true});
        try { await drainStream(ps); } catch (e2){}
      }
      continue;
    }
    if (kind.mode === "nested-zip"){
      const buf = concatU8(await readAllChunks(ps));
      try {
        const inner = await unzipMem(buf);
        for (const e of inner){
          filesIndexed++;
          currentFile = e.name;
          if (e.skip){ emitFile(e); continue; }
          const ck = classifyEntry(e.name, e.size || (e.data && e.data.length) || 0);
          if (ck.mode === "index"){
            emitFile({name:e.name, text:"", size:e.size||0, skip:ck.reason, core:!!ck.core, indexed:true});
          } else if (e.data){
            const t = dec.decode(e.data.length > (ck.cap||TEXT_CAP) ? e.data.subarray(e.data.length - TEXT_TAIL) : e.data);
            emitFile({name:e.name, text:t, size:e.size||e.data.length, partial: e.data.length > (ck.cap||TEXT_CAP)});
          }
        }
      } catch (e){
        emitFile({name, text:"", size, skip: "could not unpack zip: " + (e && e.message || e), indexed:true});
      }
      continue;
    }
    if (extractTarget && namesMatch(name, extractTarget)){
      const r = await collectStream(ps, size, 8 * 1024 * 1024);
      emitFile({name, text:r.text, size, partial: !!r.partial, skip:null, note: r.partial ? "Loaded a larger slice of this file on demand." : null});
      extractFound = true;
      await tar.abort();
      return;
    }
    if (kind.mode === "scan"){
      const matchesOnly = budgetHit && !isEssential(name);
      const r = await scanStream(ps, size, name, {matchesOnly});
      emitFile({name, text:r.text, size, partial:r.partial || matchesOnly, matchCount:r.matchCount, matches:r.matches, skip:null, budgeted: matchesOnly});
      continue;
    }
    // full (size-capped)
    if (budgetHit && !isEssential(name)){
      await drainStream(ps);
      emitFile({name, text:"", size, skip:"indexed only (memory budget)", indexed:true, budgeted:true});
      continue;
    }
    const r = await collectStream(ps, size, kind.cap || TEXT_CAP);
    emitFile({name, text:r.text, size, partial:r.partial, skip:null});
  }
}

async function readAllChunks(stream){
  const reader = stream.getReader();
  const chunks = [];
  while (true){
    const {done, value} = await reader.read();
    if (done) break;
    checkCancel();
    chunks.push(value);
  }
  return chunks;
}

async function inflateRaw(u8, fmt){
  const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream(fmt));
  return concatU8(await readAllChunks(s));
}

async function unzipMem(u8){
  const v = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let e = u8.length - 22;
  while (e >= 0 && v.getUint32(e, true) !== 0x06054b50) e--;
  if (e < 0) throw new Error("Not a valid zip file");
  let n = v.getUint16(e + 10, true), p = v.getUint32(e + 16, true);
  const out = [];
  for (let i = 0; i < n; i++){
    const m = v.getUint16(p + 10, true);
    const cs = v.getUint32(p + 20, true);
    const fl = v.getUint16(p + 28, true);
    const xl = v.getUint16(p + 30, true);
    const cl = v.getUint16(p + 32, true);
    const lo = v.getUint32(p + 42, true);
    const name = dec.decode(u8.subarray(p + 46, p + 46 + fl));
    p += 46 + fl + xl + cl;
    if (name.endsWith("/")) continue;
    const ds = lo + 30 + v.getUint16(lo + 26, true) + v.getUint16(lo + 28, true);
    const raw = u8.subarray(ds, ds + cs);
    if (v.getUint16(lo + 6, true) & 1){
      out.push({name, text:"", skip:"password protected", size:0, indexed:true});
      continue;
    }
    let data;
    if (m === 0) data = raw.slice();
    else if (m === 8) data = await inflateRaw(raw, "deflate-raw");
    else data = new Uint8Array();
    out.push({name, data, size: data.length});
  }
  return out;
}

async function unpackTsfFile(file){
  inBytes = 0;
  outBytes = 0;
  filesIndexed = 0;
  currentFile = file && file.name || "";
  fileSize = file && file.size || 0;
  peakHeap = 0;
  let emitted = 0;
  const before = () => (emitted = filesIndexed);
  const head = new Uint8Array(await file.slice(0, 512).arrayBuffer());
  // Re-read via File.slice(0) + stream so on-demand extract uses the same path.
  const src = file.slice ? file.slice(0) : file;
  if (looksGzip(head) || /\.(tgz|tar\.gz|gz)$/i.test(file.name || "")){
    const stream = countInputStream(src.stream()).pipeThrough(new DecompressionStream("gzip"));
    before();
    await parseTarStream(stream, 0);
    if (filesIndexed === emitted && !extractFound){
      const raw = await inflateRaw(new Uint8Array(await src.arrayBuffer()), "gzip");
      if (looksTar(raw)){
        await parseTarStream(new Blob([raw]).stream(), 0);
      } else {
        const n = (file.name || "file").replace(/\.gz$/i,"");
        const kind = classifyEntry(n, raw.length);
        filesIndexed++;
        if (kind.mode === "index") emitFile({name:n, text:"", size:raw.length, skip:kind.reason, core:!!kind.core, indexed:true});
        else emitFile({name:n, text:dec.decode(raw.length > (kind.cap||TEXT_CAP) ? raw.subarray(raw.length-TEXT_TAIL) : raw), size:raw.length});
      }
    }
  } else if (looksZip(head) || /\.zip$/i.test(file.name || "")){
    if (file.size > 256*1024*1024) throw new Error("This zip is too large to open in the browser. Use the original .tgz if you have it.");
    const u8 = new Uint8Array(await src.arrayBuffer());
    inBytes = file.size;
    const inner = await unzipMem(u8);
    for (const e of inner){
      filesIndexed++;
      currentFile = e.name;
      if (e.skip){ emitFile(e); continue; }
      const ck = classifyEntry(e.name, e.size || (e.data && e.data.length) || 0);
      if (ck.mode === "index") emitFile({name:e.name, text:"", size:e.size||0, skip:ck.reason, core:!!ck.core, indexed:true});
      else if (ck.mode === "nested-tgz" && e.data){
        try {
          const raw = looksGzip(e.data) ? new Blob([e.data]).stream().pipeThrough(new DecompressionStream("gzip")) : new Blob([e.data]).stream();
          await parseTarStream(raw, 1);
        } catch (err){
          emitFile({name:e.name, text:"", size:e.size||0, skip:"could not unpack nested archive: " + err.message, indexed:true});
        }
      } else if (e.data){
        const cap = ck.cap || TEXT_CAP;
        const slice = e.data.length > cap ? e.data.subarray(Math.max(0, e.data.length - TEXT_TAIL)) : e.data;
        emitFile({name:e.name, text:dec.decode(slice), size:e.size||e.data.length, partial: e.data.length > cap});
      }
      if (extractFound) break;
    }
  } else if (looksTar(head) || /\.tar$/i.test(file.name || "")){
    const stream = countInputStream(src.stream());
    await parseTarStream(stream, 0);
  } else {
    const u8 = new Uint8Array(await src.arrayBuffer());
    inBytes = file.size;
    filesIndexed = 1;
    emitFile({name: file.name, text: dec.decode(u8), size: u8.length});
  }
  flushBatch();
  progress("done", true);
  return {peakHeap, inBytes, outBytes, filesIndexed, retainedBytes, budgetHit, budgetedCount, budget: retainBudget, extractFound};
}

if (typeof self !== "undefined"){
  self.onmessage = async function(ev){
    const msg = ev.data || {};
    if (msg.type === "cancel"){ cancelled = true; return; }
    if (msg.type !== "start" && msg.type !== "extract") return;
    cancelled = false;
    onProgress = null;
    try {
      if (msg.type === "extract"){
        resetEmitState(Math.max(msg.cap || 8*1024*1024, 8*1024*1024));
        extractTarget = msg.name || "";
        extractFound = false;
        const result = await unpackTsfFile(msg.file);
        flushBatch();
        if (cancelled){ self.postMessage({type:"cancelled"}); return; }
        self.postMessage({type:"extracted", found: !!result.extractFound, name: extractTarget, peakHeap: result.peakHeap});
        return;
      }
      resetEmitState(msg.budget);
      const result = await unpackTsfFile(msg.file);
      flushBatch();
      if (cancelled){ self.postMessage({type:"cancelled"}); return; }
      self.postMessage({
        type:"done",
        peakHeap: result.peakHeap,
        inBytes: result.inBytes,
        outBytes: result.outBytes,
        filesIndexed: result.filesIndexed,
        retainedBytes: result.retainedBytes,
        budgetHit: result.budgetHit,
        budgetedCount: result.budgetedCount,
        budget: result.budget
      });
    } catch (e){
      if (cancelled || (e && (e.name === "AbortError" || e.cancelled))) self.postMessage({type:"cancelled"});
      else self.postMessage({type:"error", message: String(e && e.message || e)});
    }
  };
}
