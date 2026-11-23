#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/** Print the FlowMapper engine version and sha256 of build/core.js. */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const core = path.join(__dirname, "..", "build", "core.js");
const text = fs.readFileSync(core, "utf8");
const sha = crypto.createHash("sha256").update(fs.readFileSync(core)).digest("hex");
const versions = [...text.matchAll(/version:\s*"([0-9][^"]*)"/g)].map((m) => m[1]);
const version = versions.length ? versions[versions.length - 1] : "unknown";
const out = { file: "build/core.js", version, sha256: sha, bytes: fs.statSync(core).size };
if (process.argv.includes("--json")) console.log(JSON.stringify(out));
else console.log("FlowMapper engine " + out.version + "  sha256=" + out.sha256 + "  bytes=" + out.bytes);
