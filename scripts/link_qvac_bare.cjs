"use strict";

const fs = require("fs");
const path = require("path");

const SDK_NM = path.join("node_modules", "@qvac", "sdk", "node_modules");
const ROOT_NM = "node_modules";

function platformDir(parent) {
  if (!fs.existsSync(parent)) {
    return null;
  }
  return fs.readdirSync(parent).find((name) => /^bare-runtime-[a-z0-9]+-[a-z0-9]+$/.test(name));
}

function link(src, dest) {
  if (fs.existsSync(dest)) {
    return;
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.symlinkSync(path.resolve(src), dest, process.platform === "win32" ? "junction" : "dir");
}

const already = platformDir(SDK_NM);
if (already) {
  process.exit(0);
}

const nestedParent = path.join(SDK_NM, "bare-runtime", "node_modules");
const nested = platformDir(nestedParent);
if (nested) {
  link(path.join(nestedParent, nested), path.join(SDK_NM, nested));
  process.exit(0);
}

const hoisted = platformDir(ROOT_NM);
if (hoisted) {
  link(path.join(ROOT_NM, hoisted), path.join(SDK_NM, hoisted));
}
