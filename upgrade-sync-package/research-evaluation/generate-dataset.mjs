// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

import fs from "node:fs";
import path from "node:path";

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const repoRoot = path.resolve(arg("--repo-root", path.resolve("..", "..")));
const output = path.resolve(arg("--output", "dataset.json"));
const count = Number.parseInt(arg("--count", "10"), 10);
const tags = arg("--tags", "gbt4754-2017.01").split(",").map((item) => item.trim()).filter(Boolean);

const template = JSON.parse(fs.readFileSync(path.join(repoRoot, "data/demo-service-agent/did-document.json"), "utf8"));
const suffixAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function replaceDid(value, oldDid, newDid) {
  if (typeof value === "string") return value.replaceAll(oldDid, newDid);
  if (Array.isArray(value)) return value.map((item) => replaceDid(item, oldDid, newDid));
  if (value && typeof value === "object") {
    const next = {};
    for (const [key, item] of Object.entries(value)) next[key] = replaceDid(item, oldDid, newDid);
    return next;
  }
  return value;
}

const oldDid = template.id;
const agents = [];
for (let i = 0; i < count; i += 1) {
  const tag = tags[i % tags.length];
  const suffixChar = suffixAlphabet[i % suffixAlphabet.length];
  const newDid = `did:ans:AGDM:ef${suffixChar.repeat(22)}${String(i + 1).padStart(6, "0")}`;
  const didDocument = replaceDid(clone(template), oldDid, newDid);
  didDocument.ansMetadata.identityType = "research-evaluation-agent";
  didDocument.ansMetadata.agentDescription.capabilityTags = [tag, `custom.research.${i % 10}`];
  didDocument.ansMetadata.agentDescription.capabilityDescription = `Research evaluation Service Agent ${i + 1} for capability tag ${tag}.`;
  for (const service of didDocument.service ?? []) {
    service.serviceEndpoint = service.serviceEndpoint.replace("9001", String(9300 + (i % 50)));
    service.port = 9300 + (i % 50);
  }
  agents.push({
    index: i + 1,
    did: newDid,
    capabilityTags: didDocument.ansMetadata.agentDescription.capabilityTags,
    didDocument,
  });
}

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify({ count, tags, agents }, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ output, count, tags }));
