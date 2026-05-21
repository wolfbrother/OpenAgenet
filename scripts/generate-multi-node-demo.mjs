// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = path.join(rootDir, ".oan-multi-node-demo");

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  if (bytes.length === 0) return "";
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const byte of bytes) {
    if (byte === 0) result += BASE58_ALPHABET[0];
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function didToFileName(did) {
  return `${did.replaceAll(":", "_")}.json`;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeText(filePath, text) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, text, "utf8");
}

function generateIdentity({
  semanticCode,
  subjectType,
  identityType,
  role,
  description,
  capabilityTags,
  services,
}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicKeyRaw = Buffer.from(publicJwk.x, "base64url");
  const did = `did:ans:${semanticCode}:ef${base58Encode(publicKeyRaw)}`;
  const keyId = `${did}#key-1`;
  const didDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/ans/v1"],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: `z${base58Encode(publicKeyRaw)}`,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    service: services.map((service) => ({
      id: `${did}${service.fragment}`,
      type: service.type,
      serviceEndpoint: service.endpoint,
      version: "1.0.0",
      protocol: "http",
      serverType: service.serverType,
      port: service.port,
    })),
    ansMetadata: {
      subjectType,
      identityType,
      ttl: 300,
      addressBindings: services.map((service) => ({
        id: `${did}${service.fragment.replace("#", "#addr-")}`,
        addressType: "endpoint",
        network: "local-http",
        address: service.endpoint,
        controller: did,
        purpose: "service",
      })),
      agentDescription: {
        capabilityDescription: description,
        capabilityTags,
        useCaseExamples: services.length
          ? ["Provide governance or discovery endpoints.", "Support local multi-node demonstration."]
          : ["Discover a Service Agent.", "Submit or verify a registration package."],
      },
      servicePolicy: "public-local-resolution",
      networkScope: "openagentnet-local",
    },
  };

  return {
    did,
    keyId,
    publicJwk,
    privateJwk,
    didDocument,
    didDocumentHash: sha256Hex(canonicalJson(didDocument)),
  };
}

function signEvent(rootPrivateKey, event) {
  const eventHash = sha256Hex(canonicalJson(event));
  const signature = crypto.sign(null, Buffer.from(eventHash, "utf8"), rootPrivateKey).toString("base64url");
  return { ...event, eventHash, signature };
}

function writeNode(nodeDir, identity) {
  writeJson(path.join(nodeDir, "did-document.json"), identity.didDocument);
  writeJson(path.join(nodeDir, "keys", "keypair.json"), {
    warning: "Development key only. Do not use in production.",
    did: identity.did,
    keyId: identity.keyId,
    algorithm: "Ed25519",
    publicKeyMultibase: identity.didDocument.verificationMethod[0].publicKeyMultibase,
    publicKeyJwk: identity.publicJwk,
    privateKeyJwk: identity.privateJwk,
  });
}

fs.rmSync(outputDir, { recursive: true, force: true });
ensureDir(outputDir);

const root = generateIdentity({
  semanticCode: "AGRT",
  subjectType: "infrastructure-node",
  identityType: "root-node",
  role: "Root Node",
  description: "Local OpenAgentNet trust anchor for authorization, bulletin anchoring, DID Document verification, and verified package publishing.",
  capabilityTags: ["root-authority", "authorization", "bulletin", "verification"],
  services: [
    { fragment: "#root-api", type: "RootAuthorityService", endpoint: "http://localhost:8100", serverType: "local-root", port: 8100 },
    { fragment: "#bulletin", type: "TrustBulletinService", endpoint: "http://localhost:8100/bulletin", serverType: "local-root", port: 8100 },
  ],
});

const registrarA = generateIdentity({
  semanticCode: "AGRA",
  subjectType: "infrastructure-node",
  identityType: "registrar-node",
  role: "Registrar Node A",
  description: "Registrar Node A for multi-node onboarding and registration coordination.",
  capabilityTags: ["registration", "credential-issuance", "did-document-validation"],
  services: [{ fragment: "#registrar-api", type: "AgentRegistrarService", endpoint: "http://localhost:8101", serverType: "local-registrar-a", port: 8101 }],
});

const registrarB = generateIdentity({
  semanticCode: "AGRB",
  subjectType: "infrastructure-node",
  identityType: "registrar-node",
  role: "Registrar Node B",
  description: "Registrar Node B for multi-node onboarding and registration coordination.",
  capabilityTags: ["registration", "credential-issuance", "did-document-validation"],
  services: [{ fragment: "#registrar-api", type: "AgentRegistrarService", endpoint: "http://localhost:8102", serverType: "local-registrar-b", port: 8102 }],
});

const discoveryA = generateIdentity({
  semanticCode: "AGDA",
  subjectType: "infrastructure-node",
  identityType: "discovery-node",
  role: "Discovery Node A",
  description: "Discovery Node A for multi-node capability indexing and signed query responses.",
  capabilityTags: ["discovery", "capability-index", "routing"],
  services: [{ fragment: "#discovery-api", type: "AgentDiscoveryService", endpoint: "http://localhost:8103", serverType: "local-discovery-a", port: 8103 }],
});

const discoveryB = generateIdentity({
  semanticCode: "AGDB",
  subjectType: "infrastructure-node",
  identityType: "discovery-node",
  role: "Discovery Node B",
  description: "Discovery Node B for multi-node capability indexing and signed query responses.",
  capabilityTags: ["discovery", "capability-index", "routing"],
  services: [{ fragment: "#discovery-api", type: "AgentDiscoveryService", endpoint: "http://localhost:8104", serverType: "local-discovery-b", port: 8104 }],
});

const cdn = generateIdentity({
  semanticCode: "AGCN",
  subjectType: "infrastructure-node",
  identityType: "cdn-service",
  role: "CDN Service",
  description: "Local CDN service for verified packages and metadata.",
  capabilityTags: ["cdn", "distribution"],
  services: [{ fragment: "#cdn-api", type: "CdnService", endpoint: "http://localhost:8105", serverType: "local-cdn", port: 8105 }],
});

for (const [nodeName, identity] of Object.entries({
  root,
  "registrar-a": registrarA,
  "registrar-b": registrarB,
  "discovery-a": discoveryA,
  "discovery-b": discoveryB,
  cdn,
})) {
  writeNode(path.join(outputDir, nodeName), identity);
}

ensureDir(path.join(outputDir, "registrar-a", "credentials"));
ensureDir(path.join(outputDir, "registrar-b", "credentials"));
ensureDir(path.join(outputDir, "discovery-a", "credentials"));
ensureDir(path.join(outputDir, "discovery-b", "credentials"));

const createdAt = "2026-05-21T00:00:00Z";
const rootPrivateKey = crypto.createPrivateKey({ key: root.privateJwk, format: "jwk" });
const bulletinEvents = [
  {
    sequence: 1,
    previousHash: null,
    eventType: "ROOT_INITIALIZED",
    subjectDid: root.did,
    actorDid: root.did,
    payload: { didDocumentHash: root.didDocumentHash },
    createdAt,
  },
  {
    sequence: 2,
    previousHash: null,
    eventType: "CDN_SERVICE_INFO_UPDATED",
    subjectDid: root.did,
    actorDid: root.did,
    payload: {
      serviceId: "multi-node-cdn",
      providerType: "local",
      baseUrl: "http://localhost:8105",
      manifestUrl: "http://localhost:8105/cdn/manifest",
      updatesUrl: "http://localhost:8105/cdn/updates",
      documentsUrlTemplate: "http://localhost:8105/cdn/documents/{did}",
      packagesUrlTemplate: "http://localhost:8105/cdn/packages/{did}",
      metadataUrlTemplate: "http://localhost:8105/cdn/metadata/{did}",
      status: "active",
      validFrom: createdAt,
      validUntil: null,
    },
    createdAt,
  },
  {
    sequence: 3,
    previousHash: null,
    eventType: "REGISTRAR_AUTHORIZED",
    subjectDid: registrarA.did,
    actorDid: root.did,
    payload: { didDocumentHash: registrarA.didDocumentHash },
    createdAt,
  },
  {
    sequence: 4,
    previousHash: null,
    eventType: "REGISTRAR_AUTHORIZED",
    subjectDid: registrarB.did,
    actorDid: root.did,
    payload: { didDocumentHash: registrarB.didDocumentHash },
    createdAt,
  },
  {
    sequence: 5,
    previousHash: null,
    eventType: "DISCOVERY_NODE_AUTHORIZED",
    subjectDid: discoveryA.did,
    actorDid: root.did,
    payload: { didDocumentHash: discoveryA.didDocumentHash, authorizedDomains: ["*"], tagTreeVersion: 1 },
    createdAt,
  },
  {
    sequence: 6,
    previousHash: null,
    eventType: "DISCOVERY_NODE_AUTHORIZED",
    subjectDid: discoveryB.did,
    actorDid: root.did,
    payload: { didDocumentHash: discoveryB.didDocumentHash, authorizedDomains: ["*"], tagTreeVersion: 1 },
    createdAt,
  },
];

let prevHash = null;
const signedEvents = bulletinEvents.map((event) => {
  const signed = signEvent(rootPrivateKey, { ...event, previousHash: prevHash });
  prevHash = signed.eventHash;
  return signed;
});

writeJson(path.join(outputDir, "root", "bulletin.json"), {
  version: "0.1.0",
  rootDid: root.did,
  createdAt,
  events: signedEvents,
});

writeJson(path.join(outputDir, "cdn", "manifest.json"), {
  version: "0.1.0",
  generatedAt: createdAt,
  rootDid: root.did,
  packages: [],
});

for (const [source, target] of [
  ["root-a.toml", "root/config.example.toml"],
  ["registrar-a.toml", "registrar-a/config.example.toml"],
  ["registrar-b.toml", "registrar-b/config.example.toml"],
  ["discovery-a.toml", "discovery-a/config.example.toml"],
  ["discovery-b.toml", "discovery-b/config.example.toml"],
  ["cdn.toml", "cdn/config.example.toml"],
]) {
  ensureDir(path.join(outputDir, path.dirname(target)));
  fs.copyFileSync(
    path.join(rootDir, "examples", "multi-registrar-discovery", "config", source),
    path.join(outputDir, target),
  );
}

writeText(path.join(outputDir, "README.md"), [
  "# Multi Node Demo Data",
  "",
  "Generated by `scripts/generate-multi-node-demo.mjs`.",
  "This directory is isolated from the default single-node demo fixtures.",
  "",
].join("\n"));

console.log(`Generated multi-node demo data at ${outputDir}`);
