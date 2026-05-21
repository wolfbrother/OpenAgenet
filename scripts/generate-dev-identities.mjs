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
const dataDir = path.join(rootDir, "data");

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

function safeFileName(value) {
  return value.replace(/[^A-Za-z0-9_.-]/g, "_");
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeLocalCredential(ownerDataPath, dimension, issuer, subject, credentialId, credential) {
  writeJson(
    path.join(
      dataDir,
      ownerDataPath,
      "credentials",
      "by-dimension",
      safeFileName(dimension),
      safeFileName(issuer),
      safeFileName(subject),
      `${safeFileName(credentialId)}.json`,
    ),
    credential,
  );
}

function resetGeneratedDir(relativePath) {
  const target = path.join(dataDir, relativePath);
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
}

function createIdentity(definition) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const publicKeyRaw = Buffer.from(publicJwk.x, "base64url");
  const suffix = `ef${base58Encode(publicKeyRaw)}`;
  const did = `did:ans:${definition.semanticCode}:${suffix}`;
  const keyId = `${did}#key-1`;

  const service = definition.services.map((service) => ({
    id: `${did}${service.fragment}`,
    type: service.type,
    serviceEndpoint: service.endpoint,
    version: service.version ?? "1.0.0",
    protocol: service.protocol ?? "http",
    serverType: service.serverType,
    port: service.port,
  }));

  const addressBindings = definition.services.map((service) => ({
    id: `${did}${service.fragment.replace("#", "#addr-")}`,
    addressType: "endpoint",
    network: "local-http",
    address: service.endpoint,
    controller: did,
    purpose: service.purpose ?? "service",
  }));

  const didDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/ans/v1",
    ],
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
    service,
    ansMetadata: {
      subjectType: definition.subjectType,
      identityType: definition.identityType,
      ttl: 300,
      addressBindings,
      agentDescription: definition.agentDescription,
      servicePolicy: "public-local-resolution",
      networkScope: "openagentnet-local",
    },
  };

  return {
    ...definition,
    did,
    keyId,
    publicJwk,
    privateJwk,
    publicKeyMultibase: `z${base58Encode(publicKeyRaw)}`,
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    didDocument,
    didDocumentHash: sha256Hex(canonicalJson(didDocument)),
  };
}

function signEvent(rootPrivateKey, event) {
  const eventHash = sha256Hex(canonicalJson(event));
  const signature = crypto.sign(null, Buffer.from(eventHash, "utf8"), rootPrivateKey).toString("base64url");
  return { ...event, eventHash, signature };
}

function signCredential(privateKey, credential) {
  const unsigned = { ...credential };
  delete unsigned.proof;
  delete unsigned.proofCreator;
  const payloadHash = sha256Hex(canonicalJson(unsigned));
  return {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      creator: credential.proofCreator,
      created: credential.issuedAt,
      proofPurpose: "assertionMethod",
      proofValue: crypto.sign(null, Buffer.from(payloadHash, "utf8"), privateKey).toString("base64url"),
    },
  };
}

const definitions = [
  {
    id: "root",
    dataPath: "root",
    semanticCode: "AGRT",
    subjectType: "infrastructure-node",
    identityType: "root-node",
    role: "Root Node",
    services: [
      { fragment: "#root-api", type: "RootAuthorityService", endpoint: "http://localhost:8000", serverType: "local-root", port: 8000 },
      { fragment: "#bulletin", type: "TrustBulletinService", endpoint: "http://localhost:8000/bulletin", serverType: "local-root", port: 8000 },
    ],
    agentDescription: {
      capabilityDescription: "Local OpenAgentNet trust anchor for authorization, bulletin anchoring, DID Document verification, and verified package publishing.",
      capabilityTags: ["root-authority", "authorization", "bulletin", "verification"],
      useCaseExamples: ["Authorize infrastructure nodes.", "Anchor DID Document hashes to the local bulletin."],
    },
  },
  {
    id: "registrar",
    dataPath: "registrar",
    semanticCode: "AGRG",
    subjectType: "infrastructure-node",
    identityType: "registrar-node",
    role: "Registrar Node",
    services: [
      { fragment: "#registrar-api", type: "AgentRegistrarService", endpoint: "http://localhost:8001", serverType: "local-registrar", port: 8001 },
    ],
    agentDescription: {
      capabilityDescription: "Registers Service Agents, validates DID Documents, and issues local AgentRegistrationCredential records.",
      capabilityTags: ["registration", "credential-issuance", "did-document-validation"],
      useCaseExamples: ["Register a demo Service Agent.", "Submit a verified DID Document to Root Node."],
    },
  },
  {
    id: "discovery",
    dataPath: "discovery",
    semanticCode: "AGDS",
    subjectType: "infrastructure-node",
    identityType: "discovery-node",
    role: "Discovery Node",
    services: [
      { fragment: "#discovery-api", type: "AgentDiscoveryService", endpoint: "http://localhost:8002", serverType: "local-discovery", port: 8002 },
    ],
    agentDescription: {
      capabilityDescription: "Synchronizes verified metadata from CDN Service, builds a capability index, and returns signed discovery results.",
      capabilityTags: ["discovery", "capability-index", "routing"],
      useCaseExamples: ["Find Service Agents by capability tag.", "Return signed candidate Agent records."],
    },
  },
  {
    id: "service-agent",
    dataPath: "demo-service-agent",
    semanticCode: "AGDM",
    subjectType: "agent",
    identityType: "demo-service-agent",
    role: "Demo Service Agent",
    services: [
      { fragment: "#agent-endpoint", type: "AgentService", endpoint: "http://localhost:9001/agent/invoke", serverType: "local-demo-agent", port: 9001 },
      { fragment: "#mcp-endpoint", type: "MCPService", endpoint: "http://localhost:9001/mcp", serverType: "local-demo-agent", port: 9001 },
      { fragment: "#a2a-endpoint", type: "A2AService", endpoint: "http://localhost:9001/a2a", serverType: "local-demo-agent", port: 9001 },
    ],
    agentDescription: {
      capabilityDescription: "A local demo Service Agent with echo, translation, and summarization capabilities exposed through trusted invocation, MCP, and A2A endpoints.",
      capabilityTags: ["echo", "translation", "summarization", "mcp", "a2a", "text-processing"],
      useCaseExamples: ["Echo a signed request.", "Translate English text into Chinese.", "Summarize a short paragraph."],
    },
  },
  {
    id: "user-agent",
    dataPath: "user-agent",
    semanticCode: "AGUS",
    subjectType: "agent",
    identityType: "user-agent",
    role: "User Agent",
    services: [],
    agentDescription: {
      capabilityDescription: "A local demo User Agent that discovers Service Agents, resolves DID Documents, verifies signatures, and performs trusted invocation.",
      capabilityTags: ["user-agent", "discovery-client", "trusted-invocation", "mcp-client", "a2a-client"],
      useCaseExamples: ["Discover a Service Agent by capability.", "Invoke a Service Agent with a signed request."],
    },
  },
];

const identities = definitions.map(createIdentity);
const identityById = Object.fromEntries(identities.map((identity) => [identity.id, identity]));
const rootPrivateKey = crypto.createPrivateKey({ key: identityById.root.privateJwk, format: "jwk" });
const createdAt = "2026-05-20T00:00:00Z";

for (const relativePath of [
  "cdn/documents",
  "cdn/metadata",
  "cdn/packages",
  "registrar/records",
  "registrar/credentials",
  "discovery/credentials",
  "demo-service-agent/credentials",
  "user-agent/credentials",
]) {
  resetGeneratedDir(relativePath);
}

for (const identity of identities) {
  const baseDir = path.join(dataDir, identity.dataPath);
  writeJson(path.join(baseDir, "did-document.json"), identity.didDocument);
  writeJson(path.join(baseDir, "keys", "keypair.json"), {
    warning: "Development key only. Do not use in production.",
    did: identity.did,
    keyId: identity.keyId,
    algorithm: "Ed25519",
    publicKeyMultibase: identity.publicKeyMultibase,
    publicKeyJwk: identity.publicJwk,
    privateKeyJwk: identity.privateJwk,
    publicKeyPem: identity.publicKeyPem,
    privateKeyPem: identity.privateKeyPem,
  });
}

const registry = {
  generatedAt: createdAt,
  warning: "Development identities only. Do not use these keys in production.",
  identities: Object.fromEntries(identities.map((identity) => [
    identity.id,
    {
      role: identity.role,
      did: identity.did,
      didSemanticCode: identity.semanticCode,
      subjectType: identity.subjectType,
      identityType: identity.identityType,
      didDocumentPath: `data/${identity.dataPath}/did-document.json`,
      keypairPath: `data/${identity.dataPath}/keys/keypair.json`,
      didDocumentHash: identity.didDocumentHash,
      services: identity.didDocument.service,
    },
  ])),
};
writeJson(path.join(dataDir, "dev-identities.json"), registry);

const bulletinEvents = [
  {
    sequence: 1,
    previousHash: null,
    eventType: "ROOT_INITIALIZED",
    subjectDid: identityById.root.did,
    actorDid: identityById.root.did,
    payload: { didDocumentHash: identityById.root.didDocumentHash },
    createdAt,
  },
  {
    sequence: 2,
    eventType: "CDN_SERVICE_INFO_UPDATED",
    subjectDid: identityById.root.did,
    actorDid: identityById.root.did,
    payload: {
      serviceId: "openagentnet-local-cdn",
      providerType: "local",
      baseUrl: "http://localhost:8003",
      manifestUrl: "http://localhost:8003/cdn/manifest",
      updatesUrl: "http://localhost:8003/cdn/updates",
      documentsUrlTemplate: "http://localhost:8003/cdn/documents/{did}",
      packagesUrlTemplate: "http://localhost:8003/cdn/packages/{did}",
      metadataUrlTemplate: "http://localhost:8003/cdn/metadata/{did}",
      status: "active",
      validFrom: createdAt,
      validUntil: null,
    },
    createdAt,
  },
  {
    sequence: 3,
    eventType: "REGISTRAR_AUTHORIZED",
    subjectDid: identityById.registrar.did,
    actorDid: identityById.root.did,
    payload: { didDocumentHash: identityById.registrar.didDocumentHash },
    createdAt,
  },
  {
    sequence: 4,
    eventType: "DISCOVERY_NODE_AUTHORIZED",
    subjectDid: identityById.discovery.did,
    actorDid: identityById.root.did,
    payload: {
      didDocumentHash: identityById.discovery.didDocumentHash,
      authorizedDomains: ["*"],
      tagTreeVersion: 1,
    },
    createdAt,
  },
  {
    sequence: 5,
    eventType: "AGENT_DID_DOCUMENT_ANCHORED",
    subjectDid: identityById["service-agent"].did,
    actorDid: identityById.root.did,
    payload: {
      registrarDid: identityById.registrar.did,
      didDocumentHash: identityById["service-agent"].didDocumentHash,
    },
    createdAt,
  },
];

const registrarAuthorizationCredential = signCredential(rootPrivateKey, {
  id: "urn:openagentnet:credential:registrar-authorization:local-root:v1",
  type: "RegistrarAuthorizationCredential",
  issuer: identityById.root.did,
  subject: identityById.registrar.did,
  role: "registrar",
  status: "active",
  issuedAt: createdAt,
  expiresAt: null,
  claims: {
    endpoint: "http://localhost:8001",
    networkScope: "openagentnet-local",
  },
  proofCreator: identityById.root.keyId,
});

const discoveryAuthorizationCredential = signCredential(rootPrivateKey, {
  id: "urn:openagentnet:credential:discovery-authorization:local-root:v1",
  type: "DiscoveryAuthorizationCredential",
  issuer: identityById.root.did,
  subject: identityById.discovery.did,
  role: "discovery",
  status: "active",
  issuedAt: createdAt,
  expiresAt: null,
  claims: {
    endpoint: "http://localhost:8002",
    authorizedDomains: ["*"],
    tagTreeVersion: 1,
    networkScope: "openagentnet-local",
  },
  proofCreator: identityById.root.keyId,
});

const registrarPrivateKey = crypto.createPrivateKey({ key: identityById.registrar.privateJwk, format: "jwk" });
const serviceAgentRegistrationCredential = signCredential(registrarPrivateKey, {
  id: "urn:openagentnet:credential:agent-registration:local-registrar:v1",
  type: "AgentRegistrationCredential",
  issuer: identityById.registrar.did,
  subject: identityById["service-agent"].did,
  status: "active",
  issuedAt: createdAt,
  expiresAt: null,
  claims: {
    registered: true,
    identityType: "demo-service-agent",
    serviceEndpoint: "http://localhost:9001/agent/invoke",
    didDocumentHash: identityById["service-agent"].didDocumentHash,
    capabilityTags: identityById["service-agent"].didDocument.ansMetadata.agentDescription.capabilityTags,
  },
  proofCreator: identityById.registrar.keyId,
});

const userAgentRegistrationCredential = signCredential(registrarPrivateKey, {
  id: "urn:openagentnet:credential:user-agent-registration:local-registrar:v1",
  type: "UserAgentRegistrationCredential",
  issuer: identityById.registrar.did,
  subject: identityById["user-agent"].did,
  status: "active",
  issuedAt: createdAt,
  expiresAt: null,
  claims: {
    registered: true,
    identityType: "user-agent",
    didDocumentHash: identityById["user-agent"].didDocumentHash,
    capabilityTags: identityById["user-agent"].didDocument.ansMetadata.agentDescription.capabilityTags,
    allowedInvocation: ["trusted-hello-demo"],
  },
  proofCreator: identityById.registrar.keyId,
});

writeJson(path.join(dataDir, "registrar", "credentials", "node-authorization.json"), registrarAuthorizationCredential);
writeJson(path.join(dataDir, "discovery", "credentials", "node-authorization.json"), discoveryAuthorizationCredential);
writeJson(path.join(dataDir, "demo-service-agent", "credentials", "agent-registration.json"), serviceAgentRegistrationCredential);
writeJson(path.join(dataDir, "user-agent", "credentials", "user-agent-registration.json"), userAgentRegistrationCredential);
writeLocalCredential("registrar", "node-authorization", registrarAuthorizationCredential.issuer, registrarAuthorizationCredential.subject, registrarAuthorizationCredential.id, registrarAuthorizationCredential);
writeLocalCredential("discovery", "node-authorization", discoveryAuthorizationCredential.issuer, discoveryAuthorizationCredential.subject, discoveryAuthorizationCredential.id, discoveryAuthorizationCredential);
writeLocalCredential("demo-service-agent", "agent-registration", serviceAgentRegistrationCredential.issuer, serviceAgentRegistrationCredential.subject, serviceAgentRegistrationCredential.id, serviceAgentRegistrationCredential);
writeLocalCredential("user-agent", "user-agent-registration", userAgentRegistrationCredential.issuer, userAgentRegistrationCredential.subject, userAgentRegistrationCredential.id, userAgentRegistrationCredential);
writeJson(path.join(dataDir, "user-agent", "credentials", "credentials-index.json"), {
  ownerDid: identityById["user-agent"].did,
  storageMode: "local",
  credentials: [
    {
      dimension: "user-agent-registration",
      issuer: userAgentRegistrationCredential.issuer,
      subject: userAgentRegistrationCredential.subject,
      credentialId: userAgentRegistrationCredential.id,
      path: "credentials/user-agent-registration.json",
      type: userAgentRegistrationCredential.type,
      status: userAgentRegistrationCredential.status,
    },
  ],
  dimensions: {
    "user-agent-registration": [
      {
        issuer: userAgentRegistrationCredential.issuer,
        subject: userAgentRegistrationCredential.subject,
        credentialId: userAgentRegistrationCredential.id,
        path: "credentials/user-agent-registration.json",
      },
    ],
  },
  note: "User Agent stores multiple local credentials by dimension, issuer, subject, and credential id when issued or received. MVP has no hosted VC wallet.",
});

const signedEvents = [];
for (const event of bulletinEvents) {
  const previousHash = signedEvents.length > 0 ? signedEvents.at(-1).eventHash : event.previousHash;
  signedEvents.push(signEvent(rootPrivateKey, { ...event, previousHash }));
}
writeJson(path.join(dataDir, "root", "bulletin.json"), {
  version: "0.1.0",
  rootDid: identityById.root.did,
  createdAt,
  events: signedEvents,
});

const packages = [];
for (const identity of identities) {
  const metadata = {
    did: identity.did,
    role: identity.role,
    identityType: identity.identityType,
    didDocumentHash: identity.didDocumentHash,
    subjectType: identity.subjectType,
    capabilityTags: identity.didDocument.ansMetadata.agentDescription.capabilityTags,
    services: identity.didDocument.service,
    status: "active",
    updatedAt: createdAt,
  };
  const verifiedPackage = {
    packageVersion: "0.1.0",
    did: identity.did,
    didDocument: identity.didDocument,
    didDocumentHash: identity.didDocumentHash,
    metadata,
    rootProof: {
      rootDid: identityById.root.did,
      bulletinEventHash: signedEvents.find((event) => event.subjectDid === identity.did)?.eventHash ?? null,
      signature: signedEvents.find((event) => event.subjectDid === identity.did)?.signature ?? null,
    },
    createdAt,
  };

  writeJson(path.join(dataDir, "cdn", "documents", didToFileName(identity.did)), identity.didDocument);
  writeJson(path.join(dataDir, "cdn", "metadata", didToFileName(identity.did)), metadata);
  writeJson(path.join(dataDir, "cdn", "packages", didToFileName(identity.did)), verifiedPackage);
  packages.push({
    did: identity.did,
    role: identity.role,
    documentPath: `/cdn/documents/${encodeURIComponent(identity.did)}`,
    metadataPath: `/cdn/metadata/${encodeURIComponent(identity.did)}`,
    packagePath: `/cdn/packages/${encodeURIComponent(identity.did)}`,
    didDocumentHash: identity.didDocumentHash,
    updatedAt: createdAt,
  });
}

writeJson(path.join(dataDir, "cdn", "manifest.json"), {
  version: "0.1.0",
  generatedAt: createdAt,
  rootDid: identityById.root.did,
  packages,
});

writeJson(path.join(dataDir, "registrar", "records", `${didToFileName(identityById["service-agent"].did)}`), {
  agentDid: identityById["service-agent"].did,
  registrarDid: identityById.registrar.did,
  status: "registered",
  didDocumentHash: identityById["service-agent"].didDocumentHash,
  registeredAt: createdAt,
  credential: serviceAgentRegistrationCredential,
});

writeJson(path.join(dataDir, "discovery", "index", "capabilities.json"), {
  generatedAt: createdAt,
  sourceManifest: "data/cdn/manifest.json",
  capabilities: {
    echo: [identityById["service-agent"].did],
    translation: [identityById["service-agent"].did],
    summarization: [identityById["service-agent"].did],
    mcp: [identityById["service-agent"].did],
    a2a: [identityById["service-agent"].did],
  },
});

fs.writeFileSync(path.join(dataDir, "DEV_KEYS_NOTICE.md"), [
  "# Development Keys",
  "",
  "The keys and DID Documents in this directory are local development fixtures.",
  "",
  "Do not use them in production or for any real identity, signing, authorization, or credential workflow.",
  "",
].join("\n"), "utf8");

console.log(`Generated ${identities.length} development identities.`);
