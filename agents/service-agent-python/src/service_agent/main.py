# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DID_DOCUMENT = REPO_ROOT / "data" / "demo-service-agent" / "did-document.json"
SERVICE_KEYPAIR = REPO_ROOT / "data" / "demo-service-agent" / "keys" / "keypair.json"
REGISTRAR_DID_DOCUMENT = REPO_ROOT / "data" / "registrar" / "did-document.json"

SEEN_NONCES: set[str] = set()

ORGANIZATION = {
    "deployer": "China Academy of Information and Communications Technology (CAICT)",
    "author": "JINLIANG XU",
    "email": ["xujinliang@caict.ac.cn", "jlxufly@gmail.com"],
}


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def payload_hash(value: Any) -> bytes:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest().encode("utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def private_key_from_jwk(jwk: dict[str, str]) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"]))


def public_key_from_did_document(did_document: dict[str, Any], key_id: str) -> Ed25519PublicKey:
    for method in did_document.get("verificationMethod", []):
        if method.get("id") == key_id:
            return Ed25519PublicKey.from_public_bytes(b64url_decode(method["publicKeyJwk"]["x"]))
    raise ValueError(f"verification method not found: {key_id}")


def verify_signed_value(value: dict[str, Any], did_document: dict[str, Any], proof_field: str = "proof") -> bool:
    proof = value.get(proof_field) or {}
    creator = proof.get("creator")
    signature = proof.get("proofValue")
    if not creator or not signature:
        return False

    unsigned = copy.deepcopy(value)
    unsigned.pop(proof_field, None)
    unsigned.pop("proofCreator", None)
    public_key = public_key_from_did_document(did_document, creator)
    public_key.verify(b64url_decode(signature), payload_hash(unsigned))
    return True


def sign_value(value: dict[str, Any], keypair: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    unsigned.pop("proof", None)
    private_key = private_key_from_jwk(keypair["privateKeyJwk"])
    proof = {
        "type": "Ed25519Signature2020",
        "creator": keypair["keyId"],
        "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "proofPurpose": "assertionMethod",
        "proofValue": b64url_encode(private_key.sign(payload_hash(unsigned))),
    }
    return {**unsigned, "proof": proof}


def service_profile() -> dict[str, Any]:
    did_document = load_json(DEFAULT_DID_DOCUMENT)
    description = did_document.get("ansMetadata", {}).get("agentDescription", {})
    return {
        "name": "Demo Service Agent",
        "role": "service-agent",
        "did": did_document["id"],
        "deployment": ORGANIZATION,
        "capabilityDescription": description.get("capabilityDescription"),
        "capabilityTags": description.get("capabilityTags", []),
        "serviceEndpoints": did_document.get("service", []),
        "supportedProtocols": ["OpenAgentNet trusted invocation", "MCP", "A2A"],
    }


def verify_invocation(payload: dict[str, Any]) -> dict[str, Any]:
    service_did = load_json(DEFAULT_DID_DOCUMENT)["id"]
    caller_did = payload.get("callerDid")
    target_did = payload.get("targetDid")
    nonce = payload.get("nonce")
    timestamp = payload.get("timestamp")
    caller_did_document = payload.get("callerDidDocument")
    credentials = payload.get("credentials", [])

    if payload.get("type") != "OpenAgentNetTrustedInvocation":
        raise ValueError("invalid_invocation_type")
    if not caller_did or not target_did or not nonce or not timestamp:
        raise ValueError("missing_invocation_fields")
    if target_did != service_did:
        raise ValueError("target_did_mismatch")
    if not isinstance(caller_did_document, dict) or caller_did_document.get("id") != caller_did:
        raise ValueError("caller_did_document_mismatch")
    if nonce in SEEN_NONCES:
        raise ValueError("replayed_nonce")

    request_signature_verified = verify_signed_value(payload, caller_did_document)
    registrar_did_document = load_json(REGISTRAR_DID_DOCUMENT)
    user_credentials = [
        credential for credential in credentials
        if credential.get("subject") == caller_did
        and credential.get("status") == "active"
        and credential.get("type") in {"UserAgentRegistrationCredential", "AgentRegistrationCredential"}
    ]
    if not user_credentials:
        raise ValueError("missing_user_agent_credential")

    user_credential = user_credentials[0]
    credential_verified = verify_signed_value(user_credential, registrar_did_document)
    if not credential_verified:
        raise ValueError("user_agent_credential_not_verified")

    SEEN_NONCES.add(nonce)
    return {
        "callerDid": caller_did,
        "targetDid": target_did,
        "nonce": nonce,
        "timestamp": timestamp,
        "requestSignatureVerified": request_signature_verified,
        "userCredentialVerified": credential_verified,
        "userCredentialType": user_credential.get("type"),
        "userCredentialIssuer": user_credential.get("issuer"),
    }


class ServiceAgentHandler(BaseHTTPRequestHandler):
    server_version = "OpenAgentNetServiceAgent/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json({"status": "ok", "nodeType": "service-agent"})
            return
        if self.path == "/agent/did":
            self.write_json(load_json(DEFAULT_DID_DOCUMENT))
            return
        if self.path == "/agent/profile":
            self.write_json(service_profile())
            return
        if self.path in {"/mcp", "/a2a"}:
            self.write_json({
                "status": "ok",
                "protocol": self.path.strip("/").upper(),
                "profile": service_profile(),
            })
            return
        self.write_json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        payload = self.read_json_body()
        if self.path in {"/agent/hello", "/agent/invoke"}:
            try:
                verification = verify_invocation(payload)
                response = {
                    "type": "OpenAgentNetTrustedInvocationResponse",
                    "reply": "hello, verified OpenAgentNet caller",
                    "verified": True,
                    "callerDid": verification["callerDid"],
                    "serviceDid": service_profile()["did"],
                    "requestNonce": verification["nonce"],
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "verification": verification,
                    "serviceAgent": service_profile(),
                    "demoPurpose": "Show signed Agent-to-Agent invocation, VC verification, deployment organization, author, and callable endpoint in one trusted collaboration response.",
                }
                self.write_json(sign_value(response, load_json(SERVICE_KEYPAIR)))
            except Exception as exc:
                self.write_json({"error": "trusted_invocation_rejected", "reason": str(exc)}, status=401)
            return
        self.write_json({"error": "not_found"}, status=404)

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def write_json(self, value: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[service-agent] " + fmt % args + "\n")


def main() -> None:
    host = "127.0.0.1"
    port = 9001
    server = ThreadingHTTPServer((host, port), ServiceAgentHandler)
    print(f"service-agent-python listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
