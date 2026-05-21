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
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


REPO_ROOT = Path(__file__).resolve().parents[4]
USER_DID_DOCUMENT = REPO_ROOT / "data" / "user-agent" / "did-document.json"
USER_KEYPAIR = REPO_ROOT / "data" / "user-agent" / "keys" / "keypair.json"
USER_CREDENTIAL = REPO_ROOT / "data" / "user-agent" / "credentials" / "user-agent-registration.json"
SERVICE_DID_DOCUMENT = REPO_ROOT / "data" / "demo-service-agent" / "did-document.json"
DISCOVERY_ENDPOINT = "http://127.0.0.1:8002"


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


def sign_value(value: dict[str, Any], keypair: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    unsigned.pop("proof", None)
    private_key = private_key_from_jwk(keypair["privateKeyJwk"])
    proof = {
        "type": "Ed25519Signature2020",
        "creator": keypair["keyId"],
        "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "proofPurpose": "authentication",
        "proofValue": b64url_encode(private_key.sign(payload_hash(unsigned))),
    }
    return {**unsigned, "proof": proof}


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


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def build_invocation(target_did: str, discovery_proof: dict[str, Any]) -> dict[str, Any]:
    user_did_document = load_json(USER_DID_DOCUMENT)
    body = {
        "message": "hello from OpenAgentNet User Agent",
        "purpose": "trusted-agent-hello",
    }
    invocation = {
        "type": "OpenAgentNetTrustedInvocation",
        "callerDid": user_did_document["id"],
        "targetDid": target_did,
        "nonce": secrets.token_urlsafe(24),
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "body": body,
        "bodyHash": hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest(),
        "callerDidDocument": user_did_document,
        "credentials": [load_json(USER_CREDENTIAL)],
        "discoveryProof": discovery_proof,
    }
    return sign_value(invocation, load_json(USER_KEYPAIR))


def main() -> None:
    user_did_document = load_json(USER_DID_DOCUMENT)
    query = {
        "capabilityTags": ["gbt4754-2017.01"],
        "serviceType": "AgentService",
        "protocol": "http",
        "limit": 1,
    }
    discovery_response = post_json(f"{DISCOVERY_ENDPOINT}/discover/query", query)
    candidates = discovery_response.get("candidates", [])
    if not candidates:
        raise SystemExit("No Service Agent candidate returned by Discovery.")

    candidate = candidates[0]
    service = next(item for item in candidate["services"] if item.get("type") == "AgentService")
    service_endpoint = service["serviceEndpoint"].removesuffix("/invoke")
    profile = get_json(f"{service_endpoint}/profile")
    invocation = build_invocation(candidate["did"], discovery_response.get("proof") or {})
    hello = post_json(f"{service_endpoint}/hello", invocation)
    response_signature_verified = verify_signed_value(hello, load_json(SERVICE_DID_DOCUMENT))
    verification = hello.get("verification", {})
    deployment = hello.get("serviceAgent", {}).get("deployment", {})
    provenance_verified = (
        deployment.get("deployer")
        == "China Academy of Information and Communications Technology (CAICT)"
        and deployment.get("author") == "JINLIANG XU"
        and "xujinliang@caict.ac.cn" in deployment.get("email", [])
        and "jlxufly@gmail.com" in deployment.get("email", [])
    )

    print(json.dumps({
        "demo": "trusted-agent-hello",
        "userAgentDid": user_did_document["id"],
        "discoveryDid": discovery_response.get("discoveryDid"),
        "discoveryProof": discovery_response.get("proof"),
        "selectedServiceAgent": profile,
        "invocation": {
            "type": invocation["type"],
            "callerDid": invocation["callerDid"],
            "targetDid": invocation["targetDid"],
            "nonce": invocation["nonce"],
            "timestamp": invocation["timestamp"],
            "credentialTypes": [credential.get("type") for credential in invocation["credentials"]],
            "requestSignature": invocation["proof"],
        },
        "helloResponse": hello,
        "checks": {
            "requestSignatureVerifiedByServiceAgent": verification.get("requestSignatureVerified") is True,
            "userCredentialVerifiedByServiceAgent": verification.get("userCredentialVerified") is True,
            "responseSignatureVerifiedByUserAgent": response_signature_verified,
            "provenanceVerified": provenance_verified,
        },
        "provenance": deployment,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
